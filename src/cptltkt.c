/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of his software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *
 *
 * David Dice, Virendra J. Marathe, and Nir Shavit. 2015.
 * Lock Cohorting: A General Technique for Designing NUMA Locks.
 * ACM Trans. Parallel Comput. 1, 2, Article 13 (February 2015).
 *
 * For a description of the algorithm, see cbomcs.c
 * The main difference between C-BO-MCS and C-PTL-TKT is that C-PTL-TKT uses a
 * Ticket lock for local locks and a Partitioned-Ticket lock for the global
 * lock.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <cptltkt.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CPU_NUMBER / NUMA_NODES);
}

cpt_mutex_t *cpt_mutex_create(const pthread_mutexattr_t *attr) {
    cpt_mutex_t *impl = (cpt_mutex_t *)alloc_cache_align(sizeof(cpt_mutex_t));
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif
    memset(impl, 0, sizeof *impl);

    return impl;
}

static int __cpt_mutex_lock(cpt_mutex_t *impl, cpt_node_t *UNUSED(me)) {
    tkt_lock_t *local_lock = &impl->local_locks[current_numa_node()];

    // Acquire the local lock
    int t = __sync_fetch_and_add(&local_lock->u.s.request, 1);
    while (local_lock->u.s.grant != t)
        CPU_PAUSE();

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return 0;
    }

    // Acquire top lock
    t = __sync_fetch_and_add(&impl->top_lock.request, 1);
    while (impl->top_lock.grants[t % PTL_SLOTS].grant != t)
        CPU_PAUSE();

    impl->top_lock.owner_ticket = t;
    impl->top_home              = local_lock;

    return 0;
}

int cpt_mutex_lock(cpt_mutex_t *impl, cpt_node_t *me) {
    int ret = __cpt_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

static int __cpt_mutex_trylock(cpt_mutex_t *impl, cpt_node_t *UNUSED(me)) {
    tkt_lock_t *local_lock = &impl->local_locks[current_numa_node()];
    uint32_t t;

    // Trylock the local lock
    uint32_t me     = local_lock->u.s.request;
    uint32_t menew  = me + 1;
    uint64_t cmp    = ((uint64_t)me << 32) + me;
    uint64_t cmpnew = ((uint64_t)menew << 32) + me;

    if (__sync_val_compare_and_swap(&local_lock->u.u, cmp, cmpnew) != cmp)
        return EBUSY;

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return 0;
    }

    /**
     * It is not possible to implement a true trylock with partitioned ticket
     * lock.
     * As the partitioned provides cohort detection, we can watch if there is
     * anyone else, and if not try a blocking lock
     **/
    if (impl->top_lock.grants[impl->top_lock.request % PTL_SLOTS].grant !=
        impl->top_lock.request) {
        // Lock not available, release the local lock
        local_lock->u.s.grant++;
        return EBUSY;
    } else {
        /**
         * If the lock is abortable, we can try a few times and abort.
         * But partitioned ticket lock is not abortable, so we might potentially
         * wait (this seems the best we can do).
         **/
        t = __sync_fetch_and_add(&impl->top_lock.request, 1);
        while (impl->top_lock.grants[t % PTL_SLOTS].grant != t)
            CPU_PAUSE();
    }

    impl->top_lock.owner_ticket = t;
    impl->top_home              = local_lock;

    return 0;
}

int cpt_mutex_trylock(cpt_mutex_t *impl, cpt_node_t *me) {
    int ret = __cpt_mutex_trylock(impl, me);

#if COND_VAR
    if (ret == 0) {
        while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
            ;
        assert(ret == 0);
        return 0;
    }
#endif
    return ret;
}

static void __cpt_mutex_unlock(cpt_mutex_t *impl, cpt_node_t *UNUSED(me)) {
    tkt_lock_t *local_lock = impl->top_home;
    int new_grant          = local_lock->u.s.grant + 1;

    // Is anybody there?
    if (local_lock->u.s.request != new_grant) {
        // Cohort detection
        local_lock->batch_count--;
        // Give the lock to a thread on the same node
        if (local_lock->batch_count >= 0) {
            local_lock->top_grant = 1;
            COMPILER_BARRIER();
            local_lock->u.s.grant = new_grant;
            return;
        }
        local_lock->batch_count = BATCH_COUNT;
    }

    // Release the local lock AND the global lock
    int new_owner_ticket = impl->top_lock.owner_ticket + 1;
    COMPILER_BARRIER();
    impl->top_lock.grants[new_owner_ticket % PTL_SLOTS].grant =
        new_owner_ticket;
    local_lock->u.s.grant = new_grant;
}

void cpt_mutex_unlock(cpt_mutex_t *impl, cpt_node_t *me) {
#if COND_VAR
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __cpt_mutex_unlock(impl, me);
}

int cpt_mutex_destroy(cpt_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int cpt_cond_init(cpt_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cpt_cond_timedwait(cpt_cond_t *cond, cpt_mutex_t *lock, cpt_node_t *me,
                       const struct timespec *ts) {
#if COND_VAR
    int res;

    __cpt_mutex_unlock(lock, me);
    DEBUG("[%d] Sleep cond=%p lock=%p posix_lock=%p\n", cur_thread_id, cond,
          lock, &(lock->posix_lock));
    DEBUG_PTHREAD("[%d] Cond posix = %p lock = %p\n", cur_thread_id, cond,
                  &lock->posix_lock);

    if (ts)
        res = REAL(pthread_cond_timedwait)(cond, &lock->posix_lock, ts);
    else
        res = REAL(pthread_cond_wait)(cond, &lock->posix_lock);

    if (res != 0 && res != ETIMEDOUT) {
        fprintf(stderr, "Error on cond_{timed,}wait %d\n", res);
        assert(0);
    }

    int ret = 0;
    if ((ret = REAL(pthread_mutex_unlock)(&lock->posix_lock)) != 0) {
        fprintf(stderr, "Error on mutex_unlock %d\n", ret == EPERM);
        assert(0);
    }

    cpt_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cpt_cond_wait(cpt_cond_t *cond, cpt_mutex_t *lock, cpt_node_t *me) {
    return cpt_cond_timedwait(cond, lock, me, 0);
}

int cpt_cond_signal(cpt_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cpt_cond_broadcast(cpt_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cpt_cond_destroy(cpt_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void cpt_thread_start(void) {
}

void cpt_thread_exit(void) {
}

void cpt_application_init(void) {
}

void cpt_application_exit(void) {
}

void cpt_init_context(lock_mutex_t *UNUSED(impl),
                      lock_context_t *UNUSED(context), int UNUSED(number)) {
}
