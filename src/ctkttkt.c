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
 * SOFTWARE.
 *
 *
 * David Dice, Virendra J. Marathe, and Nir Shavit. 2015.
 * Lock Cohorting: A General Technique for Designing NUMA Locks.
 * ACM Trans. Parallel Comput. 1, 2, Article 13 (February 2015).
 *
 * For a description of the algorithm, see cbomcs.c
 * The main difference between C-BO-MCS and C-TKT-TKT is that this lock uses a
 * Ticket lock for the local locks and the global lock.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <ctkttkt.h>

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

ctkt_mutex_t *ctkt_mutex_create(const pthread_mutexattr_t *attr) {
    ctkt_mutex_t *impl =
        (ctkt_mutex_t *)alloc_cache_align(sizeof(ctkt_mutex_t));
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    memset(impl, 0, sizeof *impl);

    return impl;
}

static int __ctkt_mutex_lock(ctkt_mutex_t *impl, ctkt_node_t *UNUSED(me)) {
    local_tkt_lock_t *local_lock = &impl->local_locks[current_numa_node()];

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
    t = __sync_fetch_and_add(&impl->top_lock.u.s.request, 1);
    while (impl->top_lock.u.s.grant != t)
        CPU_PAUSE();

    impl->top_home = local_lock;

    return 0;
}

int ctkt_mutex_lock(ctkt_mutex_t *impl, ctkt_node_t *me) {
    int ret = __ctkt_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

static int __ctkt_mutex_trylock(ctkt_mutex_t *impl, ctkt_node_t *UNUSED(me)) {
    local_tkt_lock_t *local_lock = &impl->local_locks[current_numa_node()];

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

    // Trylock the global lock
    me     = impl->top_lock.u.s.request;
    menew  = me + 1;
    cmp    = ((uint64_t)me << 32) + me;
    cmpnew = ((uint64_t)menew << 32) + me;

    if (__sync_val_compare_and_swap(&impl->top_lock.u.u, cmp, cmpnew) != cmp) {
        // Lock not available, release the local lock
        local_lock->u.s.grant++;
        return EBUSY;
    }

    impl->top_home = local_lock;

    return 0;
}

int ctkt_mutex_trylock(ctkt_mutex_t *impl, ctkt_node_t *me) {
    int ret = __ctkt_mutex_trylock(impl, me);

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

static void __ctkt_mutex_unlock(ctkt_mutex_t *impl, ctkt_node_t *UNUSED(me)) {
    local_tkt_lock_t *local_lock = impl->top_home;
    int new_grant                = local_lock->u.s.grant + 1;

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
    COMPILER_BARRIER();
    impl->top_lock.u.s.grant++;
    local_lock->u.s.grant = new_grant;
}

void ctkt_mutex_unlock(ctkt_mutex_t *impl, ctkt_node_t *me) {
#if COND_VAR
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __ctkt_mutex_unlock(impl, me);
}

int ctkt_mutex_destroy(ctkt_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int ctkt_cond_init(ctkt_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ctkt_cond_timedwait(ctkt_cond_t *cond, ctkt_mutex_t *lock, ctkt_node_t *me,
                        const struct timespec *ts) {
#if COND_VAR
    int res;

    __ctkt_mutex_unlock(lock, me);
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

    ctkt_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ctkt_cond_wait(ctkt_cond_t *cond, ctkt_mutex_t *lock, ctkt_node_t *me) {
    return ctkt_cond_timedwait(cond, lock, me, 0);
}

int ctkt_cond_signal(ctkt_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ctkt_cond_broadcast(ctkt_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ctkt_cond_destroy(ctkt_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void ctkt_thread_start(void) {
}

void ctkt_thread_exit(void) {
}

void ctkt_application_init(void) {
}

void ctkt_application_exit(void) {
}

void ctkt_init_context(lock_mutex_t *UNUSED(impl),
                       lock_context_t *UNUSED(context), int UNUSED(number)) {
}
