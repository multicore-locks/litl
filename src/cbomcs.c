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
 * Roughly, the idea of C-BO-MCS is to have one lock per NUMA node, and one
 * global lock.
 * - On lock, the first time the thread grabs its local lock and then the
 * global lock
 * - On unlock, the thread releases the local lock, and if there is no thread
 * waiting for the local lock, it releases the global lock (or for fairness it
 * releases the global lock randomly)
 * - On lock, if the thread that unlocks the local lock doesn't release the
 * global lock, then the locker thread doesn't need to grab the global lock
 * and just grabs the local one.
 * - Here the local lock is a MCS lock and the global lock is a Backoff lock
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <cbomcs.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

// To get the process id, use rdtscp
static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CPU_NUMBER / NUMA_NODES);
}

static int __mcs_mutex_lock(mcs_mutex_t *impl, mcs_node_t *me) {
    mcs_node_t *tail;

    me->next = 0;
    me->spin = LOCKED;

    // The atomic instruction is needed when two threads try to put themselves
    // at the tail of the list at the same time
    tail = xchg_64((void *)&impl->tail, (void *)me);

    /* No one there? */
    if (!tail) {
        return 0;
    }

    /* Someone there, need to link in */
    tail->next = me;
    COMPILER_BARRIER();

    waiting_policy_sleep(&me->spin);

    return 0;
}

static void __mcs_mutex_unlock(mcs_mutex_t *impl, mcs_node_t *me) {
    /* No successor yet? */
    if (!me->next) {
        // The atomic instruction is needed if a thread between the previous if
        // and now has enqueued itself at the tail
        if (__sync_val_compare_and_swap(&impl->tail, me, 0) == me)
            return;

        /* Wait for successor to appear */
        while (!me->next)
            CPU_PAUSE();
    }

    /* Unlock next one */
    waiting_policy_wake(&me->next->spin);
}

static int __mcs_mutex_trylock(mcs_mutex_t *impl, mcs_node_t *me) {
    mcs_node_t *tail;

    me->next = 0;
    me->spin = LOCKED;

    // The trylock is a cmp&swap, where the thread enqueues itself to the end of
    // the list only if there is nobody at the tail
    tail = __sync_val_compare_and_swap(&impl->tail, 0, me);

    /* No one was there - can quickly return */
    if (!tail) {
        return 0;
    }

    return EBUSY;
}

static int __mcs_mutex_anybody_there(mcs_mutex_t *impl, mcs_node_t *me) {
    return me != impl->tail;
}

static int __backoff_mutex_lock(backoff_ttas_t *impl) {
    unsigned int delay = DEFAULT_BACKOFF_DELAY;
    unsigned int i;
    while (true) {
        while (impl->spin_lock != UNLOCKED) {
            for (i = 0; i < delay; i++)
                CPU_PAUSE();

            if (delay < MAX_BACKOFF_DELAY)
                delay *= 2;
        }

        if (l_tas_uint8(&impl->spin_lock) == UNLOCKED) {
            break;
        }
    }

    return 0;
}

static void __backoff_mutex_unlock(backoff_ttas_t *impl) {
    COMPILER_BARRIER();
    impl->spin_lock = UNLOCKED;
}

static int __backoff_mutex_trylock(backoff_ttas_t *impl) {
    if (l_tas_uint8(&impl->spin_lock) == UNLOCKED)
        return 0;

    return EBUSY;
}

cbomcs_mutex_t *cbomcs_mutex_create(const pthread_mutexattr_t *attr) {
    cbomcs_mutex_t *impl =
        (cbomcs_mutex_t *)alloc_cache_align(sizeof(cbomcs_mutex_t));
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    memset(impl, 0, sizeof *impl);

    impl->top_lock.spin_lock = UNLOCKED;

    return impl;
}

static int __cbomcs_mutex_lock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
    local_mcs_lock_t *local_lock = &impl->local_locks[current_numa_node()];

    // Acquire the local lock
    __mcs_mutex_lock(&local_lock->l, me);

    // Do we already have the global lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return 0;
    }

    // Acquire top lock
    __backoff_mutex_lock(&impl->top_lock);
    impl->top_home = local_lock;

    return 0;
}

int cbomcs_mutex_lock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
    int ret = __cbomcs_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

static int __cbomcs_mutex_trylock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
    local_mcs_lock_t *local_lock = &impl->local_locks[current_numa_node()];
    if (__mcs_mutex_trylock(&local_lock->l, me) == EBUSY)
        return EBUSY;

    // Do we already have the local lock?
    if (local_lock->top_grant) {
        local_lock->top_grant = 0;
        return 0;
    }

    // Trylock the global lock
    if (__backoff_mutex_trylock(&impl->top_lock) == EBUSY) {
        __mcs_mutex_unlock(&local_lock->l, me);
        return EBUSY;
    }

    impl->top_home = local_lock;

    return 0;
}

int cbomcs_mutex_trylock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
    int ret = __cbomcs_mutex_trylock(impl, me);

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

static void __cbomcs_mutex_unlock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
    local_mcs_lock_t *local_lock = impl->top_home;

    // Is anybody there?
    if (__mcs_mutex_anybody_there(&local_lock->l, me)) {
        // Cohort detection
        local_lock->batch_count--;
        // Give the lock to a thread on the same node
        if (local_lock->batch_count >= 0) {
            local_lock->top_grant = 1;
            __mcs_mutex_unlock(&local_lock->l, me);
            return;
        }
        local_lock->batch_count = BATCH_COUNT;
    }

    // Release the local lock AND the global lock
    __mcs_mutex_unlock(&local_lock->l, me);
    __backoff_mutex_unlock(&impl->top_lock);
}

void cbomcs_mutex_unlock(cbomcs_mutex_t *impl, cbomcs_node_t *me) {
#if COND_VAR
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __cbomcs_mutex_unlock(impl, me);
}

int cbomcs_mutex_destroy(cbomcs_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int cbomcs_cond_init(cbomcs_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cbomcs_cond_timedwait(cbomcs_cond_t *cond, cbomcs_mutex_t *lock,
                          cbomcs_node_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __cbomcs_mutex_unlock(lock, me);
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

    cbomcs_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cbomcs_cond_wait(cbomcs_cond_t *cond, cbomcs_mutex_t *lock,
                     cbomcs_node_t *me) {
    return cbomcs_cond_timedwait(cond, lock, me, 0);
}

int cbomcs_cond_signal(cbomcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cbomcs_cond_broadcast(cbomcs_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int cbomcs_cond_destroy(cbomcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void cbomcs_thread_start(void) {
}

void cbomcs_thread_exit(void) {
}

void cbomcs_application_init(void) {
}

void cbomcs_application_exit(void) {
}

void cbomcs_init_context(lock_mutex_t *UNUSED(impl),
                         lock_context_t *UNUSED(context), int UNUSED(number)) {
}
