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
 * Milind Chabbi, Michael Fagan, and John Mellor-Crummey. 2015.
 * High performance locks for multi-level NUMA systems.
 * In Proceedings of the 20th ACM SIGPLAN Symposium on Principles and Practice
 * of Parallel Programming (PPoPP 2015)
 *
 * Here we consider only 2-level HMCS lock.
 *
 * This lock is conceptually very similar to a C-MCS-MCS (see the description of
 * cohorting locks for more information).
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
#include <hmcs.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

#define COHORT_START 1
#define ACQUIRE_PARENT (UINT64_MAX - 1)
#define WAIT UINT64_MAX

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CPU_NUMBER / NUMA_NODES);
}

hmcs_mutex_t *hmcs_mutex_create(const pthread_mutexattr_t *attr) {
    hmcs_mutex_t *impl =
        (hmcs_mutex_t *)alloc_cache_align(sizeof(hmcs_mutex_t));

    // Link local nodes to parent
    uint8_t i;
    for (i = 0; i < NUMA_NODES; i++) {
        impl->local[i].parent = &impl->global;
        impl->local[i].tail   = NULL;
    }

    // Init the parent
    impl->global.parent = NULL;
    impl->global.tail   = NULL;

#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, /*&errattr */ attr);
    DEBUG("Mutex init lock=%p posix_lock=%p\n", impl, &impl->posix_lock);
#endif

    return impl;
}

static inline int __hmcs_mutex_global_lock(hmcs_hnode_t *impl,
                                           hmcs_qnode_t *me) {
    hmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    tail = xchg_64((void *)&impl->tail, (void *)me);

    /* No one there? */
    if (!tail) {
        me->status = UNLOCKED;
        DEBUG("[%2d] Locking global %p\n", cur_thread_id, impl);
        return 0;
    }

    /* Someone there, need to link in */
    COMPILER_BARRIER();
    tail->next = me;

    while (me->status == LOCKED)
        CPU_PAUSE();

    DEBUG("[%2d] Locking global %p\n", cur_thread_id, impl);
    return 0;
}

static inline int __hmcs_mutex_local_lock(hmcs_hnode_t *impl,
                                          hmcs_qnode_t *me) {
    hmcs_qnode_t *tail;

    // Prepare the node for use
    me->next   = 0;
    me->status = WAIT;

    // printf("[%2d] Enqueing %p on %p\n", cur_thread_id, me);
    tail = xchg_64((void *)&impl->tail, (void *)me);

    if (tail) {
        tail->next = me;
        uint64_t cur_status;

        DEBUG("[%2d] There was someone (%p)...\n", cur_thread_id, tail);

        COMPILER_BARRIER();
        while ((cur_status = me->status) == WAIT)
            CPU_PAUSE();

        // Acquired, enter CS
        if (cur_status < ACQUIRE_PARENT) {
            DEBUG("[%2d] Locking local without locking global %p\n",
                  cur_thread_id, impl);
            return 0;
        }
    }

    DEBUG("[%2d] Locking local %p\n", cur_thread_id, impl);
    me->status = COHORT_START;
    int ret    = __hmcs_mutex_global_lock(impl->parent, &impl->node);
    return ret;
}

static inline void __hmcs_release_helper(hmcs_hnode_t *impl, hmcs_qnode_t *me,
                                         uint64_t val) {
    /* No successor yet? */
    if (!me->next) {
        /* Try to atomically unlock */
        if (__sync_val_compare_and_swap(&impl->tail, me, 0) == me)
            return;

        /* Wait for successor to appear */
        while (!me->next)
            CPU_PAUSE();
    }

    // Pass lock
    me->next->status = val;
    MEMORY_BARRIER();
}

static inline int __hmcs_mutex_global_trylock(hmcs_hnode_t *impl,
                                              hmcs_qnode_t *me) {
    hmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    tail = __sync_val_compare_and_swap(&impl->tail, NULL, me);
    if (tail == NULL) {
        me->status = UNLOCKED;
        return 0;
    }

    return EBUSY;
}

static inline int __hmcs_mutex_local_trylock(hmcs_hnode_t *impl,
                                             hmcs_qnode_t *me) {
    hmcs_qnode_t *tail;

    // Prepare the node for use
    me->next   = 0;
    me->status = WAIT;

    tail = __sync_val_compare_and_swap(&impl->tail, NULL, me);

    if (tail != NULL) {
        return EBUSY;
    }

    me->status = COHORT_START;
    int ret    = __hmcs_mutex_global_trylock(impl->parent, &impl->node);

    // Unable to get the global, release the local and fail
    if (ret == EBUSY) {
        // Unlock and ask the successor to get the global lock if it is here
        __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
    }

    return ret;
}

static inline int __hmcs_mutex_global_unlock(hmcs_hnode_t *impl,
                                             hmcs_qnode_t *me) {
    DEBUG("[%2d] Unlocking global %p\n", cur_thread_id, impl);
    __hmcs_release_helper(impl, me, UNLOCKED);
    return 0;
}

static inline int __hmcs_mutex_local_unlock(hmcs_hnode_t *impl,
                                            hmcs_qnode_t *me) {
    uint64_t cur_count = me->status;

    DEBUG("[%2d] Unlocking local %p\n", cur_thread_id, impl);

    // Lower level release
    if (cur_count == RELEASE_THRESHOLD) {
        DEBUG("[%2d] Threshold reached\n", cur_thread_id);
        // Reached threshold, release the next level (suppose 2-level)
        __hmcs_mutex_global_unlock(impl->parent, &impl->node);

        // Ask successor to acquire next-level lock
        __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
        return 0;
    }

    // Not reached threshold
    hmcs_qnode_t *succ = me->next;
    if (succ) {
        DEBUG("[%2d] Successor is here\n", cur_thread_id);
        succ->status = cur_count + 1;
        return 0;
    }

    // No known successor, release to parent
    __hmcs_mutex_global_unlock(impl->parent, &impl->node);

    // Ask successor to acquire next-level lock
    __hmcs_release_helper(impl, me, ACQUIRE_PARENT);
    return 0;
}

int hmcs_mutex_lock(hmcs_mutex_t *impl, hmcs_qnode_t *me) {
    hmcs_hnode_t *local = &impl->local[current_numa_node()];

    // Must remember the last local node for release
    me->last_local = local;

    DEBUG("[%2d] Waiting for local lock %p\n", cur_thread_id, local);
    int ret = __hmcs_mutex_local_lock(local, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    DEBUG("[%2d]\tLock acquired posix=%p\n", cur_thread_id, &impl->posix_lock);
    return ret;
}

int hmcs_mutex_trylock(hmcs_mutex_t *impl, hmcs_qnode_t *me) {
    hmcs_hnode_t *local = &impl->local[current_numa_node()];

    // Must remember the last local node for release
    me->last_local = local;

    int ret = __hmcs_mutex_local_trylock(local, me);
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

void hmcs_mutex_unlock(hmcs_mutex_t *impl, hmcs_qnode_t *me) {
#if COND_VAR
    DEBUG("[%2d]\tUnlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __hmcs_mutex_local_unlock(me->last_local, me);
}

int hmcs_mutex_destroy(hmcs_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int hmcs_cond_init(hmcs_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hmcs_cond_timedwait(hmcs_cond_t *cond, hmcs_mutex_t *lock, hmcs_qnode_t *me,
                        const struct timespec *ts) {
#if COND_VAR
    int res;
    __hmcs_mutex_local_unlock(me->last_local, me);

    if (ts)
        res = REAL(pthread_cond_timedwait)(cond, &lock->posix_lock, ts);
    else
        res = REAL(pthread_cond_wait)(cond, &lock->posix_lock);

    if (res != 0 && res != ETIMEDOUT) {
        DEBUG("Error on cond_{timed,}wait %d\n", res);
        assert(0);
    }

    int ret = 0;
    if ((ret = REAL(pthread_mutex_unlock)(&lock->posix_lock)) != 0) {
        DEBUG("Error on mutex_unlock %d\n", ret == EPERM);
        assert(0);
    }

    hmcs_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hmcs_cond_wait(hmcs_cond_t *cond, hmcs_mutex_t *lock, hmcs_qnode_t *me) {
    return hmcs_cond_timedwait(cond, lock, me, 0);
}

int hmcs_cond_signal(hmcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hmcs_cond_broadcast(hmcs_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hmcs_cond_destroy(hmcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void hmcs_thread_start(void) {
}

void hmcs_thread_exit(void) {
}

void hmcs_application_init(void) {
}

void hmcs_application_exit(void) {
}
void hmcs_init_context(lock_mutex_t *UNUSED(impl),
                       lock_context_t *UNUSED(context), int UNUSED(number)) {
}
