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
 * Milind Chabbi and John Mellor-Crummey. 2016.
 * Contention-conscious, locality-preserving locks.
 * In Proceedings of the 21st ACM SIGPLAN Symposium on Principles and Practice
 * of Parallel Programming (PPoPP '16).
 *
 * Here we consider only 2-level HYSHMCS lock.
 * Depth == 1 => root, Depth == 2 => leaf
 * Note: see the Ph.D. thesis of Millind Chabbi (Listing A.2) for more
 * information
 * https://scholarship.rice.edu/bitstream/handle/1911/87730/CHABBI-DOCUMENT-2015.pdf?sequence=1&isAllowed=y
 *
 * Lock design summary:
 * This lock is a variant of the HMCS lock.
 * First, it allows a thread to only acquire the MCS lock at the top of the tree
 * if there is no thread there.
 * Second, while releasing the lock, if a thread sees that there is are no
 * threads waiting after it, the next time it will
 * try to acquire the lock at one level closer to the root of the tree (thus
 * acquiring less locks).
 * Respectively, if there were some threads waiting at the last level where the
 * thread released the lock, the next time
 * it will try to grab the lock one level further from the root.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <hyshmcs.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

#define COHORT_START 1
#define ACQUIRE_PARENT (UINT64_MAX - 1)
#define WAIT UINT64_MAX

#define LEVEL_LOCAL 1
#define LEVEL_GLOBAL 2

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CPU_NUMBER / NUMA_NODES);
}

hyshmcs_mutex_t *hyshmcs_mutex_create(const pthread_mutexattr_t *attr) {
    hyshmcs_mutex_t *impl =
        (hyshmcs_mutex_t *)alloc_cache_align(sizeof(hyshmcs_mutex_t));

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

static inline int __hyshmcs_mutex_global_lock(hyshmcs_hnode_t *impl,
                                              hyshmcs_qnode_t *me) {
    hyshmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    DEBUG("[%2d] Trying to lock global %p (me=%p)\n", cur_thread_id, impl, me);
    tail = xchg_64((void *)&impl->tail, (void *)me);

    /* No one there? */
    if (!tail) {
        me->status = UNLOCKED;
        DEBUG("[%2d] Locking global %p (me=%p)\n", cur_thread_id, impl, me);
        return LEVEL_GLOBAL;
    }

    /* Someone there, need to link in */
    tail->next = me;
    COMPILER_BARRIER();

    while (me->status == LOCKED)
        CPU_PAUSE();

    DEBUG("[%2d] Locking global %p (me=%p)\n", cur_thread_id, impl, me);
    return LEVEL_GLOBAL;
}

static inline int __hyshmcs_mutex_local_lock(hyshmcs_hnode_t *impl,
                                             hyshmcs_qnode_t *me) {
    hyshmcs_qnode_t *tail;

    // Prepare the node for use
    me->next   = 0;
    me->status = WAIT;

    DEBUG("[%2d] Trying to lock local %p (me=%p)\n", cur_thread_id, impl, me);
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
            DEBUG(
                "[%2d] Locking local without locking global (h+1 lock held) %p "
                "(me=%p)\n",
                cur_thread_id, impl, me);
            return LEVEL_LOCAL;
        }
    }

    DEBUG("[%2d] Locking local %p (me=%p\n", cur_thread_id, impl, me);
    me->status = COHORT_START;
    return __hyshmcs_mutex_global_lock(impl->parent, &impl->node);
}

static inline void __hyshmcs_release_helper(hyshmcs_hnode_t *impl,
                                            hyshmcs_qnode_t *me, uint64_t val) {
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
    DEBUG("[%2d] me=%p passing the lock %p to succ=%p with val=%lu\n",
          cur_thread_id, me, impl, me->next, val);
    me->next->status = val;
    MEMORY_BARRIER();
}

static inline int __hyshmcs_mutex_global_unlock(hyshmcs_hnode_t *impl,
                                                hyshmcs_qnode_t *me) {
    DEBUG("[%2d] Unlocking global %p (me=%p)\n", cur_thread_id, impl, me);
    __hyshmcs_release_helper(impl, me, UNLOCKED);
    return LEVEL_GLOBAL;
}

static inline int __hyshmcs_mutex_local_unlock(hyshmcs_hnode_t *impl,
                                               hyshmcs_qnode_t *me) {
    uint64_t cur_count = me->status;

    DEBUG("[%2d] Unlocking local %p (me=%p)\n", cur_thread_id, impl, me);

    // Lower level release
    if (cur_count == RELEASE_THRESHOLD) {
        DEBUG("[%2d] Release threshold reached, releasing the global lock\n",
              cur_thread_id);
        // Reached threshold, release the next level (suppose 2-level)
        __hyshmcs_mutex_global_unlock(impl->parent, &impl->node);

        // Ask successor to acquire next-level lock
        __hyshmcs_release_helper(impl, me, ACQUIRE_PARENT);
        return LEVEL_LOCAL;
    }

    // Not reached threshold
    hyshmcs_qnode_t *succ = me->next;
    if (succ) {
        DEBUG("[%2d] Successor is here for lock %p (succ=%p, cur_count=%lu, "
              "me=%p)\n",
              cur_thread_id, impl, succ, cur_count, me);
        succ->status = cur_count + 1;
        return LEVEL_LOCAL;
    }

    // No known successor, release to parent
    __hyshmcs_mutex_global_unlock(impl->parent, &impl->node);

    // Ask successor to acquire next-level lock
    __hyshmcs_release_helper(impl, me, ACQUIRE_PARENT);
    return LEVEL_GLOBAL;
}

static inline void __hyshmcs_mutex_lock(hyshmcs_mutex_t *impl,
                                        hyshmcs_qnode_t *me) {
    DEBUG("[%2d] Mutex lock %p at level %s\n", cur_thread_id, impl,
          me->cur_depth == LEVEL_LOCAL ? "local" : "global");
    hyshmcs_hnode_t *cur_lock = NULL;

    if (me->cur_depth == LEVEL_LOCAL) {
        cur_lock = &impl->local[current_numa_node()];
    } else {
        cur_lock = &impl->global;
    }

    hyshmcs_qnode_t *cur_tail = cur_lock->tail;
    uint8_t new_level         = 0;
    hyshmcs_hnode_t *new_lock = NULL;

    // Is current level contended ?
    if (cur_tail == NULL) {
        // Is root-level contended ?
        if (impl->global.tail == NULL) {
            // Root is uncontended, take fast-path
            DEBUG("[%2d] Taking fast-path\n", cur_thread_id);
            me->took_fast_path = true;
            __hyshmcs_mutex_global_lock(&impl->global, me);
            return;
        }

        // Root is contended, take slow-path
        new_level = me->cur_depth;
        new_lock = cur_lock;
    } else if (me->cur_depth == LEVEL_GLOBAL &&
               (me->next && me->next != cur_tail)) {
        // Current level is sufficiently contended (at least 2 successors
        // waiting)
        // Eagerly enqueue at a level below

        // Normaly, here we switch from global to local
        new_level = LEVEL_LOCAL;
        new_lock  = &impl->local[current_numa_node()];
    } else {
        // Either no child level or the current level is not sufficiently
        // contended
        new_level = me->cur_depth;
        new_lock  = cur_lock;
    }

    me->cur_node   = new_lock;
    me->real_depth = new_level;

    // Slow-path
    if (new_level == LEVEL_LOCAL) {
        me->depth_waited = __hyshmcs_mutex_local_lock(new_lock, me);
    } else {
        me->depth_waited = __hyshmcs_mutex_global_lock(new_lock, me);
    }
}

int hyshmcs_mutex_lock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me) {
    __hyshmcs_mutex_lock(impl, me);
#if COND_VAR
    assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    DEBUG("[%2d]\tLock acquired %p (me=%p)\n", cur_thread_id, impl, me);
#endif
    return 0;
}

static inline int __hyshmcs_mutex_global_trylock(hyshmcs_hnode_t *impl,
                                                 hyshmcs_qnode_t *me) {
    hyshmcs_qnode_t *tail;

    me->next   = 0;
    me->status = LOCKED;

    tail = __sync_val_compare_and_swap(&impl->tail, NULL, me);
    if (tail == NULL) {
        me->status = UNLOCKED;
        return 0;
    }

    return EBUSY;
}

int hyshmcs_mutex_trylock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me) {
    // Here we only try fast-path locking because we know than the trylock
    //  will succeed only if the root is uncontended

    if (impl->global.tail == NULL) {
        // Root is uncontended, take fast-path
        int ret = __hyshmcs_mutex_global_trylock(&impl->global, me);
        if (ret == 0) {
            me->took_fast_path = true;
#if COND_VAR
            while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) ==
                   EBUSY)
                ;
            assert(ret == 0);
#endif
            return 0;
        }
        return ret;
    }

    return EBUSY;
}

static inline void __hyshmcs_mutex_unlock(hyshmcs_mutex_t *impl,
                                          hyshmcs_qnode_t *me) {
    uint8_t depth_passed;

    if (me->took_fast_path) {
        DEBUG("[%2d]\tUnlocking after fast-path %p (me=%p)\n", cur_thread_id,
              impl, me);
        __hyshmcs_mutex_global_unlock(&impl->global, me);
        me->took_fast_path = false;
    } else {
        if (me->real_depth == LEVEL_LOCAL) {
            DEBUG("[%2d]\tUnlocking at local level %p (me=%p)\n", cur_thread_id,
                  impl, me);
            depth_passed = __hyshmcs_mutex_local_unlock(me->cur_node, me);
        } else {
            DEBUG("[%2d]\tUnlocking at global level %p (me=%p)\n",
                  cur_thread_id, impl, me);
            depth_passed = __hyshmcs_mutex_global_unlock(me->cur_node, me);
        }

        // Key logic to adjust to contention
        // If we acquired and released closer to the leaf in the tree,
        // compare to the currently noted depth, we recede a level closer to the
        // leaf
        if (me->cur_depth == LEVEL_GLOBAL &&
            ((me->depth_waited == LEVEL_LOCAL) ||
             (depth_passed == LEVEL_LOCAL))) {
            me->cur_depth = LEVEL_LOCAL;
        } else {
            // If we acquired and released closer to the root in the tree,
            // compare to the currently noted depth, we recede a level closer to
            // the root
            if (me->cur_depth == LEVEL_LOCAL &&
                ((me->depth_waited == LEVEL_GLOBAL) &&
                 (depth_passed == LEVEL_GLOBAL))) {
                me->cur_depth = LEVEL_GLOBAL;
            }
        }
    }
}

void hyshmcs_mutex_unlock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me) {
#if COND_VAR
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __hyshmcs_mutex_unlock(impl, me);
}

int hyshmcs_mutex_destroy(hyshmcs_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int hyshmcs_cond_init(hyshmcs_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hyshmcs_cond_timedwait(hyshmcs_cond_t *cond, hyshmcs_mutex_t *lock,
                           hyshmcs_qnode_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;
    __hyshmcs_mutex_unlock(lock, me);

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

    hyshmcs_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hyshmcs_cond_wait(hyshmcs_cond_t *cond, hyshmcs_mutex_t *lock,
                      hyshmcs_qnode_t *me) {
#if COND_VAR
    return hyshmcs_cond_timedwait(cond, lock, me, 0);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hyshmcs_cond_signal(hyshmcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hyshmcs_cond_broadcast(hyshmcs_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int hyshmcs_cond_destroy(hyshmcs_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void hyshmcs_thread_start(void) {
}

void hyshmcs_thread_exit(void) {
}

void hyshmcs_application_init(void) {
}

void hyshmcs_application_exit(void) {
}
void hyshmcs_init_context(lock_mutex_t *impl, lock_context_t *context,
                          int number) {
    uint32_t i;
    for (i = 0; i < number; i++) {
        context[i].took_fast_path = false;
        context[i].cur_depth      = LEVEL_LOCAL;
    }
}
