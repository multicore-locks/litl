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
 * Michael L. Scott. 2013.
 * Shared-Memory Synchronization.
 * Morgan & Claypool Publishers.
 *
 * Variant with standard interface.
 *
 * Lock design summary:
 * The CLH lock is a FIFO lock that uses two pointers (head and tail of the
 * waiting list)
 * Each thread has its context, composed of a memory location on which any
 * thread can spin, and a pointer to the context to use for the next lock
 * acquisition (a thread gives its context when it releases the lock).
 * - On lock, the thread adds its current context to the tail of the waiting
 * list and spins on the memory space of the thread before it
 * - When the thread acquires the lock, it takes the context of the thread that
 * has unlocked him (the context shifts from thread to thread)
 * - On unlock, the thread simply wakes the thread at the head of the waiting
 * list.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <clh.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

clh_mutex_t *clh_mutex_create(const pthread_mutexattr_t *attr) {
    clh_mutex_t *impl = (clh_mutex_t *)alloc_cache_align(sizeof(clh_mutex_t));
    // At the beginning, all threads need a first context.
    // This context is embedded inside the lock itself (dummy)
    impl->dummy.spin = UNLOCKED;
    impl->head       = NULL;
    impl->tail       = &impl->dummy;

#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
    DEBUG("Mutex init lock=%p posix_lock=%p\n", impl, &impl->posix_lock);
#endif

    return impl;
}

void clh_init_context(lock_mutex_t *impl, lock_context_t *ctx, int number) {
    int i;

    // At the beginning, all threads use the node embedded in their own context
    for (i = 0; i < number; i++) {
        ctx[i].initial.spin = UNLOCKED;
        ctx[i].current      = &ctx[i].initial;
    }
}

static int __clh_mutex_lock(clh_mutex_t *impl, clh_context_t *me) {
    clh_node_t *p = me->current;
    p->spin       = LOCKED;

    // The thread enqueues
    clh_node_t *pred = xchg_64((void *)&impl->tail, (void *)p);
    // If the previous thread was locked, we wait on its context
    waiting_policy_sleep(&pred->spin);
    impl->head = p;
    COMPILER_BARRIER();
    // We take the context of the previous thread
    me->current = pred;

    return 0;
}

int clh_mutex_lock(clh_mutex_t *impl, clh_context_t *me) {
    int ret = __clh_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

int clh_mutex_trylock(clh_mutex_t *impl, clh_context_t *me) {
    assert(0 && "Trylock not implemented for CLH.");

    return EBUSY;
}

static void __clh_mutex_unlock(clh_mutex_t *impl, clh_context_t *me) {
    COMPILER_BARRIER();
    waiting_policy_wake(&impl->head->spin);
}

void clh_mutex_unlock(clh_mutex_t *impl, clh_context_t *me) {
#if COND_VAR
    DEBUG_PTHREAD("[%d] Unlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __clh_mutex_unlock(impl, me);
}

int clh_mutex_destroy(clh_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int clh_cond_init(clh_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clh_cond_timedwait(clh_cond_t *cond, clh_mutex_t *lock, clh_context_t *me,
                       const struct timespec *ts) {
#if COND_VAR
    int res;

    __clh_mutex_unlock(lock, me);
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

    clh_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clh_cond_wait(clh_cond_t *cond, clh_mutex_t *lock, clh_context_t *me) {
    return clh_cond_timedwait(cond, lock, me, 0);
}

int clh_cond_signal(clh_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clh_cond_broadcast(clh_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clh_cond_destroy(clh_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void clh_thread_start(void) {
}

void clh_thread_exit(void) {
}

void clh_application_init(void) {
}

void clh_application_exit(void) {
}
