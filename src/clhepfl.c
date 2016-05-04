/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *               2013 Tudor David
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
 * For a description of the algorithm, see clh.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <clhepfl.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

clhepfl_mutex_t *clhepfl_mutex_create(const pthread_mutexattr_t *attr) {
    clhepfl_mutex_t *impl =
        (clhepfl_mutex_t *)alloc_cache_align(sizeof(clhepfl_mutex_t));
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

void clhepfl_init_context(lock_mutex_t *impl, lock_context_t *ctx, int number) {
    int i;

    // At the beginning, all threads use the node embedded in their own context
    for (i = 0; i < number; i++) {
        ctx[i].initial.spin = UNLOCKED;
        ctx[i].current      = &ctx[i].initial;
    }
}

static int __clhepfl_mutex_lock(clhepfl_mutex_t *impl, clhepfl_context_t *me) {
    clhepfl_node_t *p = me->current;
    p->spin           = LOCKED;

    MEMORY_BARRIER();
    // The thread enqueues
    clhepfl_node_t *pred = xchg_64((void *)&impl->tail, (void *)p);
    if (pred == NULL)
        return 0;

    // If the previous thread was locked, we wait on its context
    PREFETCHW(pred);
    while (pred->spin == LOCKED) {
        CPU_PAUSE();
        pause_rep(REP_VAL);
        PREFETCHW(pred);
    }

    impl->head = p;
    COMPILER_BARRIER();
    // We take the context of the previous thread
    me->current = pred;

    return 0;
}

int clhepfl_mutex_lock(clhepfl_mutex_t *impl, clhepfl_context_t *me) {
    int ret = __clhepfl_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

int clhepfl_mutex_trylock(clhepfl_mutex_t *impl, clhepfl_context_t *me) {
    assert(0 && "Trylock not implemented for CLHEPFL.");

    return EBUSY;
}

static void __clhepfl_mutex_unlock(clhepfl_mutex_t *impl,
                                   clhepfl_context_t *me) {
    COMPILER_BARRIER();
    impl->head->spin = UNLOCKED;
}

void clhepfl_mutex_unlock(clhepfl_mutex_t *impl, clhepfl_context_t *me) {
#if COND_VAR
    DEBUG_PTHREAD("[%d] Unlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __clhepfl_mutex_unlock(impl, me);
}

int clhepfl_mutex_destroy(clhepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int clhepfl_cond_init(clhepfl_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clhepfl_cond_timedwait(clhepfl_cond_t *cond, clhepfl_mutex_t *lock,
                           clhepfl_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __clhepfl_mutex_unlock(lock, me);
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

    clhepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clhepfl_cond_wait(clhepfl_cond_t *cond, clhepfl_mutex_t *lock,
                      clhepfl_context_t *me) {
    return clhepfl_cond_timedwait(cond, lock, me, 0);
}

int clhepfl_cond_signal(clhepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clhepfl_cond_broadcast(clhepfl_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int clhepfl_cond_destroy(clhepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void clhepfl_thread_start(void) {
}

void clhepfl_thread_exit(void) {
}

void clhepfl_application_init(void) {
}

void clhepfl_application_exit(void) {
}
