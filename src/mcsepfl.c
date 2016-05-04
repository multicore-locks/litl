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
 * John M. Mellor-Crummey and Michael L. Scott. 1991.
 * Algorithms for scalable synchronization on shared-memory multiprocessors.
 * ACM Trans. Comput. Syst. 9, 1 (February 1991).
 *
 * For a description of the algorithm, see mcs.c
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <mcsepfl.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

mcsepfl_mutex_t *mcsepfl_mutex_create(const pthread_mutexattr_t *attr) {
    mcsepfl_mutex_t *impl =
        (mcsepfl_mutex_t *)alloc_cache_align(sizeof(mcsepfl_mutex_t));
    impl->tail = 0;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, /*&errattr */ attr);
    DEBUG("Mutex init lock=%p posix_lock=%p\n", impl, &impl->posix_lock);
#endif

    return impl;
}

static int __mcsepfl_mutex_lock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me) {
    mcsepfl_node_t *tail;

    me->next = 0;

    MEMORY_BARRIER();
    tail = xchg_64((void *)&impl->tail, (void *)me);

    /* No one there? */
    if (!tail) {
        DEBUG("[%d] (1) Locking lock=%p tail=%p me=%p\n", cur_thread_id, impl,
              impl->tail, me);
        return 0;
    }

    me->spin = LOCKED;
    MEMORY_BARRIER();
    tail->next = me;

    PREFETCHW(me);

    while (me->spin != UNLOCKED) {
        CPU_PAUSE();
        pause_rep(REP_VAL);
        PREFETCHW(me);
    }

    DEBUG("[%d] (2) Locking lock=%p tail=%p me=%p\n", cur_thread_id, impl,
          impl->tail, me);
    return 0;
}

int mcsepfl_mutex_lock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me) {
    int ret = __mcsepfl_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    DEBUG("[%d] Lock acquired posix=%p\n", cur_thread_id, &impl->posix_lock);
    return ret;
}

int mcsepfl_mutex_trylock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me) {
    mcsepfl_node_t *tail;

    me->next = 0;

    MEMORY_BARRIER();
    /* Try to lock */
    tail = __sync_val_compare_and_swap(&impl->tail, 0, me);

    /* No one was there - can quickly return */
    if (!tail) {
#if COND_VAR
        DEBUG("[%d] TryLocking lock=%p tail=%p me=%p\n", cur_thread_id, impl,
              impl->tail, me);
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        int ret = 0;
        while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
            ;
        assert(ret == 0);
#endif
        return 0;
    }

    return EBUSY;
}

static void __mcsepfl_mutex_unlock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me) {
    DEBUG("[%d] Unlocking lock=%p tail=%p me=%p\n", cur_thread_id, impl,
          impl->tail, me);

    volatile mcsepfl_node_t *succ;
    PREFETCHW(me);

    /* No successor yet? */
    if (!(succ = me->next)) {
        /* Try to atomically unlock */
        if (__sync_val_compare_and_swap(&impl->tail, me, 0) == me)
            return;

        /* Wait for successor to appear */
        do {
            succ = me->next;
            CPU_PAUSE();
        } while (!succ);
    }

    /* Unlock next one */
    succ->spin = UNLOCKED;
}

void mcsepfl_mutex_unlock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me) {
#if COND_VAR
    DEBUG_PTHREAD("[%d] Unlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __mcsepfl_mutex_unlock(impl, me);
}

int mcsepfl_mutex_destroy(mcsepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int mcsepfl_cond_init(mcsepfl_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcsepfl_cond_timedwait(mcsepfl_cond_t *cond, mcsepfl_mutex_t *lock,
                           mcsepfl_node_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __mcsepfl_mutex_unlock(lock, me);
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

    mcsepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcsepfl_cond_wait(mcsepfl_cond_t *cond, mcsepfl_mutex_t *lock,
                      mcsepfl_node_t *me) {
    return mcsepfl_cond_timedwait(cond, lock, me, 0);
}

int mcsepfl_cond_signal(mcsepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcsepfl_cond_broadcast(mcsepfl_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcsepfl_cond_destroy(mcsepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void mcsepfl_thread_start(void) {
}

void mcsepfl_thread_exit(void) {
}

void mcsepfl_application_init(void) {
}

void mcsepfl_application_exit(void) {
}
void mcsepfl_init_context(lock_mutex_t *UNUSED(impl),
                          lock_context_t *UNUSED(context), int UNUSED(number)) {
}
