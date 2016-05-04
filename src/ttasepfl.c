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
 * T. E. Anderson. 1990.
 * The Performance of Spin Lock Alternatives for Shared-Memory Multiprocessors.
 * IEEE Trans. Parallel Distrib. Syst. 1, 1 (January 1990).
 *
 * Lock design summary:
 * This is just a test and set on the same memory location.
 * However, instead of doing an atomic operation for each loop iteration when
 * trying to grab the lock, the thread first tries to check if the lock is
 * taken with a regular memory access.
 * This avoid useless cache invalidations.
 * This version adds a randomized exponential backoff between two attempts to
 * grab the lock, in order to lower pressure on the lock.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <ttasepfl.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

__thread unsigned long *ttas_seeds;

ttasepfl_mutex_t *ttasepfl_mutex_create(const pthread_mutexattr_t *attr) {
    ttasepfl_mutex_t *impl =
        (ttasepfl_mutex_t *)alloc_cache_align(sizeof(ttasepfl_mutex_t));
    impl->spin_lock = UNLOCKED;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int ttasepfl_mutex_lock(ttasepfl_mutex_t *impl, ttasepfl_context_t *me) {
    volatile uint8_t *l = &(impl->spin_lock);
    uint32_t delay;

    while (1) {
        PREFETCHW(l);
        while ((*l) != UNLOCKED) {
            PREFETCHW(l);
        }
        if (l_tas_uint8(&(impl->spin_lock)) == UNLOCKED) {
#if COND_VAR
            int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);
            assert(ret == 0);
#endif
            return 0;
        } else {
            // backoff
            delay = my_random(&(ttas_seeds[0]), &(ttas_seeds[1]),
                              &(ttas_seeds[2])) %
                    (me->limit);
            me->limit =
                MAX_DELAY > 2 * (me->limit) ? 2 * (me->limit) : MAX_DELAY;
            cdelay(delay);
        }
    }
}

int ttasepfl_mutex_trylock(ttasepfl_mutex_t *impl,
                           ttasepfl_context_t *UNUSED(me)) {
    if (l_tas_uint8(&impl->spin_lock) == UNLOCKED) {
#if COND_VAR
        int ret = 0;
        while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
            CPU_PAUSE();

        assert(ret == 0);
#endif
        return 0;
    }

    return EBUSY;
}

void __ttasepfl_mutex_unlock(ttasepfl_mutex_t *impl) {
    COMPILER_BARRIER();
    impl->spin_lock = UNLOCKED;
}

void ttasepfl_mutex_unlock(ttasepfl_mutex_t *impl,
                           ttasepfl_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __ttasepfl_mutex_unlock(impl);
}

int ttasepfl_mutex_destroy(ttasepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int ttasepfl_cond_init(ttasepfl_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttasepfl_cond_timedwait(ttasepfl_cond_t *cond, ttasepfl_mutex_t *lock,
                            ttasepfl_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __ttasepfl_mutex_unlock(lock);

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

    ttasepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttasepfl_cond_wait(ttasepfl_cond_t *cond, ttasepfl_mutex_t *lock,
                       ttasepfl_context_t *me) {
    return ttasepfl_cond_timedwait(cond, lock, me, 0);
}

int ttasepfl_cond_signal(ttasepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttasepfl_cond_broadcast(ttasepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttasepfl_cond_destroy(ttasepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void ttasepfl_thread_start(void) {
    ttas_seeds = seed_rand();
}

void ttasepfl_thread_exit(void) {
}

void ttasepfl_application_init(void) {
    ttasepfl_thread_start();
}

void ttasepfl_application_exit(void) {
    ttasepfl_thread_exit();
}

void ttasepfl_init_context(lock_mutex_t *UNUSED(impl), lock_context_t *context,
                           int number) {
    int i;
    for (i = 0; i < number; i++) {
        context[i].limit = 1;
    }
}
