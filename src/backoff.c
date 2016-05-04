/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *               2010-2014 Samy Al Bahra.
 *               2011-2013 AppNexus, Inc.
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
 * The backoff implementation is taken from concurrencykit
 * https://github.com/concurrencykit/ck/blob/master/include/ck_backoff.h.
 *
 * Lock design summary:
 * - This is a basic spinlock (all threads wait on the same memory address)
 * - On lock, the thread first checks if the lock is taken, and if so wait (busy
 * waiting)
 * - The wait time evolves each time the thread fails to take the lock (* 2 each
 * time, bounded to MAX_BACKOFF_DELAY)
 * - On unlock, a simple atomic test&set unlocks the lock
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
#include <backoff.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

backoff_mutex_t *backoff_mutex_create(const pthread_mutexattr_t *attr) {
    backoff_mutex_t *impl =
        (backoff_mutex_t *)alloc_cache_align(sizeof(backoff_mutex_t));
    impl->spin_lock = UNLOCKED;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int backoff_mutex_lock(backoff_mutex_t *impl, backoff_context_t *UNUSED(me)) {
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

#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int backoff_mutex_trylock(backoff_mutex_t *impl,
                          backoff_context_t *UNUSED(me)) {
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

void __backoff_mutex_unlock(backoff_mutex_t *impl) {
    COMPILER_BARRIER();
    impl->spin_lock = UNLOCKED;
}

void backoff_mutex_unlock(backoff_mutex_t *impl,
                          backoff_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __backoff_mutex_unlock(impl);
}

int backoff_mutex_destroy(backoff_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int backoff_cond_init(backoff_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int backoff_cond_timedwait(backoff_cond_t *cond, backoff_mutex_t *lock,
                           backoff_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __backoff_mutex_unlock(lock);

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

    backoff_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int backoff_cond_wait(backoff_cond_t *cond, backoff_mutex_t *lock,
                      backoff_context_t *me) {
    return backoff_cond_timedwait(cond, lock, me, 0);
}

int backoff_cond_signal(backoff_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int backoff_cond_broadcast(backoff_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int backoff_cond_destroy(backoff_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void backoff_thread_start(void) {
}

void backoff_thread_exit(void) {
}

void backoff_application_init(void) {
}

void backoff_application_exit(void) {
}

void backoff_init_context(lock_mutex_t *UNUSED(impl),
                          lock_context_t *UNUSED(context), int UNUSED(number)) {
}
