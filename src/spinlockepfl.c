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
 * Lock design summary:
 * This is just a test and set on the same memory location.
 *
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <spinlockepfl.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

#define UNLOCKED 0
#define LOCKED 1

spinlockepfl_mutex_t *
spinlockepfl_mutex_create(const pthread_mutexattr_t *attr) {
    spinlockepfl_mutex_t *impl =
        (spinlockepfl_mutex_t *)alloc_cache_align(sizeof(spinlockepfl_mutex_t));
    impl->spin_lock = UNLOCKED;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int spinlockepfl_mutex_lock(spinlockepfl_mutex_t *impl,
                            spinlockepfl_context_t *UNUSED(me)) {
    while (l_tas_uint8(&impl->spin_lock) != UNLOCKED)
        CPU_PAUSE();
#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int spinlockepfl_mutex_trylock(spinlockepfl_mutex_t *impl,
                               spinlockepfl_context_t *UNUSED(me)) {
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

void __spinlockepfl_mutex_unlock(spinlockepfl_mutex_t *impl) {
    COMPILER_BARRIER();
    impl->spin_lock = UNLOCKED;
}

void spinlockepfl_mutex_unlock(spinlockepfl_mutex_t *impl,
                               spinlockepfl_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __spinlockepfl_mutex_unlock(impl);
}

int spinlockepfl_mutex_destroy(spinlockepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int spinlockepfl_cond_init(spinlockepfl_cond_t *cond,
                           const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int spinlockepfl_cond_timedwait(spinlockepfl_cond_t *cond,
                                spinlockepfl_mutex_t *lock,
                                spinlockepfl_context_t *me,
                                const struct timespec *ts) {
#if COND_VAR
    int res;

    __spinlockepfl_mutex_unlock(lock);

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

    spinlockepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int spinlockepfl_cond_wait(spinlockepfl_cond_t *cond,
                           spinlockepfl_mutex_t *lock,
                           spinlockepfl_context_t *me) {
    return spinlockepfl_cond_timedwait(cond, lock, me, 0);
}

int spinlockepfl_cond_signal(spinlockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int spinlockepfl_cond_broadcast(spinlockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int spinlockepfl_cond_destroy(spinlockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void spinlockepfl_thread_start(void) {
}

void spinlockepfl_thread_exit(void) {
}

void spinlockepfl_application_init(void) {
}

void spinlockepfl_application_exit(void) {
}

void spinlockepfl_init_context(lock_mutex_t *UNUSED(impl),
                               lock_context_t *UNUSED(context),
                               int UNUSED(number)) {
}
