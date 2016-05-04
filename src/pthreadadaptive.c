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
 * A wrapper around posix locks, with the PTHREAD_MUTEX_ADAPTIVE_NP flag.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <pthreadadaptive.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

pthread_adaptive_mutex_t *
pthread_adaptive_mutex_create(const pthread_mutexattr_t *attr) {
    pthread_adaptive_mutex_t *impl =
        (pthread_adaptive_mutex_t *)alloc_cache_align(
            sizeof(pthread_adaptive_mutex_t));

    pthread_mutexattr_t tattr;
    pthread_mutexattr_init(&tattr);
    pthread_mutexattr_settype(&tattr, PTHREAD_MUTEX_ADAPTIVE_NP);
    REAL(pthread_mutex_init)(&impl->lock, &tattr);
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int pthread_adaptive_mutex_lock(pthread_adaptive_mutex_t *impl,
                                pthread_adaptive_context_t *UNUSED(me)) {
    int ret = REAL(pthread_mutex_lock)(&impl->lock);
#if COND_VAR
    ret = REAL(pthread_mutex_lock)(&impl->posix_lock);
#endif
    assert(ret == 0);

    return 0;
}

int pthread_adaptive_mutex_trylock(pthread_adaptive_mutex_t *impl,
                                   pthread_adaptive_context_t *UNUSED(me)) {
    if (REAL(pthread_mutex_trylock)(&impl->lock) != EBUSY) {
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

void pthread_adaptive_mutex_unlock(pthread_adaptive_mutex_t *impl,
                                   pthread_adaptive_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif

    REAL(pthread_mutex_unlock)(&impl->lock);
}

int pthread_adaptive_mutex_destroy(pthread_adaptive_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    REAL(pthread_mutex_destroy)(&lock->lock);
    free(lock);
    lock = NULL;

    return 0;
}

int pthread_adaptive_cond_init(pthread_adaptive_cond_t *cond,
                               const pthread_condattr_t *attr) {
    return REAL(pthread_cond_init)(cond, attr);
}

int pthread_adaptive_cond_timedwait(pthread_adaptive_cond_t *cond,
                                    pthread_adaptive_mutex_t *lock,
                                    pthread_adaptive_context_t *UNUSED(me),
                                    const struct timespec *ts) {
    int res;

#if COND_VAR
    REAL(pthread_mutex_unlock)(&lock->lock);

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

    REAL(pthread_mutex_lock)(&lock->lock);
    REAL(pthread_mutex_lock)(&lock->posix_lock);
#else
    if (ts)
        res = REAL(pthread_cond_timedwait)(cond, &lock->lock, ts);
    else
        res = REAL(pthread_cond_wait)(cond, &lock->lock);
#endif

    return res;
}

int pthread_adaptive_cond_wait(pthread_adaptive_cond_t *cond,
                               pthread_adaptive_mutex_t *lock,
                               pthread_adaptive_context_t *UNUSED(me)) {
    return pthread_adaptive_cond_timedwait(cond, lock, NULL, 0);
}

int pthread_adaptive_cond_signal(pthread_adaptive_cond_t *cond) {
    return REAL(pthread_cond_signal)(cond);
}

int pthread_adaptive_cond_broadcast(pthread_adaptive_cond_t *cond) {
    return REAL(pthread_cond_broadcast)(cond);
}

int pthread_adaptive_cond_destroy(pthread_adaptive_cond_t *cond) {
    return REAL(pthread_cond_destroy)(cond);
}

void pthread_adaptive_thread_start(void) {
}

void pthread_adaptive_thread_exit(void) {
}

void pthread_adaptive_application_init(void) {
}

void pthread_adaptive_application_exit(void) {
}

void pthread_adaptive_init_context(lock_mutex_t *UNUSED(impl),
                                   lock_context_t *UNUSED(context),
                                   int UNUSED(number)) {
}
