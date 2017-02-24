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
 * V. Trigonakis et al.
 * Unlocking Energy
 * USENIX ATC 16
 *
 * Lock design summary:
 * Lock designed to energy efficiency
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <mutexee.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

const struct timespec mutexee_max_sleep = { .tv_sec = MUTEXEE_FTIMEOUTS,
					    .tv_nsec = MUTEXEE_FTIMEOUT };

mutexee_mutex_t *mutexee_mutex_create(const pthread_mutexattr_t *attr) {
    mutexee_mutex_t *impl =
        (mutexee_mutex_t *)alloc_cache_align(sizeof(mutexee_mutex_t));
    mutexee_init(&impl->lock, attr);
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int mutexee_mutex_lock(mutexee_mutex_t *impl,
                        mutexee_context_t *UNUSED(me)) {
    mutexee_lock(&impl->lock);
#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int mutexee_mutex_trylock(mutexee_mutex_t *impl,
                           mutexee_context_t *UNUSED(me)) {
    if (mutexee_lock_trylock(&impl->lock) != EBUSY) {
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

void mutexee_mutex_unlock(mutexee_mutex_t *impl,
                           mutexee_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    mutexee_unlock(&impl->lock);
}

int mutexee_mutex_destroy(mutexee_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    mutexee_destroy(&lock->lock);
    free(lock);
    lock = NULL;

    return 0;
}

int mutexee_cond_init(mutexee_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mutexee_cond_timedwait(mutexee_cond_t *cond, mutexee_mutex_t *lock,
                            mutexee_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    mutexee_unlock(&lock->lock);

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

    mutexee_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mutexee_cond_wait(mutexee_cond_t *cond, mutexee_mutex_t *lock,
                       mutexee_context_t *me) {
    return mutexee_cond_timedwait(cond, lock, me, 0);
}

int mutexee_cond_signal(mutexee_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mutexee_cond_broadcast(mutexee_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mutexee_cond_destroy(mutexee_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void mutexee_thread_start(void) {
}

void mutexee_thread_exit(void) {
}

void mutexee_application_init(void) {
}

void mutexee_application_exit(void) {
}

void mutexee_init_context(lock_mutex_t *UNUSED(impl),
                           lock_context_t *UNUSED(context),
                           int UNUSED(number)) {
}
