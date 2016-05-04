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
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <ttas.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

ttas_mutex_t *ttas_mutex_create(const pthread_mutexattr_t *attr) {
    ttas_mutex_t *impl =
        (ttas_mutex_t *)alloc_cache_align(sizeof(ttas_mutex_t));
    impl->spin_lock = UNLOCKED;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int ttas_mutex_lock(ttas_mutex_t *impl, ttas_context_t *UNUSED(me)) {
    while (1) {
        while (impl->spin_lock != UNLOCKED)
            CPU_PAUSE();

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

int ttas_mutex_trylock(ttas_mutex_t *impl, ttas_context_t *UNUSED(me)) {
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

void __ttas_mutex_unlock(ttas_mutex_t *impl) {
    COMPILER_BARRIER();
    impl->spin_lock = UNLOCKED;
}

void ttas_mutex_unlock(ttas_mutex_t *impl, ttas_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __ttas_mutex_unlock(impl);
}

int ttas_mutex_destroy(ttas_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int ttas_cond_init(ttas_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttas_cond_timedwait(ttas_cond_t *cond, ttas_mutex_t *lock,
                        ttas_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __ttas_mutex_unlock(lock);

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

    ttas_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttas_cond_wait(ttas_cond_t *cond, ttas_mutex_t *lock, ttas_context_t *me) {
    return ttas_cond_timedwait(cond, lock, me, 0);
}

int ttas_cond_signal(ttas_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttas_cond_broadcast(ttas_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ttas_cond_destroy(ttas_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void ttas_thread_start(void) {
}

void ttas_thread_exit(void) {
}

void ttas_application_init(void) {
}

void ttas_application_exit(void) {
}

void ttas_init_context(lock_mutex_t *UNUSED(impl),
                       lock_context_t *UNUSED(context), int UNUSED(number)) {
}
