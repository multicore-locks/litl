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
 * David Dice. 2011.
 * Brief announcement: a partitioned ticket lock.
 * In Proceedings of the twenty-third annual ACM symposium on Parallelism in
 * algorithms and architectures (SPAA '11)
 *
 * Lock design summary:
 * The partitioned ticket lock is a variant of the ticket lock aiming to
 * lower the number of threads waiting on the same memory address,
 * in order to limit contention due cache coherency protocol.
 * This lock is composed of a request variable, an owner-ticket variable and a
 * fixed-size array of grants variables
 * - On lock, the thread atomically increments the request variable to get its
 * ticket, then spinloop on the grants[my_ticket % SIZE] array slot.
 * - On unlock, the thread increments the grants[(owner_ticket + 1) % SIZE]
 * atomatically to wake the first thread waiting on this slot.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <partitioned.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

partitioned_mutex_t *partitioned_mutex_create(const pthread_mutexattr_t *attr) {
    partitioned_mutex_t *impl =
        (partitioned_mutex_t *)alloc_cache_align(sizeof(partitioned_mutex_t));
    impl = memset(impl, 0, sizeof *impl);
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int partitioned_mutex_lock(partitioned_mutex_t *impl,
                           partitioned_context_t *UNUSED(me)) {
    uint32_t t = __sync_fetch_and_add(&impl->u.request, 1);
    while (impl->u.grants[t % PTL_SLOTS].grant != t)
        CPU_PAUSE();

    impl->u.owner_ticket = t;
#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int partitioned_mutex_trylock(partitioned_mutex_t *impl,
                              partitioned_context_t *UNUSED(me)) {
    /**
     * It is not possible to implement a true trylock with partitioned ticket
     *lock.
     * As the partitioned provides cohort detection, we can watch if there is
     *anyone else, and if not try a sleep lock
     **/
    if (impl->u.grants[impl->u.request % PTL_SLOTS].grant != impl->u.request) {
        return EBUSY;
    }

    /**
     * If the lock is abortable, we can try a few time and abort.
     * But partitioned ticket lock is not abortable, so we might potentially
     *wait (this seems the best we can do).
     **/
    uint32_t t = __sync_fetch_and_add(&impl->u.request, 1);
    while (impl->u.grants[t % PTL_SLOTS].grant != t)
        CPU_PAUSE();

    impl->u.owner_ticket = t;

#if COND_VAR
    int ret;
    while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
        ;
    assert(ret == 0);
#endif
    return 0;
}

void __partitioned_mutex_unlock(partitioned_mutex_t *impl) {
    int new_owner_ticket = impl->u.owner_ticket + 1;
    COMPILER_BARRIER();
    impl->u.grants[new_owner_ticket % PTL_SLOTS].grant = new_owner_ticket;
}

void partitioned_mutex_unlock(partitioned_mutex_t *impl,
                              partitioned_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __partitioned_mutex_unlock(impl);
}

int partitioned_mutex_destroy(partitioned_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int partitioned_cond_init(partitioned_cond_t *cond,
                          const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int partitioned_cond_timedwait(partitioned_cond_t *cond,
                               partitioned_mutex_t *lock,
                               partitioned_context_t *me,
                               const struct timespec *ts) {
#if COND_VAR
    int res;

    __partitioned_mutex_unlock(lock);

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

    partitioned_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int partitioned_cond_wait(partitioned_cond_t *cond, partitioned_mutex_t *lock,
                          partitioned_context_t *me) {
    return partitioned_cond_timedwait(cond, lock, me, 0);
}

int partitioned_cond_signal(partitioned_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int partitioned_cond_broadcast(partitioned_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int partitioned_cond_destroy(partitioned_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void partitioned_thread_start(void) {
}

void partitioned_thread_exit(void) {
}

void partitioned_application_init(void) {
}

void partitioned_application_exit(void) {
}

void partitioned_init_context(lock_mutex_t *UNUSED(impl),
                              lock_context_t *UNUSED(context),
                              int UNUSED(number)) {
}
