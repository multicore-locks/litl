/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *               2016 Lockless Inc
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
 * Lock design summary:
 * The ticket lock is a variant of spinlock that allows limiting the number of
 * atomic instructions on the lock acquire path.
 * This lock is composed of a request variable, and a grant variable.
 * - On lock, the thread atomically increments the request variable to get its
 * ticket, then spinloop while its ticket is different from the grant.
 * - On unlock, the thread increments the grant variable.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <ticket.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

ticket_mutex_t *ticket_mutex_create(const pthread_mutexattr_t *attr) {
    ticket_mutex_t *impl =
        (ticket_mutex_t *)alloc_cache_align(sizeof(ticket_mutex_t));
    impl->u.s.request = 0;
    impl->u.s.grant   = 0;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

int ticket_mutex_lock(ticket_mutex_t *impl, ticket_context_t *UNUSED(me)) {
    // Acquire the local lock
    int t = __sync_fetch_and_add(&impl->u.s.request, 1);
    while (impl->u.s.grant != t)
        CPU_PAUSE();

#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int ticket_mutex_trylock(ticket_mutex_t *impl, ticket_context_t *UNUSED(me)) {
    // For a ticket trylock, we need to change both grant & request at the same
    // time
    // Thus we use 32-bit variables that we change to a 64-bit variable
    // and do a cmp&swp on it
    uint32_t me     = impl->u.s.request;
    uint32_t menew  = me + 1;
    uint64_t cmp    = ((uint64_t)me << 32) + me;
    uint64_t cmpnew = ((uint64_t)menew << 32) + me;

    if (__sync_val_compare_and_swap(&impl->u.u, cmp, cmpnew) != cmp)
        return EBUSY;

#if COND_VAR
    int ret;
    while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
        ;
    assert(ret == 0);
#endif
    return 0;
}

void __ticket_mutex_unlock(ticket_mutex_t *impl) {
    COMPILER_BARRIER();
    impl->u.s.grant++;
}

void ticket_mutex_unlock(ticket_mutex_t *impl, ticket_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __ticket_mutex_unlock(impl);
}

int ticket_mutex_destroy(ticket_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int ticket_cond_init(ticket_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticket_cond_timedwait(ticket_cond_t *cond, ticket_mutex_t *lock,
                          ticket_context_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __ticket_mutex_unlock(lock);

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

    ticket_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticket_cond_wait(ticket_cond_t *cond, ticket_mutex_t *lock,
                     ticket_context_t *me) {
    return ticket_cond_timedwait(cond, lock, me, 0);
}

int ticket_cond_signal(ticket_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticket_cond_broadcast(ticket_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticket_cond_destroy(ticket_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void ticket_thread_start(void) {
}

void ticket_thread_exit(void) {
}

void ticket_application_init(void) {
}

void ticket_application_exit(void) {
}

void ticket_init_context(lock_mutex_t *UNUSED(impl),
                         lock_context_t *UNUSED(context), int UNUSED(number)) {
}
