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
 * For a description of the algorithm, see ticket.c
 *
 * This version adds a backoff delay between two locking attempts that is
 * proportionnal to the difference between the thread's ticket and the
 * grant variable.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <ticketepfl.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

ticketepfl_mutex_t *ticketepfl_mutex_create(const pthread_mutexattr_t *attr) {
    ticketepfl_mutex_t *impl =
        (ticketepfl_mutex_t *)alloc_cache_align(sizeof(ticketepfl_mutex_t));
    impl->u.s.request = 0;
    impl->u.s.grant   = 1;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    return impl;
}

static inline uint32_t sub_abs(const uint32_t a, const uint32_t b) {
    if (a > b) {
        return a - b;
    } else {
        return b - a;
    }
}

int ticketepfl_mutex_lock(ticketepfl_mutex_t *impl,
                          ticketepfl_context_t *UNUSED(me)) {
    // Acquire the local lock
    uint32_t my_ticket     = __sync_add_and_fetch(&impl->u.s.request, 1);
    uint32_t wait          = TICKET_BASE_WAIT;
    uint32_t distance_prev = 1;

    while (1) {
        PREFETCHW(&impl->u.u);
        uint32_t cur = impl->u.s.grant;
        if (cur == my_ticket) {
            break;
        }
        uint32_t distance = sub_abs(cur, my_ticket);
        if (distance > 1) {
            if (distance != distance_prev) {
                distance_prev = distance;
                wait          = TICKET_BASE_WAIT;
            }

            nop_rep(distance * wait);
            /* wait = (wait + TICKET_BASE_WAIT) & TICKET_MAX_WAIT; */
        } else {
            nop_rep(TICKET_WAIT_NEXT);
        }

        if (distance > 20) {
            sched_yield();
            /* pthread_yield(); */
        }
    }

#if COND_VAR
    int ret = REAL(pthread_mutex_lock)(&impl->posix_lock);

    assert(ret == 0);
#endif
    return 0;
}

int ticketepfl_mutex_trylock(ticketepfl_mutex_t *impl,
                             ticketepfl_context_t *UNUSED(me)) {
    // Trylock the local lock
    uint32_t me     = impl->u.s.request;
    uint32_t menew  = me + 1;
    uint64_t cmp    = ((uint64_t)me << 32) + menew;
    uint64_t cmpnew = ((uint64_t)menew << 32) + menew;

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

void __ticketepfl_mutex_unlock(ticketepfl_mutex_t *impl) {
    PREFETCHW(&impl->u.u);
    COMPILER_BARRIER();
    impl->u.s.grant++;
}

void ticketepfl_mutex_unlock(ticketepfl_mutex_t *impl,
                             ticketepfl_context_t *UNUSED(me)) {
#if COND_VAR
    int ret = REAL(pthread_mutex_unlock)(&impl->posix_lock);
    assert(ret == 0);
#endif
    __ticketepfl_mutex_unlock(impl);
}

int ticketepfl_mutex_destroy(ticketepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int ticketepfl_cond_init(ticketepfl_cond_t *cond,
                         const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticketepfl_cond_timedwait(ticketepfl_cond_t *cond, ticketepfl_mutex_t *lock,
                              ticketepfl_context_t *me,
                              const struct timespec *ts) {
#if COND_VAR
    int res;

    __ticketepfl_mutex_unlock(lock);

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

    ticketepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticketepfl_cond_wait(ticketepfl_cond_t *cond, ticketepfl_mutex_t *lock,
                         ticketepfl_context_t *me) {
    return ticketepfl_cond_timedwait(cond, lock, me, 0);
}

int ticketepfl_cond_signal(ticketepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticketepfl_cond_broadcast(ticketepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int ticketepfl_cond_destroy(ticketepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void ticketepfl_thread_start(void) {
}

void ticketepfl_thread_exit(void) {
}

void ticketepfl_application_init(void) {
}

void ticketepfl_application_exit(void) {
}

void ticketepfl_init_context(lock_mutex_t *UNUSED(impl),
                             lock_context_t *UNUSED(context),
                             int UNUSED(number)) {
}
