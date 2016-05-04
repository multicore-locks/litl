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
 * Tudor David, Rachid Guerraoui, and Vasileios Trigonakis. 2013.
 * Everything you always wanted to know about synchronization but were afraid to
 * ask.
 * In Proceedings of the Twenty-Fourth ACM Symposium on Operating Systems
 * Principles (SOSP '13).
 *
 * The idea of this is lock is very similar to the C-TKT-TKT (please refer to
 * the description of this algorithm).
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <htlockepfl.h>

#include "waiting_policy.h"
#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;

static inline int current_numa_node() {
    unsigned long a, d, c;
    int core;
    __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c));
    core = c & 0xFFF;
    return core / (CPU_NUMBER / NUMA_NODES);
}

htlockepfl_mutex_t *htlockepfl_mutex_create(const pthread_mutexattr_t *attr) {
    htlockepfl_mutex_t *impl =
        (htlockepfl_mutex_t *)alloc_cache_align(sizeof(htlockepfl_mutex_t));
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, attr);
#endif

    memset(impl, 0, sizeof *impl);

    // Init local tickets
    int i;
    for (i = 0; i < NUMA_NODES; i++) {
        impl->local[i].u.s.grant   = NB_TICKETS_LOCAL;
        impl->local[i].u.s.request = 0;
    }

    return impl;
}

static inline uint32_t sub_abs(const uint32_t a, const uint32_t b) {
    if (a > b) {
        return a - b;
    } else {
        return b - a;
    }
}

static inline void __htlockepfl_wait_global_ticket(ticket_lock_local_t *lock,
                                                   const uint32_t ticket) {
    while (lock->u.s.grant != ticket) {
        uint32_t distance = sub_abs(lock->u.s.grant, ticket);
        if (distance > 1) {
            wait_cycles(distance * 256);
        } else {
            CPU_PAUSE();
        }
    }
}

static inline void __htlockepfl_wait_local_ticket(ticket_lock_local_t *lock,
                                                  const uint32_t ticket) {
    uint32_t wait          = TICKET_BASE_WAIT;
    uint32_t distance_prev = 1;

    while (1) {
        PREFETCHW(lock);
        int32_t lock_cur = lock->u.s.grant;
        if (lock_cur == ticket) {
            break;
        }
        uint32_t distance = sub_abs(lock->u.s.grant, ticket);
        if (distance > 1) {
            if (distance != distance_prev) {
                distance_prev = distance;
                wait          = TICKET_BASE_WAIT;
            }

            nop_rep(distance * wait);
            wait = (wait + TICKET_BASE_WAIT) & TICKET_MAX_WAIT;
        } else {
            nop_rep(TICKET_WAIT_NEXT);
        }
    }
}

static int __htlockepfl_mutex_lock(htlockepfl_mutex_t *impl,
                                   htlockepfl_context_t *me) {
    me->last_numa_node              = current_numa_node();
    ticket_lock_local_t *local_lock = &impl->local[me->last_numa_node];
    int32_t local_ticket;

again_local:
    local_ticket = __sync_sub_and_fetch(&local_lock->u.s.request, 1);
    if (local_ticket < -1) {
        CPU_PAUSE();
        wait_cycles(-local_ticket * 120);
        CPU_PAUSE();
        goto again_local;
    }

    if (local_ticket >= 0) {
        __htlockepfl_wait_local_ticket(local_lock, local_ticket);
    } else {
        do {
            PREFETCHW(local_lock);
        } while (local_lock->u.s.grant != NB_TICKETS_LOCAL);
        local_lock->u.s.request = NB_TICKETS_LOCAL;

        ticket_lock_global_t *global_lock = &impl->global;
        uint32_t global_ticket =
            __sync_fetch_and_add(&global_lock->u.s.request, 1);

        __htlockepfl_wait_global_ticket((ticket_lock_local_t *)global_lock,
                                        global_ticket);
    }

    return 0;
}

int htlockepfl_mutex_lock(htlockepfl_mutex_t *impl, htlockepfl_context_t *me) {
    int ret = __htlockepfl_mutex_lock(impl, me);
    assert(ret == 0);
#if COND_VAR
    if (ret == 0) {
        DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);
        assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
    }
#endif
    return ret;
}

int htlockepfl_mutex_trylock(htlockepfl_mutex_t *impl,
                             htlockepfl_context_t *me) {
    assert("Trylock not supported by htlock yet." && 0);
}

static void __htlockepfl_mutex_unlock(htlockepfl_mutex_t *impl,
                                      htlockepfl_context_t *me) {
    ticket_lock_local_t *local = &impl->local[me->last_numa_node];
    PREFETCHW(local);

    int32_t local_grant = local->u.s.grant;
    int32_t local_request =
        __sync_val_compare_and_swap(&local->u.s.request, local_grant, 0);
    if (local_grant == 0 || local_grant == local_request) {
        PREFETCHW(&impl->global);
        PREFETCHW(local);

        local->u.s.grant = NB_TICKETS_LOCAL;
        impl->global.u.s.grant++;
    } else {
        PREFETCHW(local);
        local->u.s.grant = local_grant - 1;
    }
}

void htlockepfl_mutex_unlock(htlockepfl_mutex_t *impl,
                             htlockepfl_context_t *me) {
#if COND_VAR
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __htlockepfl_mutex_unlock(impl, me);
}

int htlockepfl_mutex_destroy(htlockepfl_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int htlockepfl_cond_init(htlockepfl_cond_t *cond,
                         const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int htlockepfl_cond_timedwait(htlockepfl_cond_t *cond, htlockepfl_mutex_t *lock,
                              htlockepfl_context_t *me,
                              const struct timespec *ts) {
#if COND_VAR
    int res;

    __htlockepfl_mutex_unlock(lock, me);
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

    htlockepfl_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int htlockepfl_cond_wait(htlockepfl_cond_t *cond, htlockepfl_mutex_t *lock,
                         htlockepfl_context_t *me) {
    return htlockepfl_cond_timedwait(cond, lock, me, 0);
}

int htlockepfl_cond_signal(htlockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int htlockepfl_cond_broadcast(htlockepfl_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int htlockepfl_cond_destroy(htlockepfl_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void htlockepfl_thread_start(void) {
}

void htlockepfl_thread_exit(void) {
}

void htlockepfl_application_init(void) {
}

void htlockepfl_application_exit(void) {
}

void htlockepfl_init_context(lock_mutex_t *UNUSED(impl),
                             lock_context_t *UNUSED(context),
                             int UNUSED(number)) {
}
