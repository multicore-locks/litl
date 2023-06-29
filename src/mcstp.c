/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Hugo Guiroux <hugo.guiroux at gmail dot com>
 *               UPMC, 2010-2011, Jean-Pierre Lozi <jean-pierre.lozi@lip6.fr>
 *                                Gaël Thomas <gael.thomas@lip6.fr>
 *                                Florian David <florian.david@lip6.fr>
 *                                Julia Lawall <julia.lawall@lip6.fr>
 *                                Gilles Muller <gilles.muller@lip6.fr>
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
 * Bijun He, William N. Scherer, and Michael L. Scott. 2005.
 * Preemption adaptivity in time-published queue-based spin locks.
 * In Proceedings of the 12th international conference on High Performance
 * Computing (HiPC'05)
 *
 * Lock design summary:
 * This algorithm is a variant of MCS that aims at reducing the waiting times of
 * threads that request the lock when the lock holder thread T is preempted or
 * when its successor (i.e., the thread that will become the next lock holder)
 * is preempted.
 * Indeed, a thread A can overtake another thread B behind which it has been
 * waiting for a long time.
 * The waiting thread A will first yield its CPU (via sched_yield) in order to
 * create an opportunity for the preempted thread (lock holder or B) to make
 * progress.
 * If this is not enough, T will overtake the predecessor thread (B) by marking
 * the
 * latter as FAILED.
 * In this case, when B runs again, it will notice that it has been overtaken by
 * another thread and will restart a complete lock acquisition procedure.
 */
#define _GNU_SOURCE
#include <papi.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <mcstp.h>

#include "interpose.h"
#include "utils.h"

extern __thread unsigned int cur_thread_id;
typedef enum { INIT, AVAILABLE, WAITING, TIMED_OUT, FAILED } qnode_status;
#define GET_TIME()                                                             \
    ((long long)PAPI_get_real_cyc() / (FREQUENCY / MICROSEC_TO_SEC))

int mcs_tp_mutex_lock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me) {
#if COND_VAR
    DEBUG("[%d] MCS-TP lock=%p posix_lock=%p\n", cur_thread_id, impl,
          &(impl->posix_lock));
#endif

    while (mcs_tp_mutex_trylock(impl, me) == EBUSY)
        ;
#if COND_VAR
    DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id, &impl->posix_lock);

// The posix lock is already taken at the exit of mcs_tp_mutex_trylock
// assert(REAL(pthread_mutex_lock)(&impl->posix_lock) == 0);
#endif
    return 0;
}

int mcs_tp_mutex_trylock_oneshot(mcs_tp_mutex_t *impl, mcs_tp_node_t *me) {
    mcs_tp_node_t *pred = NULL;

    me->last_lock = impl;

    /* Try to reclaim position in queue */
    if (me->status != TIMED_OUT ||
        !__sync_bool_compare_and_swap(&me->status, TIMED_OUT, WAITING)) {
        me->status = WAITING;
        me->next   = 0;
        pred = __sync_val_compare_and_swap(&impl->tail, 0, me);
        if (!pred) { // lock was free
            impl->cs_start_time = GET_TIME();
            DEBUG("[%d] TryLocking lock=%p tail=%p me=%p\n", cur_thread_id,
                  impl, impl->tail, me);
#if COND_VAR
            DEBUG_PTHREAD("[%d] Lock posix=%p\n", cur_thread_id,
                          &impl->posix_lock);
            int ret = 0;
            while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) ==
                   EBUSY)
                ;
            assert(ret == 0);
#endif
            return 0;
        }
    }

    return EBUSY;
}

int mcs_tp_mutex_trylock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me) {
    mcs_tp_node_t *pred;
    long long start_time = GET_TIME();

#if COND_VAR
    DEBUG("[%d] MCS-TP trylock=%p posix_lock=%p\n", cur_thread_id, impl,
          &(impl->posix_lock));
#endif
    /* Try to reclaim position in queue */
    if (me->status != TIMED_OUT || me->last_lock != impl ||
        !__sync_bool_compare_and_swap(&me->status, TIMED_OUT, WAITING)) {
        me->status = WAITING;
        me->next   = 0;
        pred       = __sync_lock_test_and_set(&impl->tail, me);

        if (!pred) { // lock was free
            impl->cs_start_time = GET_TIME();
            goto success;
        } else
            pred->next = me;
    }

    for (;;) {
        if (me->status == AVAILABLE) {
            impl->cs_start_time = GET_TIME();
            goto success;
        } else if (me->status == FAILED) {
            if (GET_TIME() - impl->cs_start_time > MAX_CS_TIME)
                sched_yield();

            me->last_lock = impl;
            return EBUSY;
        }

        while (me->status == WAITING) {
            me->time = GET_TIME();

            if (GET_TIME() - start_time <= PATIENCE) {
                continue;
            }

            if (!__sync_bool_compare_and_swap(&me->status, WAITING,
                                              TIMED_OUT)) {
                //             me->last_lock = impl;
                break;
            }

            if (GET_TIME() - impl->cs_start_time > MAX_CS_TIME)
                sched_yield();

            me->last_lock = impl;
            return EBUSY;
        }
    }

success : {
#if COND_VAR
    int ret = 0;
    while ((ret = REAL(pthread_mutex_trylock)(&impl->posix_lock)) == EBUSY)
        ;
    assert(ret == 0);
#endif
    return 0;
}
}

static void __mcs_tp_mutex_unlock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me) {
    int scanned_nodes          = 0;
    mcs_tp_node_t *succ, *curr = me, *last = NULL;

    for (;;) {
        succ = curr->next;

        if (!succ) {
            if (__sync_bool_compare_and_swap(&impl->tail, curr, 0)) {
                curr->status = FAILED;
                return; /* I was last in line. */
            }

            while (!succ)
                succ = curr->next;
        }

        if (++scanned_nodes < MAX_THREADS_MCS_TP)
            curr->status = FAILED;
        else if (!last)
            last = curr; /* Handle treadmill case. */

        if (succ->status == WAITING) {
            long long succ_time = succ->time;

            if ((GET_TIME() - succ_time <= UPDATE_DELAY) &&
                __sync_bool_compare_and_swap(&succ->status, WAITING,
                                             AVAILABLE)) {
                for (; last && last != curr; last = last->next)
                    last->status = FAILED;

                return;
            }
        }

        curr = succ;
    }
}

void mcs_tp_mutex_unlock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me) {
#if COND_VAR
    DEBUG_PTHREAD("[%d] Unlock posix=%p\n", cur_thread_id, &impl->posix_lock);
    assert(REAL(pthread_mutex_unlock)(&impl->posix_lock) == 0);
#endif
    __mcs_tp_mutex_unlock(impl, me);
}

mcs_tp_mutex_t *mcs_tp_mutex_create(const pthread_mutexattr_t *attr) {
    mcs_tp_mutex_t *impl =
        (mcs_tp_mutex_t *)alloc_cache_align(sizeof(mcs_tp_mutex_t));

    impl->tail          = 0;
    impl->cs_start_time = 0;
#if COND_VAR
    REAL(pthread_mutex_init)(&impl->posix_lock, /*&errattr */ attr);
    DEBUG("Mutex init lock=%p posix_lock=%p\n", impl, &impl->posix_lock);
#endif

    return impl;
}

int mcs_tp_mutex_destroy(mcs_tp_mutex_t *lock) {
#if COND_VAR
    REAL(pthread_mutex_destroy)(&lock->posix_lock);
#endif
    free(lock);
    lock = NULL;

    return 0;
}

int mcs_tp_cond_init(mcs_tp_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcs_tp_cond_timedwait(mcs_tp_cond_t *cond, mcs_tp_mutex_t *lock,
                          mcs_tp_node_t *me, const struct timespec *ts) {
#if COND_VAR
    int res;

    __mcs_tp_mutex_unlock(lock, me);
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

    mcs_tp_mutex_lock(lock, me);

    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcs_tp_cond_wait(mcs_tp_cond_t *cond, mcs_tp_mutex_t *lock,
                     mcs_tp_node_t *me) {
    return mcs_tp_cond_timedwait(cond, lock, me, 0);
}

int mcs_tp_cond_signal(mcs_tp_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcs_tp_cond_broadcast(mcs_tp_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int mcs_tp_cond_destroy(mcs_tp_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

void mcs_tp_application_init(void) {
    if (PAPI_is_initialized() == PAPI_NOT_INITED &&
        PAPI_library_init(PAPI_VER_CURRENT) < 0) {
        fprintf(stderr, "PAPI_library_init failed");
        exit(-1);
    }
}

void mcs_tp_thread_start(void) {
    if (PAPI_thread_init(pthread_self) != PAPI_OK) {
        fprintf(stderr, "PAPI_thread_init failed");
        exit(-1);
    }
}

void mcs_tp_thread_exit(void) {
}

void mcs_tp_application_exit(void) {
}

void mcs_tp_init_context(lock_mutex_t *UNUSED(impl),
                         lock_context_t *UNUSED(context), int UNUSED(number)) {
}
