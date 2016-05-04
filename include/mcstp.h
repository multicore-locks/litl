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
 */
#ifndef __MCS_TP_H__
#define __MCS_TP_H__

#include "padding.h"

// The constants are taken from RCL implementation
#define MAX_THREADS_MCS_TP 1000LL
#define MAX_CS_TIME 10000LL
#define UPDATE_DELAY 10LL
#define PATIENCE 50LL
#define LOCK_ALGORITHM "MCS-TP"
#define FREQUENCY 2600000000LL // 2.6GHz
#define MICROSEC_TO_SEC 1000000LL
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

struct mcs_tp_mutex;
typedef struct mcs_tp_node {
    volatile long long time;
    struct mcs_tp_mutex *volatile last_lock;
    struct mcs_tp_node *volatile next;
    char __pad[pad_to_cache_line(sizeof(long long) +
                                 sizeof(struct mcs_tp_mutex *) +
                                 sizeof(struct mcs_tp_node *))];
    volatile uint64_t status __attribute__((aligned(L_CACHE_LINE_SIZE)));
} mcs_tp_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct mcs_tp_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
    volatile long long cs_start_time;
#if COND_VAR
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t) + sizeof(long long))];
#else
    char __pad[pad_to_cache_line(sizeof(long long))];
#endif
    struct mcs_tp_node *volatile tail
        __attribute__((aligned(L_CACHE_LINE_SIZE)));
} mcs_tp_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t mcs_tp_cond_t;

mcs_tp_mutex_t *mcs_tp_mutex_create(const pthread_mutexattr_t *attr);
int mcs_tp_mutex_lock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me);
int mcs_tp_mutex_trylock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me);
int mcs_tp_mutex_trylock_oneshot(mcs_tp_mutex_t *impl, mcs_tp_node_t *me);
void mcs_tp_mutex_unlock(mcs_tp_mutex_t *impl, mcs_tp_node_t *me);
int mcs_tp_mutex_destroy(mcs_tp_mutex_t *lock);
int mcs_tp_cond_init(mcs_tp_cond_t *cond, const pthread_condattr_t *attr);
int mcs_tp_cond_timedwait(mcs_tp_cond_t *cond, mcs_tp_mutex_t *lock,
                          mcs_tp_node_t *me, const struct timespec *ts);
int mcs_tp_cond_wait(mcs_tp_cond_t *cond, mcs_tp_mutex_t *lock,
                     mcs_tp_node_t *me);
int mcs_tp_cond_signal(mcs_tp_cond_t *cond);
int mcs_tp_cond_broadcast(mcs_tp_cond_t *cond);
int mcs_tp_cond_destroy(mcs_tp_cond_t *cond);
void mcs_tp_thread_start(void);
void mcs_tp_thread_exit(void);
void mcs_tp_application_init(void);
void mcs_tp_application_exit(void);
void mcs_tp_init_context(mcs_tp_mutex_t *impl, mcs_tp_node_t *context,
                         int number);

typedef mcs_tp_mutex_t lock_mutex_t;
typedef mcs_tp_node_t lock_context_t;
typedef mcs_tp_cond_t lock_cond_t;

#define lock_mutex_create mcs_tp_mutex_create
#define lock_mutex_lock mcs_tp_mutex_lock
#define lock_mutex_trylock mcs_tp_mutex_trylock_oneshot
#define lock_mutex_unlock mcs_tp_mutex_unlock
#define lock_mutex_destroy mcs_tp_mutex_destroy
#define lock_cond_init mcs_tp_cond_init
#define lock_cond_timedwait mcs_tp_cond_timedwait
#define lock_cond_wait mcs_tp_cond_wait
#define lock_cond_signal mcs_tp_cond_signal
#define lock_cond_broadcast mcs_tp_cond_broadcast
#define lock_cond_destroy mcs_tp_cond_destroy
#define lock_thread_start mcs_tp_thread_start
#define lock_thread_exit mcs_tp_thread_exit
#define lock_application_init mcs_tp_application_init
#define lock_application_exit mcs_tp_application_exit
#define lock_init_context mcs_tp_init_context

#endif // __MCS_TP_H__
