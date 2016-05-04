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
#ifndef __MCS_H__
#define __MCS_H__

#include "padding.h"
#define LOCK_ALGORITHM "MCS"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 1

typedef struct mcs_node {
    struct mcs_node *volatile next;
    char __pad[pad_to_cache_line(sizeof(struct mcs_node *))];
    volatile int spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
} mcs_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct mcs_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    struct mcs_node *volatile tail __attribute__((aligned(L_CACHE_LINE_SIZE)));
} mcs_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t mcs_cond_t;
mcs_mutex_t *mcs_mutex_create(const pthread_mutexattr_t *attr);
int mcs_mutex_lock(mcs_mutex_t *impl, mcs_node_t *me);
int mcs_mutex_trylock(mcs_mutex_t *impl, mcs_node_t *me);
void mcs_mutex_unlock(mcs_mutex_t *impl, mcs_node_t *me);
int mcs_mutex_destroy(mcs_mutex_t *lock);
int mcs_cond_init(mcs_cond_t *cond, const pthread_condattr_t *attr);
int mcs_cond_timedwait(mcs_cond_t *cond, mcs_mutex_t *lock, mcs_node_t *me,
                       const struct timespec *ts);
int mcs_cond_wait(mcs_cond_t *cond, mcs_mutex_t *lock, mcs_node_t *me);
int mcs_cond_signal(mcs_cond_t *cond);
int mcs_cond_broadcast(mcs_cond_t *cond);
int mcs_cond_destroy(mcs_cond_t *cond);
void mcs_thread_start(void);
void mcs_thread_exit(void);
void mcs_application_init(void);
void mcs_application_exit(void);
void mcs_init_context(mcs_mutex_t *impl, mcs_node_t *context, int number);

typedef mcs_mutex_t lock_mutex_t;
typedef mcs_node_t lock_context_t;
typedef mcs_cond_t lock_cond_t;

#define lock_mutex_create mcs_mutex_create
#define lock_mutex_lock mcs_mutex_lock
#define lock_mutex_trylock mcs_mutex_trylock
#define lock_mutex_unlock mcs_mutex_unlock
#define lock_mutex_destroy mcs_mutex_destroy
#define lock_cond_init mcs_cond_init
#define lock_cond_timedwait mcs_cond_timedwait
#define lock_cond_wait mcs_cond_wait
#define lock_cond_signal mcs_cond_signal
#define lock_cond_broadcast mcs_cond_broadcast
#define lock_cond_destroy mcs_cond_destroy
#define lock_thread_start mcs_thread_start
#define lock_thread_exit mcs_thread_exit
#define lock_application_init mcs_application_init
#define lock_application_exit mcs_application_exit
#define lock_init_context mcs_init_context

#endif // __MCS_H__
