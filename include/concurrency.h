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
#ifndef __CONCURRENCY_H__
#define __CONCURRENCY_H__

#include "padding.h"
#define LOCK_ALGORITHM "CONCURRENCY"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0
#define DESTROY_ON_EXIT 1
#define CLEANUP_ON_SIGNAL 1

typedef struct concurrency_node {
    uint64_t current;
    uint64_t max;
    uint64_t count;
    double mean;
    char __pad[pad_to_cache_line(sizeof(uint64_t) * 3 + sizeof(double))];
    pthread_mutex_t lock;
    char __pad2[pad_to_cache_line(sizeof(pthread_mutex_t))];
} concurrency_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t concurrency_cond_t;
typedef void *concurrency_context_t;

concurrency_mutex_t *concurrency_mutex_create(const pthread_mutexattr_t *attr);
int concurrency_mutex_lock(concurrency_mutex_t *impl,
                           concurrency_context_t *me);
int concurrency_mutex_trylock(concurrency_mutex_t *impl,
                              concurrency_context_t *me);
void concurrency_mutex_unlock(concurrency_mutex_t *impl,
                              concurrency_context_t *me);
int concurrency_mutex_destroy(concurrency_mutex_t *lock);
int concurrency_cond_init(concurrency_cond_t *cond,
                          const pthread_condattr_t *attr);
int concurrency_cond_timedwait(concurrency_cond_t *cond,
                               concurrency_mutex_t *lock,
                               concurrency_context_t *me,
                               const struct timespec *ts);
int concurrency_cond_wait(concurrency_cond_t *cond, concurrency_mutex_t *lock,
                          concurrency_context_t *me);
int concurrency_cond_signal(concurrency_cond_t *cond);
int concurrency_cond_broadcast(concurrency_cond_t *cond);
int concurrency_cond_destroy(concurrency_cond_t *cond);
void concurrency_thread_start(void);
void concurrency_thread_exit(void);
void concurrency_application_init(void);
void concurrency_application_exit(void);
void concurrency_init_context(concurrency_mutex_t *impl,
                              concurrency_context_t *context, int number);

typedef concurrency_mutex_t lock_mutex_t;
typedef concurrency_context_t lock_context_t;
typedef pthread_cond_t lock_cond_t;

#define lock_mutex_create concurrency_mutex_create
#define lock_mutex_lock concurrency_mutex_lock
#define lock_mutex_trylock concurrency_mutex_trylock
#define lock_mutex_unlock concurrency_mutex_unlock
#define lock_mutex_destroy concurrency_mutex_destroy
#define lock_cond_init concurrency_cond_init
#define lock_cond_timedwait concurrency_cond_timedwait
#define lock_cond_wait concurrency_cond_wait
#define lock_cond_signal concurrency_cond_signal
#define lock_cond_broadcast concurrency_cond_broadcast
#define lock_cond_destroy concurrency_cond_destroy
#define lock_thread_start concurrency_thread_start
#define lock_thread_exit concurrency_thread_exit
#define lock_application_init concurrency_application_init
#define lock_application_exit concurrency_application_exit
#define lock_init_context concurrency_init_context

#endif // __CONCURRENCY_H__
