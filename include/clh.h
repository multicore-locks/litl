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
#ifndef __CLH_H__
#define __CLH_H__

#include "padding.h"
#define LOCK_ALGORITHM "CLH"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 1

// CLH variant with standard interface from M.L.Scott

typedef struct clh_node {
    volatile int spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(int))];
} clh_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct clh_mutex {
    clh_node_t dummy __attribute__((aligned(L_CACHE_LINE_SIZE)));
    // clh_node_t is cache aligned
    clh_node_t *volatile head;
    clh_node_t *volatile tail;
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(clh_node_t *) + sizeof(clh_node_t *) +
                                 sizeof(pthread_mutex_t))];
#else
    char __pad[pad_to_cache_line(sizeof(clh_node_t *) + sizeof(clh_node_t *))];
#endif
} clh_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct clh_context {
    clh_node_t initial;
    clh_node_t *volatile current __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(clh_node_t) + sizeof(clh_node_t *))];
} clh_context_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t clh_cond_t;

clh_mutex_t *clh_mutex_create(const pthread_mutexattr_t *attr);
int clh_mutex_lock(clh_mutex_t *impl, clh_context_t *me);
int clh_mutex_trylock(clh_mutex_t *impl, clh_context_t *me);
void clh_mutex_unlock(clh_mutex_t *impl, clh_context_t *me);
int clh_mutex_destroy(clh_mutex_t *lock);
int clh_cond_init(clh_cond_t *cond, const pthread_condattr_t *attr);
int clh_cond_timedwait(clh_cond_t *cond, clh_mutex_t *lock, clh_context_t *me,
                       const struct timespec *ts);
int clh_cond_wait(clh_cond_t *cond, clh_mutex_t *lock, clh_context_t *me);
int clh_cond_signal(clh_cond_t *cond);
int clh_cond_broadcast(clh_cond_t *cond);
int clh_cond_destroy(clh_cond_t *cond);
void clh_thread_start(void);
void clh_thread_exit(void);
void clh_application_init(void);
void clh_application_exit(void);
void clh_init_context(clh_mutex_t *impl, clh_context_t *context, int number);

typedef clh_mutex_t lock_mutex_t;
typedef clh_context_t lock_context_t;
typedef clh_cond_t lock_cond_t;

#define lock_mutex_create clh_mutex_create
#define lock_mutex_lock clh_mutex_lock
#define lock_mutex_trylock clh_mutex_trylock
#define lock_mutex_unlock clh_mutex_unlock
#define lock_mutex_destroy clh_mutex_destroy
#define lock_cond_init clh_cond_init
#define lock_cond_timedwait clh_cond_timedwait
#define lock_cond_wait clh_cond_wait
#define lock_cond_signal clh_cond_signal
#define lock_cond_broadcast clh_cond_broadcast
#define lock_cond_destroy clh_cond_destroy
#define lock_thread_start clh_thread_start
#define lock_thread_exit clh_thread_exit
#define lock_application_init clh_application_init
#define lock_application_exit clh_application_exit
#define lock_init_context clh_init_context

#endif // __CLH_H__
