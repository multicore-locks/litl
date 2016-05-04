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
 */
#ifndef __CLHEPFL_H__
#define __CLHEPFL_H__

#include "padding.h"
#define LOCK_ALGORITHM "CLHEPFL"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 1

// CLHEPFL using standard interface from M.L.Scott

typedef struct clhepfl_node {
    volatile int spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(int))];
} clhepfl_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct clhepfl_mutex {
    clhepfl_node_t dummy __attribute__((aligned(L_CACHE_LINE_SIZE)));
    // clhepfl_node_t is cache aligned
    clhepfl_node_t *volatile head;
    clhepfl_node_t *volatile tail;
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(clhepfl_node_t *) +
                                 sizeof(clhepfl_node_t *) +
                                 sizeof(pthread_mutex_t))];
#else
    char __pad[pad_to_cache_line(sizeof(clhepfl_node_t *) +
                                 sizeof(clhepfl_node_t *))];
#endif
} clhepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct clhepfl_context {
    clhepfl_node_t initial;
    clhepfl_node_t *volatile current
        __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(clhepfl_node_t) +
                                 sizeof(clhepfl_node_t *))];
} clhepfl_context_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t clhepfl_cond_t;

clhepfl_mutex_t *clhepfl_mutex_create(const pthread_mutexattr_t *attr);
int clhepfl_mutex_lock(clhepfl_mutex_t *impl, clhepfl_context_t *me);
int clhepfl_mutex_trylock(clhepfl_mutex_t *impl, clhepfl_context_t *me);
void clhepfl_mutex_unlock(clhepfl_mutex_t *impl, clhepfl_context_t *me);
int clhepfl_mutex_destroy(clhepfl_mutex_t *lock);
int clhepfl_cond_init(clhepfl_cond_t *cond, const pthread_condattr_t *attr);
int clhepfl_cond_timedwait(clhepfl_cond_t *cond, clhepfl_mutex_t *lock,
                           clhepfl_context_t *me, const struct timespec *ts);
int clhepfl_cond_wait(clhepfl_cond_t *cond, clhepfl_mutex_t *lock,
                      clhepfl_context_t *me);
int clhepfl_cond_signal(clhepfl_cond_t *cond);
int clhepfl_cond_broadcast(clhepfl_cond_t *cond);
int clhepfl_cond_destroy(clhepfl_cond_t *cond);
void clhepfl_thread_start(void);
void clhepfl_thread_exit(void);
void clhepfl_application_init(void);
void clhepfl_application_exit(void);
void clhepfl_init_context(clhepfl_mutex_t *impl, clhepfl_context_t *context,
                          int number);

typedef clhepfl_mutex_t lock_mutex_t;
typedef clhepfl_context_t lock_context_t;
typedef clhepfl_cond_t lock_cond_t;

#define lock_mutex_create clhepfl_mutex_create
#define lock_mutex_lock clhepfl_mutex_lock
#define lock_mutex_trylock clhepfl_mutex_trylock
#define lock_mutex_unlock clhepfl_mutex_unlock
#define lock_mutex_destroy clhepfl_mutex_destroy
#define lock_cond_init clhepfl_cond_init
#define lock_cond_timedwait clhepfl_cond_timedwait
#define lock_cond_wait clhepfl_cond_wait
#define lock_cond_signal clhepfl_cond_signal
#define lock_cond_broadcast clhepfl_cond_broadcast
#define lock_cond_destroy clhepfl_cond_destroy
#define lock_thread_start clhepfl_thread_start
#define lock_thread_exit clhepfl_thread_exit
#define lock_application_init clhepfl_application_init
#define lock_application_exit clhepfl_application_exit
#define lock_init_context clhepfl_init_context

#endif // __CLHEPFL_H__
