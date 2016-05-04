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
#ifndef __MCSEPFL_H__
#define __MCSEPFL_H__

#include "padding.h"
#define LOCK_ALGORITHM "MCSEPFL"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

typedef struct mcsepfl_node {
    volatile uint8_t spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
    volatile struct mcsepfl_node *volatile next;
    char __pad[pad_to_cache_line(sizeof(struct mcsepfl_node *) +
                                 sizeof(uint8_t))];
} mcsepfl_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct mcsepfl_mutex {
    struct mcsepfl_node *volatile tail
        __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(struct mcsepfl_node *))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} mcsepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t mcsepfl_cond_t;
mcsepfl_mutex_t *mcsepfl_mutex_create(const pthread_mutexattr_t *attr);
int mcsepfl_mutex_lock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me);
int mcsepfl_mutex_trylock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me);
void mcsepfl_mutex_unlock(mcsepfl_mutex_t *impl, mcsepfl_node_t *me);
int mcsepfl_mutex_destroy(mcsepfl_mutex_t *lock);
int mcsepfl_cond_init(mcsepfl_cond_t *cond, const pthread_condattr_t *attr);
int mcsepfl_cond_timedwait(mcsepfl_cond_t *cond, mcsepfl_mutex_t *lock,
                           mcsepfl_node_t *me, const struct timespec *ts);
int mcsepfl_cond_wait(mcsepfl_cond_t *cond, mcsepfl_mutex_t *lock,
                      mcsepfl_node_t *me);
int mcsepfl_cond_signal(mcsepfl_cond_t *cond);
int mcsepfl_cond_broadcast(mcsepfl_cond_t *cond);
int mcsepfl_cond_destroy(mcsepfl_cond_t *cond);
void mcsepfl_thread_start(void);
void mcsepfl_thread_exit(void);
void mcsepfl_application_init(void);
void mcsepfl_application_exit(void);
void mcsepfl_init_context(mcsepfl_mutex_t *impl, mcsepfl_node_t *context,
                          int number);

typedef mcsepfl_mutex_t lock_mutex_t;
typedef mcsepfl_node_t lock_context_t;
typedef mcsepfl_cond_t lock_cond_t;

#define lock_mutex_create mcsepfl_mutex_create
#define lock_mutex_lock mcsepfl_mutex_lock
#define lock_mutex_trylock mcsepfl_mutex_trylock
#define lock_mutex_unlock mcsepfl_mutex_unlock
#define lock_mutex_destroy mcsepfl_mutex_destroy
#define lock_cond_init mcsepfl_cond_init
#define lock_cond_timedwait mcsepfl_cond_timedwait
#define lock_cond_wait mcsepfl_cond_wait
#define lock_cond_signal mcsepfl_cond_signal
#define lock_cond_broadcast mcsepfl_cond_broadcast
#define lock_cond_destroy mcsepfl_cond_destroy
#define lock_thread_start mcsepfl_thread_start
#define lock_thread_exit mcsepfl_thread_exit
#define lock_application_init mcsepfl_application_init
#define lock_application_exit mcsepfl_application_exit
#define lock_init_context mcsepfl_init_context

#endif // __MCSEPFL_H__
