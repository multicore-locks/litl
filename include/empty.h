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
#ifndef __EMPTY_H__
#define __EMPTY_H__

#include "padding.h"
#define LOCK_ALGORITHM "EMPTY"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 1
#define NO_INDIRECTION 1

typedef pthread_mutex_t empty_mutex_t;
typedef pthread_cond_t empty_cond_t;
typedef void *empty_context_t;

empty_mutex_t *empty_mutex_create(const pthread_mutexattr_t *attr);
int empty_mutex_lock(empty_mutex_t *impl, empty_context_t *me);
int empty_mutex_trylock(empty_mutex_t *impl, empty_context_t *me);
void empty_mutex_unlock(empty_mutex_t *impl, empty_context_t *me);
int empty_mutex_destroy(empty_mutex_t *lock);
int empty_cond_init(empty_cond_t *cond, const pthread_condattr_t *attr);
int empty_cond_timedwait(empty_cond_t *cond, empty_mutex_t *lock,
                         empty_context_t *me, const struct timespec *ts);
int empty_cond_wait(empty_cond_t *cond, empty_mutex_t *lock,
                    empty_context_t *me);
int empty_cond_signal(empty_cond_t *cond);
int empty_cond_broadcast(empty_cond_t *cond);
int empty_cond_destroy(empty_cond_t *cond);
void empty_thread_start(void);
void empty_thread_exit(void);
void empty_application_init(void);
void empty_application_exit(void);

typedef empty_mutex_t lock_mutex_t;
typedef empty_context_t lock_context_t;
typedef empty_cond_t lock_cond_t;

#define lock_mutex_create empty_mutex_create
#define lock_mutex_lock empty_mutex_lock
#define lock_mutex_trylock empty_mutex_trylock
#define lock_mutex_unlock empty_mutex_unlock
#define lock_mutex_destroy empty_mutex_destroy
#define lock_cond_init empty_cond_init
#define lock_cond_timedwait empty_cond_timedwait
#define lock_cond_wait empty_cond_wait
#define lock_cond_signal empty_cond_signal
#define lock_cond_broadcast empty_cond_broadcast
#define lock_cond_destroy empty_cond_destroy
#define lock_thread_start empty_thread_start
#define lock_thread_exit empty_thread_exit
#define lock_application_init empty_application_init
#define lock_application_exit empty_application_exit
#define lock_init_context empty_init_context

#endif // __EMPTY_H__
