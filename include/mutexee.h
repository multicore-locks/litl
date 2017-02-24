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
#ifndef __MUTEXEE_H__
#define __MUTEXEE_H__

#include "padding.h"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

#include "mutexee_in.h"
#define LOCK_ALGORITHM LOCK_IN_NAME


typedef struct mutexee_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    mutexee_lock_t lock; // The structure is already cache aligned
} mutexee_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t mutexee_cond_t;
typedef void *mutexee_context_t; // Unused, take the less space as possible

mutexee_mutex_t *mutexee_mutex_create(const pthread_mutexattr_t *attr);
int mutexee_mutex_lock(mutexee_mutex_t *impl, mutexee_context_t *me);
int mutexee_mutex_trylock(mutexee_mutex_t *impl, mutexee_context_t *me);
void mutexee_mutex_unlock(mutexee_mutex_t *impl, mutexee_context_t *me);
int mutexee_mutex_destroy(mutexee_mutex_t *lock);
int mutexee_cond_init(mutexee_cond_t *cond, const pthread_condattr_t *attr);
int mutexee_cond_timedwait(mutexee_cond_t *cond, mutexee_mutex_t *lock,
                            mutexee_context_t *me, const struct timespec *ts);
int mutexee_cond_wait(mutexee_cond_t *cond, mutexee_mutex_t *lock,
                       mutexee_context_t *me);
int mutexee_cond_signal(mutexee_cond_t *cond);
int mutexee_cond_broadcast(mutexee_cond_t *cond);
int mutexee_cond_destroy(mutexee_cond_t *cond);
void mutexee_thread_start(void);
void mutexee_thread_exit(void);
void mutexee_application_init(void);
void mutexee_application_exit(void);

typedef mutexee_mutex_t lock_mutex_t;
typedef mutexee_context_t lock_context_t;
typedef mutexee_cond_t lock_cond_t;

#define lock_mutex_create mutexee_mutex_create
#define lock_mutex_lock mutexee_mutex_lock
#define lock_mutex_trylock mutexee_mutex_trylock
#define lock_mutex_unlock mutexee_mutex_unlock
#define lock_mutex_destroy mutexee_mutex_destroy
#define lock_cond_init mutexee_cond_init
#define lock_cond_timedwait mutexee_cond_timedwait
#define lock_cond_wait mutexee_cond_wait
#define lock_cond_signal mutexee_cond_signal
#define lock_cond_broadcast mutexee_cond_broadcast
#define lock_cond_destroy mutexee_cond_destroy
#define lock_thread_start mutexee_thread_start
#define lock_thread_exit mutexee_thread_exit
#define lock_application_init mutexee_application_init
#define lock_application_exit mutexee_application_exit
#define lock_init_context mutexee_init_context

#endif // __MUTEXEE_H__
