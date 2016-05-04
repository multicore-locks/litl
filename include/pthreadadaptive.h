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
#ifndef __PTHREAD_ADAPTIVE_H__
#define __PTHREAD_ADAPTIVE_H__

#include "padding.h"
#define LOCK_ALGORITHM "PTHREAD_ADAPTIVE"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

typedef struct pthread_adative_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    pthread_mutex_t lock;
} pthread_adaptive_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t pthread_adaptive_cond_t;
typedef void *pthread_adaptive_context_t; // Unused, take the less space
                                          // as possible

pthread_adaptive_mutex_t *
pthread_adaptive_mutex_create(const pthread_mutexattr_t *attr);
int pthread_adaptive_mutex_lock(pthread_adaptive_mutex_t *impl,
                                pthread_adaptive_context_t *me);
int pthread_adaptive_mutex_trylock(pthread_adaptive_mutex_t *impl,
                                   pthread_adaptive_context_t *me);
void pthread_adaptive_mutex_unlock(pthread_adaptive_mutex_t *impl,
                                   pthread_adaptive_context_t *me);
int pthread_adaptive_mutex_destroy(pthread_adaptive_mutex_t *lock);
int pthread_adaptive_cond_init(pthread_adaptive_cond_t *cond,
                               const pthread_condattr_t *attr);
int pthread_adaptive_cond_timedwait(pthread_adaptive_cond_t *cond,
                                    pthread_adaptive_mutex_t *lock,
                                    pthread_adaptive_context_t *me,
                                    const struct timespec *ts);
int pthread_adaptive_cond_wait(pthread_adaptive_cond_t *cond,
                               pthread_adaptive_mutex_t *lock,
                               pthread_adaptive_context_t *me);
int pthread_adaptive_cond_signal(pthread_adaptive_cond_t *cond);
int pthread_adaptive_cond_broadcast(pthread_adaptive_cond_t *cond);
int pthread_adaptive_cond_destroy(pthread_adaptive_cond_t *cond);
void pthread_adaptive_thread_start(void);
void pthread_adaptive_thread_exit(void);
void pthread_adaptive_application_init(void);
void pthread_adaptive_application_exit(void);

typedef pthread_adaptive_mutex_t lock_mutex_t;
typedef pthread_adaptive_context_t lock_context_t;
typedef pthread_adaptive_cond_t lock_cond_t;

#define lock_mutex_create pthread_adaptive_mutex_create
#define lock_mutex_lock pthread_adaptive_mutex_lock
#define lock_mutex_trylock pthread_adaptive_mutex_trylock
#define lock_mutex_unlock pthread_adaptive_mutex_unlock
#define lock_mutex_destroy pthread_adaptive_mutex_destroy
#define lock_cond_init pthread_adaptive_cond_init
#define lock_cond_timedwait pthread_adaptive_cond_timedwait
#define lock_cond_wait pthread_adaptive_cond_wait
#define lock_cond_signal pthread_adaptive_cond_signal
#define lock_cond_broadcast pthread_adaptive_cond_broadcast
#define lock_cond_destroy pthread_adaptive_cond_destroy
#define lock_thread_start pthread_adaptive_thread_start
#define lock_thread_exit pthread_adaptive_thread_exit
#define lock_application_init pthread_adaptive_application_init
#define lock_application_exit pthread_adaptive_application_exit
#define lock_init_context pthread_adaptive_init_context

#endif // __PTHREAD_ADAPTIVE_H__
