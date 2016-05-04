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
#ifndef __SPINLOCKEPFL_H__
#define __SPINLOCKEPFL_H__

#include "padding.h"
#define LOCK_ALGORITHM "SPINLOCKEPFL"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

typedef struct spinlockepfl_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    volatile uint8_t spin_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));
} spinlockepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t spinlockepfl_cond_t;
typedef void *spinlockepfl_context_t; // Unused, take the less space as possible

spinlockepfl_mutex_t *
spinlockepfl_mutex_create(const pthread_mutexattr_t *attr);
int spinlockepfl_mutex_lock(spinlockepfl_mutex_t *impl,
                            spinlockepfl_context_t *me);
int spinlockepfl_mutex_trylock(spinlockepfl_mutex_t *impl,
                               spinlockepfl_context_t *me);
void spinlockepfl_mutex_unlock(spinlockepfl_mutex_t *impl,
                               spinlockepfl_context_t *me);
int spinlockepfl_mutex_destroy(spinlockepfl_mutex_t *lock);
int spinlockepfl_cond_init(spinlockepfl_cond_t *cond,
                           const pthread_condattr_t *attr);
int spinlockepfl_cond_timedwait(spinlockepfl_cond_t *cond,
                                spinlockepfl_mutex_t *lock,
                                spinlockepfl_context_t *me,
                                const struct timespec *ts);
int spinlockepfl_cond_wait(spinlockepfl_cond_t *cond,
                           spinlockepfl_mutex_t *lock,
                           spinlockepfl_context_t *me);
int spinlockepfl_cond_signal(spinlockepfl_cond_t *cond);
int spinlockepfl_cond_broadcast(spinlockepfl_cond_t *cond);
int spinlockepfl_cond_destroy(spinlockepfl_cond_t *cond);
void spinlockepfl_thread_start(void);
void spinlockepfl_thread_exit(void);
void spinlockepfl_application_init(void);
void spinlockepfl_application_exit(void);

typedef spinlockepfl_mutex_t lock_mutex_t;
typedef spinlockepfl_context_t lock_context_t;
typedef spinlockepfl_cond_t lock_cond_t;

#define lock_mutex_create spinlockepfl_mutex_create
#define lock_mutex_lock spinlockepfl_mutex_lock
#define lock_mutex_trylock spinlockepfl_mutex_trylock
#define lock_mutex_unlock spinlockepfl_mutex_unlock
#define lock_mutex_destroy spinlockepfl_mutex_destroy
#define lock_cond_init spinlockepfl_cond_init
#define lock_cond_timedwait spinlockepfl_cond_timedwait
#define lock_cond_wait spinlockepfl_cond_wait
#define lock_cond_signal spinlockepfl_cond_signal
#define lock_cond_broadcast spinlockepfl_cond_broadcast
#define lock_cond_destroy spinlockepfl_cond_destroy
#define lock_thread_start spinlockepfl_thread_start
#define lock_thread_exit spinlockepfl_thread_exit
#define lock_application_init spinlockepfl_application_init
#define lock_application_exit spinlockepfl_application_exit
#define lock_init_context spinlockepfl_init_context

#endif // __SPINLOCKEPFL_H__
