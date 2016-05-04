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
#ifndef __BACKOFF_H__
#define __BACKOFF_H__

#include <stdint.h>
#include "padding.h"
#define LOCK_ALGORITHM "BACKOFF"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

// The constants are taken from concurrencykit
// The unit is one iteration of a loop with a CPU_PAUSE inside
#define DEFAULT_BACKOFF_DELAY (1 << 9)
#define MAX_BACKOFF_DELAY ((1 << 20) - 1)

// The lock is a memory address where all threads spinloop
typedef struct backoff_mutex {
    volatile uint8_t spin_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint8_t))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} backoff_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t backoff_cond_t;
typedef void *backoff_context_t; // Unused, take the less space as possible

backoff_mutex_t *backoff_mutex_create(const pthread_mutexattr_t *attr);
int backoff_mutex_lock(backoff_mutex_t *impl, backoff_context_t *me);
int backoff_mutex_trylock(backoff_mutex_t *impl, backoff_context_t *me);
void backoff_mutex_unlock(backoff_mutex_t *impl, backoff_context_t *me);
int backoff_mutex_destroy(backoff_mutex_t *lock);
int backoff_cond_init(backoff_cond_t *cond, const pthread_condattr_t *attr);
int backoff_cond_timedwait(backoff_cond_t *cond, backoff_mutex_t *lock,
                           backoff_context_t *me, const struct timespec *ts);
int backoff_cond_wait(backoff_cond_t *cond, backoff_mutex_t *lock,
                      backoff_context_t *me);
int backoff_cond_signal(backoff_cond_t *cond);
int backoff_cond_broadcast(backoff_cond_t *cond);
int backoff_cond_destroy(backoff_cond_t *cond);
void backoff_thread_start(void);
void backoff_thread_exit(void);
void backoff_application_init(void);
void backoff_application_exit(void);

typedef backoff_mutex_t lock_mutex_t;
typedef backoff_context_t lock_context_t;
typedef backoff_cond_t lock_cond_t;

#define lock_mutex_create backoff_mutex_create
#define lock_mutex_lock backoff_mutex_lock
#define lock_mutex_trylock backoff_mutex_trylock
#define lock_mutex_unlock backoff_mutex_unlock
#define lock_mutex_destroy backoff_mutex_destroy
#define lock_cond_init backoff_cond_init
#define lock_cond_timedwait backoff_cond_timedwait
#define lock_cond_wait backoff_cond_wait
#define lock_cond_signal backoff_cond_signal
#define lock_cond_broadcast backoff_cond_broadcast
#define lock_cond_destroy backoff_cond_destroy
#define lock_thread_start backoff_thread_start
#define lock_thread_exit backoff_thread_exit
#define lock_application_init backoff_application_init
#define lock_application_exit backoff_application_exit
#define lock_init_context backoff_init_context

#endif // __BACKOFF_H__
