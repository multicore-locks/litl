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
#ifndef __TTASEPFL_H__
#define __TTASEPFL_H__

#include <stdint.h>
#include "padding.h"
#define LOCK_ALGORITHM "TTASEPFL"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

// Max delay for the backoff
#define MAX_DELAY 1000

typedef struct ttasepfl_mutex {
    volatile uint8_t spin_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint8_t))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} ttasepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct ttasepfl_context {
    uint32_t limit __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
} ttasepfl_context_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t ttasepfl_cond_t;

ttasepfl_mutex_t *ttasepfl_mutex_create(const pthread_mutexattr_t *attr);
int ttasepfl_mutex_lock(ttasepfl_mutex_t *impl, ttasepfl_context_t *me);
int ttasepfl_mutex_trylock(ttasepfl_mutex_t *impl, ttasepfl_context_t *me);
void ttasepfl_mutex_unlock(ttasepfl_mutex_t *impl, ttasepfl_context_t *me);
int ttasepfl_mutex_destroy(ttasepfl_mutex_t *lock);
int ttasepfl_cond_init(ttasepfl_cond_t *cond, const pthread_condattr_t *attr);
int ttasepfl_cond_timedwait(ttasepfl_cond_t *cond, ttasepfl_mutex_t *lock,
                            ttasepfl_context_t *me, const struct timespec *ts);
int ttasepfl_cond_wait(ttasepfl_cond_t *cond, ttasepfl_mutex_t *lock,
                       ttasepfl_context_t *me);
int ttasepfl_cond_signal(ttasepfl_cond_t *cond);
int ttasepfl_cond_broadcast(ttasepfl_cond_t *cond);
int ttasepfl_cond_destroy(ttasepfl_cond_t *cond);
void ttasepfl_thread_start(void);
void ttasepfl_thread_exit(void);
void ttasepfl_application_init(void);
void ttasepfl_application_exit(void);
void ttasepfl_init_context(ttasepfl_mutex_t *impl, ttasepfl_context_t *context,
                           int number);

typedef ttasepfl_mutex_t lock_mutex_t;
typedef ttasepfl_context_t lock_context_t;
typedef ttasepfl_cond_t lock_cond_t;

// Define library function ptr
#define lock_mutex_create ttasepfl_mutex_create
#define lock_mutex_lock ttasepfl_mutex_lock
#define lock_mutex_trylock ttasepfl_mutex_trylock
#define lock_mutex_unlock ttasepfl_mutex_unlock
#define lock_mutex_destroy ttasepfl_mutex_destroy
#define lock_cond_init ttasepfl_cond_init
#define lock_cond_timedwait ttasepfl_cond_timedwait
#define lock_cond_wait ttasepfl_cond_wait
#define lock_cond_signal ttasepfl_cond_signal
#define lock_cond_broadcast ttasepfl_cond_broadcast
#define lock_cond_destroy ttasepfl_cond_destroy
#define lock_thread_start ttasepfl_thread_start
#define lock_thread_exit ttasepfl_thread_exit
#define lock_application_init ttasepfl_application_init
#define lock_application_exit ttasepfl_application_exit
#define lock_init_context ttasepfl_init_context

#endif // __TTASEPFL_H__
