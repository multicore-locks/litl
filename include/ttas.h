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
#ifndef __TTAS_H__
#define __TTAS_H__

#include <stdint.h>
#include "padding.h"
#define LOCK_ALGORITHM "TTAS"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

typedef struct ttas_mutex {
    volatile uint8_t spin_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint8_t))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} ttas_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t ttas_cond_t;
typedef void *ttas_context_t; // Unused, take the less space as possible

ttas_mutex_t *ttas_mutex_create(const pthread_mutexattr_t *attr);
int ttas_mutex_lock(ttas_mutex_t *impl, ttas_context_t *me);
int ttas_mutex_trylock(ttas_mutex_t *impl, ttas_context_t *me);
void ttas_mutex_unlock(ttas_mutex_t *impl, ttas_context_t *me);
int ttas_mutex_destroy(ttas_mutex_t *lock);
int ttas_cond_init(ttas_cond_t *cond, const pthread_condattr_t *attr);
int ttas_cond_timedwait(ttas_cond_t *cond, ttas_mutex_t *lock,
                        ttas_context_t *me, const struct timespec *ts);
int ttas_cond_wait(ttas_cond_t *cond, ttas_mutex_t *lock, ttas_context_t *me);
int ttas_cond_signal(ttas_cond_t *cond);
int ttas_cond_broadcast(ttas_cond_t *cond);
int ttas_cond_destroy(ttas_cond_t *cond);
void ttas_thread_start(void);
void ttas_thread_exit(void);
void ttas_application_init(void);
void ttas_application_exit(void);
void ttas_init_context(ttas_mutex_t *impl, ttas_context_t *context, int number);

typedef ttas_mutex_t lock_mutex_t;
typedef ttas_context_t lock_context_t;
typedef ttas_cond_t lock_cond_t;

// Define library function ptr
#define lock_mutex_create ttas_mutex_create
#define lock_mutex_lock ttas_mutex_lock
#define lock_mutex_trylock ttas_mutex_trylock
#define lock_mutex_unlock ttas_mutex_unlock
#define lock_mutex_destroy ttas_mutex_destroy
#define lock_cond_init ttas_cond_init
#define lock_cond_timedwait ttas_cond_timedwait
#define lock_cond_wait ttas_cond_wait
#define lock_cond_signal ttas_cond_signal
#define lock_cond_broadcast ttas_cond_broadcast
#define lock_cond_destroy ttas_cond_destroy
#define lock_thread_start ttas_thread_start
#define lock_thread_exit ttas_thread_exit
#define lock_application_init ttas_application_init
#define lock_application_exit ttas_application_exit
#define lock_init_context ttas_init_context

#endif // __TTAS_H__
