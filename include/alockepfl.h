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
#ifndef __ALOCKEPFL_H__
#define __ALOCKEPFL_H__

#include "padding.h"
#define LOCK_ALGORITHM "ALOCKEPFL"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

// Power of 2 must give better results due to modulo transformed to bitwise-mask
// Note: this directly impact memory consumption
#define MAX_THREADS_SUPPORTED 512

// Each thread needs to remember its index (used while unlocking)
typedef struct alockepfl_context {
    uint32_t my_index __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
} alockepfl_context_t;

// This is the memory address on which the thread spin
typedef struct alockepfl_flag_line {
    volatile uint16_t flag __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(uint16_t))];
} alockepfl_flag_line_t;

// Tail is the counter (how much thread has waited the lock so far)
typedef struct alockepfl_mutex {
    volatile uint32_t tail;
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
    alockepfl_flag_line_t flags[MAX_THREADS_SUPPORTED];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} alockepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t alockepfl_cond_t;

alockepfl_mutex_t *alockepfl_mutex_create(const pthread_mutexattr_t *attr);
int alockepfl_mutex_lock(alockepfl_mutex_t *impl, alockepfl_context_t *me);
int alockepfl_mutex_trylock(alockepfl_mutex_t *impl, alockepfl_context_t *me);
void alockepfl_mutex_unlock(alockepfl_mutex_t *impl, alockepfl_context_t *me);
int alockepfl_mutex_destroy(alockepfl_mutex_t *lock);
int alockepfl_cond_init(alockepfl_cond_t *cond, const pthread_condattr_t *attr);
int alockepfl_cond_timedwait(alockepfl_cond_t *cond, alockepfl_mutex_t *lock,
                             alockepfl_context_t *me,
                             const struct timespec *ts);
int alockepfl_cond_wait(alockepfl_cond_t *cond, alockepfl_mutex_t *lock,
                        alockepfl_context_t *me);
int alockepfl_cond_signal(alockepfl_cond_t *cond);
int alockepfl_cond_broadcast(alockepfl_cond_t *cond);
int alockepfl_cond_destroy(alockepfl_cond_t *cond);
void alockepfl_thread_start(void);
void alockepfl_thread_exit(void);
void alockepfl_application_init(void);
void alockepfl_application_exit(void);
void alockepfl_init_context(alockepfl_mutex_t *impl,
                            alockepfl_context_t *context, int number);

typedef alockepfl_mutex_t lock_mutex_t;
typedef alockepfl_context_t lock_context_t;
typedef alockepfl_cond_t lock_cond_t;

#define lock_mutex_create alockepfl_mutex_create
#define lock_mutex_lock alockepfl_mutex_lock
#define lock_mutex_trylock alockepfl_mutex_trylock
#define lock_mutex_unlock alockepfl_mutex_unlock
#define lock_mutex_destroy alockepfl_mutex_destroy
#define lock_cond_init alockepfl_cond_init
#define lock_cond_timedwait alockepfl_cond_timedwait
#define lock_cond_wait alockepfl_cond_wait
#define lock_cond_signal alockepfl_cond_signal
#define lock_cond_broadcast alockepfl_cond_broadcast
#define lock_cond_destroy alockepfl_cond_destroy
#define lock_thread_start alockepfl_thread_start
#define lock_thread_exit alockepfl_thread_exit
#define lock_application_init alockepfl_application_init
#define lock_application_exit alockepfl_application_exit
#define lock_init_context alockepfl_init_context

#endif // __ALOCKEPFL_H__
