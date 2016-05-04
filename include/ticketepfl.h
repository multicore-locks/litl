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
#ifndef __TICKETEPFL_H__
#define __TICKETEPFL_H__

#include "padding.h"
#define LOCK_ALGORITHM "TICKETEPFL"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

// Constants for the ticket backoff
#define TICKET_BASE_WAIT 512
#define TICKET_MAX_WAIT 4095
#define TICKET_WAIT_NEXT 128

// Use union for compare and swap
typedef union __ticketepfl_lock {
    volatile uint64_t u;
    struct {
        volatile uint32_t grant;
        volatile uint32_t request;
    } s;
} ticketepfl_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct ticketepfl_mutex {
    ticketepfl_lock_t u __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(ticketepfl_lock_t))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} ticketepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t ticketepfl_cond_t;
typedef void *ticketepfl_context_t; // Unused, take the less space as possible

ticketepfl_mutex_t *ticketepfl_mutex_create(const pthread_mutexattr_t *attr);
int ticketepfl_mutex_lock(ticketepfl_mutex_t *impl, ticketepfl_context_t *me);
int ticketepfl_mutex_trylock(ticketepfl_mutex_t *impl,
                             ticketepfl_context_t *me);
void ticketepfl_mutex_unlock(ticketepfl_mutex_t *impl,
                             ticketepfl_context_t *me);
int ticketepfl_mutex_destroy(ticketepfl_mutex_t *lock);
int ticketepfl_cond_init(ticketepfl_cond_t *cond,
                         const pthread_condattr_t *attr);
int ticketepfl_cond_timedwait(ticketepfl_cond_t *cond, ticketepfl_mutex_t *lock,
                              ticketepfl_context_t *me,
                              const struct timespec *ts);
int ticketepfl_cond_wait(ticketepfl_cond_t *cond, ticketepfl_mutex_t *lock,
                         ticketepfl_context_t *me);
int ticketepfl_cond_signal(ticketepfl_cond_t *cond);
int ticketepfl_cond_broadcast(ticketepfl_cond_t *cond);
int ticketepfl_cond_destroy(ticketepfl_cond_t *cond);
void ticketepfl_thread_start(void);
void ticketepfl_thread_exit(void);
void ticketepfl_application_init(void);
void ticketepfl_application_exit(void);

typedef ticketepfl_mutex_t lock_mutex_t;
typedef ticketepfl_context_t lock_context_t;
typedef ticketepfl_cond_t lock_cond_t;

#define lock_mutex_create ticketepfl_mutex_create
#define lock_mutex_lock ticketepfl_mutex_lock
#define lock_mutex_trylock ticketepfl_mutex_trylock
#define lock_mutex_unlock ticketepfl_mutex_unlock
#define lock_mutex_destroy ticketepfl_mutex_destroy
#define lock_cond_init ticketepfl_cond_init
#define lock_cond_timedwait ticketepfl_cond_timedwait
#define lock_cond_wait ticketepfl_cond_wait
#define lock_cond_signal ticketepfl_cond_signal
#define lock_cond_broadcast ticketepfl_cond_broadcast
#define lock_cond_destroy ticketepfl_cond_destroy
#define lock_thread_start ticketepfl_thread_start
#define lock_thread_exit ticketepfl_thread_exit
#define lock_application_init ticketepfl_application_init
#define lock_application_exit ticketepfl_application_exit
#define lock_init_context ticketepfl_init_context

#endif // __TICKETEPFL_H__
