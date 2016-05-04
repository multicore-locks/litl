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
#ifndef __HTLOCKEPFL_H__
#define __HTLOCKEPFL_H__

#include <stdint.h>
#include <topology.h>

#include "padding.h"
#define LOCK_ALGORITHM "HTLOCK_EPFL"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

// This is the number of times a local lock while be taken without releasing the
// global lock
// Constant value from libslock
#define NB_TICKETS_LOCAL 128

// Constants for the ticket backoff
#define TICKET_BASE_WAIT 512
#define TICKET_MAX_WAIT 4095
#define TICKET_WAIT_NEXT 64

// Use union for compare and swap
typedef struct {
    union {
        volatile uint64_t u;
        struct {
            volatile uint32_t grant;
            volatile uint32_t request;
        } s;
    } u;

    char __pad[pad_to_cache_line(sizeof(uint64_t))];
} ticket_lock_local_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct {
    union {
        volatile uint64_t u;
        struct {
            volatile int32_t grant;
            volatile int32_t request;
        } s;
    } u;
    char __pad[pad_to_cache_line(sizeof(uint64_t))];
} ticket_lock_global_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct htlock {
    ticket_lock_global_t global;
    ticket_lock_local_t local[NUMA_NODES];
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
} htlockepfl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct htlock_context {
    uint8_t last_numa_node;
    char __pad[pad_to_cache_line(sizeof(uint8_t))];
} htlockepfl_context_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t htlockepfl_cond_t;

htlockepfl_mutex_t *htlockepfl_mutex_create(const pthread_mutexattr_t *attr);
int htlockepfl_mutex_lock(htlockepfl_mutex_t *impl, htlockepfl_context_t *me);
int htlockepfl_mutex_trylock(htlockepfl_mutex_t *impl,
                             htlockepfl_context_t *me);
void htlockepfl_mutex_unlock(htlockepfl_mutex_t *impl,
                             htlockepfl_context_t *me);
int htlockepfl_mutex_destroy(htlockepfl_mutex_t *lock);
int htlockepfl_cond_init(htlockepfl_cond_t *cond,
                         const pthread_condattr_t *attr);
int htlockepfl_cond_timedwait(htlockepfl_cond_t *cond, htlockepfl_mutex_t *lock,
                              htlockepfl_context_t *me,
                              const struct timespec *ts);
int htlockepfl_cond_wait(htlockepfl_cond_t *cond, htlockepfl_mutex_t *lock,
                         htlockepfl_context_t *me);
int htlockepfl_cond_signal(htlockepfl_cond_t *cond);
int htlockepfl_cond_broadcast(htlockepfl_cond_t *cond);
int htlockepfl_cond_destroy(htlockepfl_cond_t *cond);
void htlockepfl_thread_start(void);
void htlockepfl_thread_exit(void);
void htlockepfl_application_init(void);
void htlockepfl_application_exit(void);
void htlockepfl_init_context(htlockepfl_mutex_t *impl,
                             htlockepfl_context_t *context, int number);

typedef htlockepfl_mutex_t lock_mutex_t;
typedef htlockepfl_context_t lock_context_t;
typedef htlockepfl_cond_t lock_cond_t;

#define lock_mutex_create htlockepfl_mutex_create
#define lock_mutex_lock htlockepfl_mutex_lock
#define lock_mutex_trylock htlockepfl_mutex_trylock
#define lock_mutex_unlock htlockepfl_mutex_unlock
#define lock_mutex_destroy htlockepfl_mutex_destroy
#define lock_cond_init htlockepfl_cond_init
#define lock_cond_timedwait htlockepfl_cond_timedwait
#define lock_cond_wait htlockepfl_cond_wait
#define lock_cond_signal htlockepfl_cond_signal
#define lock_cond_broadcast htlockepfl_cond_broadcast
#define lock_cond_destroy htlockepfl_cond_destroy
#define lock_thread_start htlockepfl_thread_start
#define lock_thread_exit htlockepfl_thread_exit
#define lock_application_init htlockepfl_application_init
#define lock_application_exit htlockepfl_application_exit
#define lock_init_context htlockepfl_init_context

#endif // __HTLOCKEPFL_H__
