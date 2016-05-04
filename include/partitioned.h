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
#ifndef __PARTITIONED_H__
#define __PARTITIONED_H__

#include "padding.h"
#define LOCK_ALGORITHM "PARTITIONED"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

// Number of slots for the partitioned ticket locks
// Note from the paper: For performance, slots should be >= # of NUMA nodes
#define PTL_SLOTS NUMA_NODES

struct grant_slot {
    volatile uint32_t grant;
    char __pad[pad_to_cache_line(sizeof(uint32_t))];
} __attribute__((aligned(L_CACHE_LINE_SIZE)));

struct partitioned_ticket_lock {
    volatile uint32_t request;
    volatile uint32_t owner_ticket;
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(uint32_t))];
    // Each slot is cache align, the purpose of PLT is avoid cache line
    // transfers
    struct grant_slot grants[PTL_SLOTS];
} __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct ticket_mutex {
    struct partitioned_ticket_lock u
        __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(struct partitioned_ticket_lock))];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
} partitioned_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t partitioned_cond_t;
typedef void *partitioned_context_t; // Unused, take the less space as possible

partitioned_mutex_t *partitioned_mutex_create(const pthread_mutexattr_t *attr);
int partitioned_mutex_lock(partitioned_mutex_t *impl,
                           partitioned_context_t *me);
int partitioned_mutex_trylock(partitioned_mutex_t *impl,
                              partitioned_context_t *me);
void partitioned_mutex_unlock(partitioned_mutex_t *impl,
                              partitioned_context_t *me);
int partitioned_mutex_destroy(partitioned_mutex_t *lock);
int partitioned_cond_init(partitioned_cond_t *cond,
                          const pthread_condattr_t *attr);
int partitioned_cond_timedwait(partitioned_cond_t *cond,
                               partitioned_mutex_t *lock,
                               partitioned_context_t *me,
                               const struct timespec *ts);
int partitioned_cond_wait(partitioned_cond_t *cond, partitioned_mutex_t *lock,
                          partitioned_context_t *me);
int partitioned_cond_signal(partitioned_cond_t *cond);
int partitioned_cond_broadcast(partitioned_cond_t *cond);
int partitioned_cond_destroy(partitioned_cond_t *cond);
void partitioned_thread_start(void);
void partitioned_thread_exit(void);
void partitioned_application_init(void);
void partitioned_application_exit(void);

typedef partitioned_mutex_t lock_mutex_t;
typedef partitioned_context_t lock_context_t;
typedef partitioned_cond_t lock_cond_t;

// Define library function ptr
#define lock_mutex_create partitioned_mutex_create
#define lock_mutex_lock partitioned_mutex_lock
#define lock_mutex_trylock partitioned_mutex_trylock
#define lock_mutex_unlock partitioned_mutex_unlock
#define lock_mutex_destroy partitioned_mutex_destroy
#define lock_cond_init partitioned_cond_init
#define lock_cond_timedwait partitioned_cond_timedwait
#define lock_cond_wait partitioned_cond_wait
#define lock_cond_signal partitioned_cond_signal
#define lock_cond_broadcast partitioned_cond_broadcast
#define lock_cond_destroy partitioned_cond_destroy
#define lock_thread_start partitioned_thread_start
#define lock_thread_exit partitioned_thread_exit
#define lock_application_init partitioned_application_init
#define lock_application_exit partitioned_application_exit
#define lock_init_context partitioned_init_context

#endif // __PARTITIONED_H__
