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
#ifndef __CBOMCS_H__
#define __CBOMCS_H__

#include <stdint.h>
#include "padding.h"
#define LOCK_ALGORITHM "C-BO-MCS"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 1

// How many local locking before release the global lock (default number in the
// paper)
#define BATCH_COUNT 100
// The constants are taken from concurrencykit
// The unit is one iteration of a loop with a CPU_PAUSE inside
#define DEFAULT_BACKOFF_DELAY (1 << 9)
#define MAX_BACKOFF_DELAY ((1 << 20) - 1)

typedef struct backoff_ttas {
    volatile uint8_t spin_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));
} backoff_ttas_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct mcs_node {
    struct mcs_node *volatile next;
    char __pad1[pad_to_cache_line(sizeof(struct mcs_node *))];

    volatile int spin __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad2[pad_to_cache_line(sizeof(int))];
} mcs_node_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct mcs_mutex {
    mcs_node_t *volatile tail __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad[pad_to_cache_line(sizeof(mcs_node_t *))];
} mcs_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

// Local lock cohorted structure
typedef struct local_mcs_lock {
    mcs_mutex_t l; // Cache aligned

    volatile uint32_t top_grant;
    int32_t batch_count;
    char __pad[pad_to_cache_line(sizeof(uint32_t) + sizeof(int32_t))];
} local_mcs_lock_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

// Global lock cohorted structure
typedef backoff_ttas_t global_backoff_ttas_lock_t;

// Cohort mutex structure
typedef struct c_ptl_tkt {
    global_backoff_ttas_lock_t top_lock;
    local_mcs_lock_t local_locks[NUMA_NODES];
#if COND_VAR
    pthread_mutex_t posix_lock;
#endif
    local_mcs_lock_t *volatile top_home;
} cbomcs_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t cbomcs_cond_t;
typedef mcs_node_t cbomcs_node_t;

cbomcs_mutex_t *cbomcs_mutex_create(const pthread_mutexattr_t *attr);
int cbomcs_mutex_lock(cbomcs_mutex_t *impl, cbomcs_node_t *me);
int cbomcs_mutex_trylock(cbomcs_mutex_t *impl, cbomcs_node_t *me);
void cbomcs_mutex_unlock(cbomcs_mutex_t *impl, cbomcs_node_t *me);
int cbomcs_mutex_destroy(cbomcs_mutex_t *lock);
int cbomcs_cond_init(cbomcs_cond_t *cond, const pthread_condattr_t *attr);
int cbomcs_cond_timedwait(cbomcs_cond_t *cond, cbomcs_mutex_t *lock,
                          cbomcs_node_t *me, const struct timespec *ts);
int cbomcs_cond_wait(cbomcs_cond_t *cond, cbomcs_mutex_t *lock,
                     cbomcs_node_t *me);
int cbomcs_cond_signal(cbomcs_cond_t *cond);
int cbomcs_cond_broadcast(cbomcs_cond_t *cond);
int cbomcs_cond_destroy(cbomcs_cond_t *cond);
void cbomcs_thread_start(void);
void cbomcs_thread_exit(void);
void cbomcs_application_init(void);
void cbomcs_application_exit(void);
void cbomcs_init_context(cbomcs_mutex_t *impl, cbomcs_node_t *context,
                         int number);

typedef cbomcs_mutex_t lock_mutex_t;
typedef cbomcs_node_t lock_context_t;
typedef cbomcs_cond_t lock_cond_t;

#define lock_mutex_create cbomcs_mutex_create
#define lock_mutex_lock cbomcs_mutex_lock
#define lock_mutex_trylock cbomcs_mutex_trylock
#define lock_mutex_unlock cbomcs_mutex_unlock
#define lock_mutex_destroy cbomcs_mutex_destroy
#define lock_cond_init cbomcs_cond_init
#define lock_cond_timedwait cbomcs_cond_timedwait
#define lock_cond_wait cbomcs_cond_wait
#define lock_cond_signal cbomcs_cond_signal
#define lock_cond_broadcast cbomcs_cond_broadcast
#define lock_cond_destroy cbomcs_cond_destroy
#define lock_thread_start cbomcs_thread_start
#define lock_thread_exit cbomcs_thread_exit
#define lock_application_init cbomcs_application_init
#define lock_application_exit cbomcs_application_exit
#define lock_init_context cbomcs_init_context

#endif // __CBOMCS_H__
