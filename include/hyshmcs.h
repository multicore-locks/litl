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
#ifndef __HYSHMCS_H__
#define __HYSHMCS_H__

#include <stdbool.h>
#include "padding.h"
#define LOCK_ALGORITHM "HYSHMCS"
#define NEED_CONTEXT 1
#define SUPPORT_WAITING 0

// How many local locking before release the global lock (default number in the
// paper)
#define RELEASE_THRESHOLD 100 // Same as cohort for comparison

struct hyshmcs_hnode;
typedef struct hyshmcs_qnode {
    struct hyshmcs_qnode *volatile next;
    char __pad[pad_to_cache_line(sizeof(struct hyshmcs_qnode *))];
    volatile uint64_t status __attribute__((aligned(L_CACHE_LINE_SIZE)));
    char __pad2[pad_to_cache_line(sizeof(uint64_t))];
    struct hyshmcs_hnode *cur_node;
    bool took_fast_path;
    uint8_t cur_depth;
    uint8_t real_depth;
    uint8_t depth_waited;
} hyshmcs_qnode_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct hyshmcs_hnode {
    struct hyshmcs_hnode *parent __attribute__((aligned(L_CACHE_LINE_SIZE)));
    struct hyshmcs_qnode *volatile tail;
    char __pad[pad_to_cache_line(sizeof(struct hyshmcs_qnode *) +
                                 sizeof(struct hyshmcs_hnode *))];
    hyshmcs_qnode_t node;
} hyshmcs_hnode_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef struct hyshmcs_mutex {
#if COND_VAR
    pthread_mutex_t posix_lock;
    char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
#endif
    hyshmcs_hnode_t global;
    hyshmcs_hnode_t local[NUMA_NODES];
} hyshmcs_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef pthread_cond_t hyshmcs_cond_t;
hyshmcs_mutex_t *hyshmcs_mutex_create(const pthread_mutexattr_t *attr);
int hyshmcs_mutex_lock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me);
int hyshmcs_mutex_trylock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me);
void hyshmcs_mutex_unlock(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *me);
int hyshmcs_mutex_destroy(hyshmcs_mutex_t *lock);
int hyshmcs_cond_init(hyshmcs_cond_t *cond, const pthread_condattr_t *attr);
int hyshmcs_cond_timedwait(hyshmcs_cond_t *cond, hyshmcs_mutex_t *lock,
                           hyshmcs_qnode_t *me, const struct timespec *ts);
int hyshmcs_cond_wait(hyshmcs_cond_t *cond, hyshmcs_mutex_t *lock,
                      hyshmcs_qnode_t *me);
int hyshmcs_cond_signal(hyshmcs_cond_t *cond);
int hyshmcs_cond_broadcast(hyshmcs_cond_t *cond);
int hyshmcs_cond_destroy(hyshmcs_cond_t *cond);
void hyshmcs_thread_start(void);
void hyshmcs_thread_exit(void);
void hyshmcs_application_init(void);
void hyshmcs_application_exit(void);
void hyshmcs_init_context(hyshmcs_mutex_t *impl, hyshmcs_qnode_t *context,
                          int number);

typedef hyshmcs_mutex_t lock_mutex_t;
typedef hyshmcs_qnode_t lock_context_t;
typedef hyshmcs_cond_t lock_cond_t;

#define lock_mutex_create hyshmcs_mutex_create
#define lock_mutex_lock hyshmcs_mutex_lock
#define lock_mutex_trylock hyshmcs_mutex_trylock
#define lock_mutex_unlock hyshmcs_mutex_unlock
#define lock_mutex_destroy hyshmcs_mutex_destroy
#define lock_cond_init hyshmcs_cond_init
#define lock_cond_timedwait hyshmcs_cond_timedwait
#define lock_cond_wait hyshmcs_cond_wait
#define lock_cond_signal hyshmcs_cond_signal
#define lock_cond_broadcast hyshmcs_cond_broadcast
#define lock_cond_destroy hyshmcs_cond_destroy
#define lock_thread_start hyshmcs_thread_start
#define lock_thread_exit hyshmcs_thread_exit
#define lock_application_init hyshmcs_application_init
#define lock_application_exit hyshmcs_application_exit
#define lock_init_context hyshmcs_init_context

#endif // __HYSHMCS_H__
