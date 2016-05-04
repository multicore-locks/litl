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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include <assert.h>
#include <atomic_ops.h>
#include <clht.h>

#ifdef MCS
#include <mcs.h>
#elif defined(MCSTP)
#include <mcstp.h>
#elif defined(SPINLOCK)
#include <spinlock.h>
#elif defined(MALTHUSIAN)
#include <malthusian.h>
#elif defined(TTAS)
#include <ttas.h>
#elif defined(TICKET)
#include <ticket.h>
#elif defined(CLH)
#include <clh.h>
#elif defined(BACKOFF)
#include <backoff.h>
#elif defined(PTHREADCACHEALIGNED)
#include <pthreadcachealigned.h>
#elif defined(PTHREADINTERPOSE)
#include <pthreadinterpose.h>
#elif defined(PTHREADADAPTIVE)
#include <pthreadadaptive.h>
#elif defined(EMPTY)
#include <empty.h>
#elif defined(CONCURRENCY)
#include <concurrency.h>
#elif defined(MCSEPFL)
#include <mcsepfl.h>
#elif defined(SPINLOCKEPFL)
#include <spinlockepfl.h>
#elif defined(TTASEPFL)
#include <ttasepfl.h>
#elif defined(TICKETEPFL)
#include <ticketepfl.h>
#elif defined(CLHEPFL)
#include <clhepfl.h>
#elif defined(HTLOCKEPFL)
#include <htlockepfl.h>
#elif defined(ALOCKEPFL)
#include <alockepfl.h>
#elif defined(HMCS)
#include <hmcs.h>
#elif defined(HYSHMCS)
#include <hyshmcs.h>
#elif defined(CBOMCS)
#include <cbomcs.h>
#elif defined(CPTLTKT)
#include <cptltkt.h>
#elif defined(CTKTTKT)
#include <ctkttkt.h>
#elif defined(PARTITIONED)
#include <partitioned.h>
#else
#error "No lock algorithm known"
#endif

#include "waiting_policy.h"
#include "utils.h"
#include "interpose.h"

// The NO_INDIRECTION flag allows disabling the pthread-to-lock hash table
// and directly calling the specific lock function
// See empty.c for example.

unsigned int last_thread_id;
__thread unsigned int cur_thread_id;

#if !NO_INDIRECTION
typedef struct {
    lock_mutex_t *lock_lock;
    char __pad[pad_to_cache_line(sizeof(lock_mutex_t *))];
#if NEED_CONTEXT
    lock_context_t lock_node[MAX_THREADS];
#endif
} lock_transparent_mutex_t;

// pthread-to-lock htable (using CLHT)
static clht_t *pthread_to_lock;
#endif

struct routine {
    void *(*fct)(void *);
    void *arg;
};

// With this flag enabled, the mutex_destroy function will be called on each
// alive lock
// at application exit (e.g., for printing statistics about a lock -- see
// src/concurrency.c)
#ifndef DESTROY_ON_EXIT
#define DESTROY_ON_EXIT 0
#endif

// With this flag enabled, SIGINT and SIGTERM are caught to call the destructor
// of the library (see interpose_exit below)
#ifndef CLEANUP_ON_SIGNAL
#define CLEANUP_ON_SIGNAL 0
#endif

#if !NO_INDIRECTION
static lock_transparent_mutex_t *
ht_lock_create(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr) {
    lock_transparent_mutex_t *impl = alloc_cache_align(sizeof *impl);
    impl->lock_lock                = lock_mutex_create(attr);
#if NEED_CONTEXT
    lock_init_context(impl->lock_lock, impl->lock_node, MAX_THREADS);
#endif

    // If a lock is initialized statically and two threads acquire the locks at
    // the same time, then only one call to clht_put will succeed.
    // For the failing thread, we free the previously allocated mutex data
    // structure and do a lookup to retrieve the ones inserted by the successful
    // thread.
    if (clht_put(pthread_to_lock, (clht_addr_t)mutex, (clht_val_t)impl) == 0) {
        free(impl);
        return (lock_transparent_mutex_t *)clht_get(pthread_to_lock->ht,
                                                    (clht_val_t)mutex);
    }
    return impl;
}

static lock_transparent_mutex_t *ht_lock_get(pthread_mutex_t *mutex) {
    lock_transparent_mutex_t *impl = (lock_transparent_mutex_t *)clht_get(
        pthread_to_lock->ht, (clht_val_t)mutex);
    if (impl == NULL) {
        impl = ht_lock_create(mutex, NULL);
    }

    return impl;
}
#endif

int (*REAL(pthread_mutex_init))(pthread_mutex_t *mutex,
                                const pthread_mutexattr_t *attr)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_mutex_destroy))(pthread_mutex_t *mutex)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_mutex_lock))(pthread_mutex_t *mutex)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_mutex_trylock))(pthread_mutex_t *mutex)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_mutex_unlock))(pthread_mutex_t *mutex)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_create))(pthread_t *thread, const pthread_attr_t *attr,
                            void *(*start_routine)(void *), void *arg)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_init))(pthread_cond_t *cond,
                               const pthread_condattr_t *attr)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_destroy))(pthread_cond_t *cond)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_timedwait))(pthread_cond_t *cond,
                                    pthread_mutex_t *mutex,
                                    const struct timespec *abstime)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_wait))(pthread_cond_t *cond, pthread_mutex_t *mutex)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_signal))(pthread_cond_t *cond)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));
int (*REAL(pthread_cond_broadcast))(pthread_cond_t *cond)
    __attribute__((aligned(L_CACHE_LINE_SIZE)));

#if CLEANUP_ON_SIGNAL
static void signal_exit(int signo);
#endif

static void __attribute__((constructor)) REAL(interpose_init)(void) {
#if !(SUPPORT_WAITING) && !(defined(WAITING_ORIGINAL))
#error "Trying to compile a lock algorithm with a generic waiting policy."
#endif

    printf("Using Lib%s with waiting %s\n", LOCK_ALGORITHM, WAITING_POLICY);
    LOAD_FUNC(pthread_mutex_init, 1, FCT_LINK_SUFFIX);
    LOAD_FUNC(pthread_mutex_destroy, 1, FCT_LINK_SUFFIX);
    LOAD_FUNC(pthread_mutex_lock, 1, FCT_LINK_SUFFIX);
    LOAD_FUNC(pthread_mutex_trylock, 1, FCT_LINK_SUFFIX);
    LOAD_FUNC(pthread_mutex_unlock, 1, FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_timedwait, 1, GLIBC_2_3_2,
                        FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_wait, 1, GLIBC_2_3_2, FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_broadcast, 1, GLIBC_2_3_2,
                        FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_destroy, 1, GLIBC_2_3_2, FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_init, 1, GLIBC_2_3_2, FCT_LINK_SUFFIX);
    LOAD_FUNC_VERSIONED(pthread_cond_signal, 1, GLIBC_2_3_2, FCT_LINK_SUFFIX);
    LOAD_FUNC(pthread_create, 1, FCT_LINK_SUFFIX);
#if !NO_INDIRECTION
    pthread_to_lock = clht_create(NUM_BUCKETS);
    assert(pthread_to_lock != NULL);
#endif

    // The main thread should also have an ID
    cur_thread_id = __sync_fetch_and_add(&last_thread_id, 1);
    if (cur_thread_id >= MAX_THREADS) {
        fprintf(stderr, "Maximum number of threads reached. Consider raising "
                        "MAX_THREADS in interpose.c\n");
        exit(-1);
    }
#if !NO_INDIRECTION
    clht_gc_thread_init(pthread_to_lock, cur_thread_id);
#endif

    lock_application_init();

#if CLEANUP_ON_SIGNAL
    // Signal handler for destroying locks at then end
    // We can't batch the registrations of the handler with a single syscall
    if (signal(SIGINT, signal_exit) == SIG_ERR) {
        fprintf(stderr, "Unable to install signal handler to catch SIGINT\n");
        abort();
    }

    if (signal(SIGTERM, signal_exit) == SIG_ERR) {
        fprintf(stderr, "Unable to install signal handler to catch SIGTERM\n");
        abort();
    }
#endif
}
static void __attribute__((destructor)) REAL(interpose_exit)(void) {
#if DESTROY_ON_EXIT
    // TODO: modify CLHT to do that
    uint64_t num_buckets = pthread_to_lock->ht->num_buckets;
    volatile bucket_t *bucket;

    uint64_t bin;
    for (bin = 0; bin < num_buckets; bin++) {
        bucket = pthread_to_lock->ht->table + bin;

        uint32_t j;
        do {
            for (j = 0; j < ENTRIES_PER_BUCKET; j++) {
                if (bucket->key[j]) {
                    lock_transparent_mutex_t *lock =
                        (lock_transparent_mutex_t *)bucket->val[j];
                    fprintf(stderr, "\n%p,%lu,%f\n", lock->lock_lock,
                            lock->lock_lock->max, lock->lock_lock->mean);
                    // Do not destroy the lock if concurrent accesses
                    // concurrency_mutex_destroy(lock->lock_lock);
                }
            }

            bucket = bucket->padding;
        } while (bucket != NULL);
    }
#endif
    // Do not destroy the hashtable. If we shutdown the application via
    // signal, some threads might still be running and accessing the hashmap
    // concurrently. (Anyway, the kernel will clean this)

    // clht_gc_destroy(pthread_to_lock);
    // pthread_to_lock = NULL;

    lock_application_exit();
}

#if !NO_INDIRECTION
static inline lock_context_t *get_node(lock_transparent_mutex_t *impl) {
#if NEED_CONTEXT
    return &impl->lock_node[cur_thread_id];
#else
    return NULL;
#endif
};
#endif

#if CLEANUP_ON_SIGNAL
static void signal_exit(int UNUSED(signo)) {
    fprintf(stderr, "Signal received\n");
    exit(-1);
}
#endif

static void *lp_start_routine(void *_arg) {
    struct routine *r = _arg;
    void *(*fct)(void *) = r->fct;
    void *arg = r->arg;
    void *res;
    free(r);

    cur_thread_id = __sync_fetch_and_add(&last_thread_id, 1);
    if (cur_thread_id >= MAX_THREADS) {
        fprintf(stderr, "Maximum number of threads reached. Consider raising "
                        "MAX_THREADS in interpose.c (current = %u)\n",
                MAX_THREADS);
        exit(-1);
    }

#if !NO_INDIRECTION
    clht_gc_thread_init(pthread_to_lock, cur_thread_id);
#endif
    lock_thread_start();
    res = fct(arg);
    lock_thread_exit();

    return res;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg) {
    DEBUG_PTHREAD("[p] pthread_create\n");
    struct routine *r = malloc(sizeof(struct routine));

    r->fct = start_routine;
    r->arg = arg;

    return REAL(pthread_create)(thread, attr, lp_start_routine, r);
}

int pthread_mutex_init(pthread_mutex_t *mutex,
                       const pthread_mutexattr_t *attr) {
    DEBUG_PTHREAD("[p] pthread_mutex_init\n");
#if !NO_INDIRECTION
    ht_lock_create(mutex, attr);
    return 0;
#else
    return REAL(pthread_mutex_init)(mutex, attr);
#endif
}

int pthread_mutex_destroy(pthread_mutex_t *mutex) {
    DEBUG_PTHREAD("[p] pthread_mutex_destroy\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = (lock_transparent_mutex_t *)clht_remove(
        pthread_to_lock, (clht_addr_t)mutex);
    if (impl != NULL) {
        lock_mutex_destroy(impl->lock_lock);
        free(impl);
    }

    return REAL(pthread_mutex_destroy)(mutex);
#else
    return lock_mutex_destroy(mutex);
#endif
}

int pthread_mutex_lock(pthread_mutex_t *mutex) {
    DEBUG_PTHREAD("[p] pthread_mutex_lock\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = ht_lock_get(mutex);
    return lock_mutex_lock(impl->lock_lock, get_node(impl));
#else
    return lock_mutex_lock(mutex, NULL);
#endif
}

int pthread_mutex_trylock(pthread_mutex_t *mutex) {
    DEBUG_PTHREAD("[p] pthread_mutex_trylock\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = ht_lock_get(mutex);
    return lock_mutex_trylock(impl->lock_lock, get_node(impl));
#else
    return lock_mutex_trylock(mutex, NULL);
#endif
}

int pthread_mutex_unlock(pthread_mutex_t *mutex) {
    DEBUG_PTHREAD("[p] pthread_mutex_unlock\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = ht_lock_get(mutex);
    lock_mutex_unlock(impl->lock_lock, get_node(impl));
    return 0;
#else
    lock_mutex_unlock(mutex, NULL);
    return 0;
#endif
}

int __pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    DEBUG_PTHREAD("[p] pthread_cond_init\n");
    return lock_cond_init(cond, attr);
}
__asm__(".symver __pthread_cond_init,pthread_cond_init@@" GLIBC_2_3_2);

int __pthread_cond_destroy(pthread_cond_t *cond) {
    DEBUG_PTHREAD("[p] pthread_cond_destroy\n");
    return lock_cond_destroy(cond);
}
__asm__(".symver __pthread_cond_destroy,pthread_cond_destroy@@" GLIBC_2_3_2);

int __pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                             const struct timespec *abstime) {
    DEBUG_PTHREAD("[p] pthread_cond_timedwait\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = ht_lock_get(mutex);
    return lock_cond_timedwait(cond, impl->lock_lock, get_node(impl), abstime);
#else
    return lock_cond_timedwait(cond, mutex, NULL, abstime);
#endif
}
__asm__(
    ".symver __pthread_cond_timedwait,pthread_cond_timedwait@@" GLIBC_2_3_2);

int __pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    DEBUG_PTHREAD("[p] pthread_cond_wait\n");
#if !NO_INDIRECTION
    lock_transparent_mutex_t *impl = ht_lock_get(mutex);
    return lock_cond_wait(cond, impl->lock_lock, get_node(impl));
#else
    return lock_cond_wait(cond, mutex, NULL);
#endif
}
__asm__(".symver __pthread_cond_wait,pthread_cond_wait@@" GLIBC_2_3_2);

int __pthread_cond_signal(pthread_cond_t *cond) {
    DEBUG_PTHREAD("[p] pthread_cond_signal\n");
    return lock_cond_signal(cond);
}
__asm__(".symver __pthread_cond_signal,pthread_cond_signal@@" GLIBC_2_3_2);

int __pthread_cond_broadcast(pthread_cond_t *cond) {
    DEBUG_PTHREAD("[p] pthread_cond_broadcast\n");
    return lock_cond_broadcast(cond);
}
__asm__(
    ".symver __pthread_cond_broadcast,pthread_cond_broadcast@@" GLIBC_2_3_2);
