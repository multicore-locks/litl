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
#ifndef __MUSL_MUTEX_H__
#define __MUSL_MUTEX_H__

#define LOCK_ALGORITHM "MUSL"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0

// Define needed types before including alltypes_make.h
// #define __NEED_pthread_cond_t
// #define __NEED_pthread_condattr_t

#include "../src/musl_mutex/alltypes_make.h"
#include "padding.h" // for glibc pthread_cond_t

// typedef struct musl_mutex {
// // #if COND_VAR
// //     pthread_mutex_t posix_lock;
// //     char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
// // #endif
//     __pthread_mutex_t lock;
// } musl_mutex_t __attribute__((aligned(L_CACHE_LINE_SIZE)));

typedef __pthread_mutex_t musl_mutex_t;
typedef __pthread_cond_t musl_cond_t;
// typedef void *musl_context_t; // Unused, take the less space
                                           // as possible
typedef void *musl_context_t;
typedef musl_mutex_t lock_mutex_t;
typedef musl_context_t lock_context_t;
typedef musl_cond_t lock_cond_t;

//

// typedef __pthread_mutex_t musl_mutex_t;
// typedef __pthread_mutexattr_t musl_mutexattr_t;

// typedef pthread_mutex_t musl_mutex_t;
// typedef pthread_cond_t musl_cond_t;
// typedef void *musl_context_t;

// typedef musl_mutex_t lock_mutex_t;
// typedef musl_context_t lock_context_t;

// typedef void *musl_context_t; // Unused, take the less space as possible
// typedef void *lock_context_t; // Required for interpose.c

//Decls
musl_mutex_t *musl_mutex_create(const __pthread_mutexattr_t *attr);
int musl_mutex_destroy(musl_mutex_t *lock);


// int musl_cond_init(musl_cond_t *cond, const pthread_condattr_t *attr);
// int __pthread_musl_cond_init(musl_cond_t *restrict c, const pthread_condattr_t *restrict a);
// // int musl_cond_timedwait(musl_cond_t *cond, musl_mutex_t *lock,
// //                             musl_context_t *me, const struct timespec *ts);
// int __pthread_musl_cond_timedwait(musl_cond_t *restrict c, musl_mutex_t *restrict m, musl_context_t *restrict me, const struct timespec *restrict ts);
// // int musl_cond_wait(musl_cond_t *cond, musl_mutex_t *lock, musl_context_t *me);
// int __pthread_musl_cond_wait(musl_cond_t *restrict c, musl_mutex_t *restrict m, musl_context_t *restrict me);

// // int musl_cond_signal(musl_cond_t *cond);
// int __pthread_musl_cond_signal(musl_cond_t *cond);
// // int musl_cond_broadcast(musl_cond_t *cond);
// int __pthread_musl_cond_broadcast(musl_cond_t *cond);
// // int musl_cond_destroy(musl_cond_t *cond);
// int __pthread_musl_cond_destroy(musl_cond_t *c);

void musl_thread_start(void);
void musl_thread_exit(void);
void musl_application_init(void);
void musl_application_exit(void);
//unused


//Defines
// From musl_mutex/pthread_musl.h
#define lock_mutex_lock __pthread_musl_mutex_lock
#define lock_mutex_trylock __pthread_musl_mutex_trylock
#define lock_mutex_unlock __pthread_musl_mutex_unlock
// #define musl_mutex_init __pthread_mutex_init

// From here
#define lock_mutex_create musl_mutex_create
#define lock_mutex_destroy musl_mutex_destroy

//Unused
#define lock_cond_init __pthread_musl_cond_init
#define lock_cond_timedwait __pthread_musl_cond_timedwait
#define lock_cond_wait __pthread_musl_cond_wait
#define lock_cond_signal __pthread_musl_cond_signal
#define lock_cond_broadcast __pthread_musl_cond_broadcast
#define lock_cond_destroy __pthread_musl_cond_destroy
#define lock_thread_start musl_thread_start
#define lock_thread_exit musl_thread_exit
#define lock_application_init musl_application_init
#define lock_application_exit musl_application_exit
#define lock_init_context musl_init_context
//unused

#endif // __MUSL_MUTEX_H__
