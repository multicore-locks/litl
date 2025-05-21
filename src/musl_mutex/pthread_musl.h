// #ifndef _PTHREAD_H
// #define _PTHREAD_H
#pragma once
//#ifdef __cplusplus
//extern "C" {
//#endif

#include "features.h"
#include "alltypes_make.h"

#define __NEED_clockid_t
#define __NEED_struct_timespec
#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#define __NEED_pthread_mutexattr_t
#define __NEED_pthread_mutex_t
#define __NEED_size_t


//#include <sched.h>
#include "time.h"

#define PTHREAD_CREATE_JOINABLE 0
#define PTHREAD_CREATE_DETACHED 1

#define PTHREAD_MUTEX_NORMAL 0
#define PTHREAD_MUTEX_DEFAULT 0
#define PTHREAD_MUTEX_RECURSIVE 1
#define PTHREAD_MUTEX_ERRORCHECK 2

#define PTHREAD_MUTEX_STALLED 0
#define PTHREAD_MUTEX_ROBUST 1

#define PTHREAD_PRIO_NONE 0
#define PTHREAD_PRIO_INHERIT 1
#define PTHREAD_PRIO_PROTECT 2

#define PTHREAD_INHERIT_SCHED 0
#define PTHREAD_EXPLICIT_SCHED 1

#define PTHREAD_SCOPE_SYSTEM 0
#define PTHREAD_SCOPE_PROCESS 1

#define PTHREAD_PROCESS_PRIVATE 0
#define PTHREAD_PROCESS_SHARED 1

#define PTHREAD_MUTEX_INITIALIZER {{{0}}}
#define PTHREAD_RWLOCK_INITIALIZER {{{0}}}
#define PTHREAD_COND_INITIALIZER {{{0}}}
#define PTHREAD_ONCE_INIT 0

#define PTHREAD_CANCEL_ENABLE 0
#define PTHREAD_CANCEL_DISABLE 1
#define PTHREAD_CANCEL_MASKED 2

#define PTHREAD_CANCEL_DEFERRED 0
#define PTHREAD_CANCEL_ASYNCHRONOUS 1

#define PTHREAD_CANCELED ((void *)-1)

#define PTHREAD_BARRIER_SERIAL_THREAD (-1)

#define PTHREAD_NULL ((pthread_t)0)


#ifdef __GNUC__
__attribute__((const))
#endif

typedef void *musl_context_t;

int __pthread_musl_mutex_lock(__pthread_mutex_t *impl, musl_context_t *me);
int __pthread_musl_mutex_unlock(__pthread_mutex_t *impl, musl_context_t *me);
int __pthread_musl_mutex_trylock(__pthread_mutex_t *, musl_context_t *me);
int __pthread_musl_mutex_timedlock(__pthread_mutex_t *restrict m, const struct timespec *restrict at, musl_context_t *me);
int __pthread_musl_mutex_init(__pthread_mutex_t *restrict m, const __pthread_mutexattr_t *restrict a);

#ifdef _GNU_SOURCE
struct cpu_set_t;
#endif

//#ifdef __cplusplus
//}
//#endif

// #endif
