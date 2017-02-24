/*
 * File: mutexee_in.h
 * Author: Vasileios Trigonakis <vasileios.trigonakis@epfl.ch>
 *
 * Description: 
 *      The mutexee spin-futex adaptive lock algorithm.
 *
 *      The mutexee is an adaptive spin-futex lock.
 *      Mutexee measures the spin-to-mutex acquire (or release) ratio and adjusts
 *      the spinning behavior of the lock accordingly. For example, when the ratio
 *      is below the target limit, mutexee might try to increase the number of 
 *      spins. If this increment is unsucessful, it might decides to increase it 
 *      further, or to simply become a futex-lock. Mutexee eventuall reaches some
 *      stable states, but never stops trying to find a better stable state.
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 Vasileios Trigonakis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* 
 */


#ifndef _MUTEXEE_IN_H_
#define _MUTEXEE_IN_H_

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <malloc.h>
#include <limits.h>

#include "topology.h"

#if !defined(__x86_64__)
#  error This file is designed to work only on x86_64 architectures! 
#endif

  /* ******************************************************************************** */
  /* settings *********************************************************************** */
#define PADDING        1        /* padd locks/conditionals to cache-line */
#define FREQ_CPU_GHZ   CPU_FREQ	/* core frequency in GHz */
#define REPLACE_MUTEX  1	/* ovewrite the pthread_[mutex|cond] functions */
#define MUTEXEE_SPIN_TRIES_LOCK       8192 /* spinning retries before futex */
#define MUTEXEE_SPIN_TRIES_LOCK_MIN   256 /* spinning retries before futex */
#define MUTEXEE_SPIN_TRIES_UNLOCK     384  /* spinning retries before futex wake */
#define MUTEXEE_SPIN_TRIES_UNLOCK_MIN 128  /* spinning retries before futex wake */

#define MUTEXEE_DO_ADAP             1
#define MUTEXEE_ADAP_EVERY          2047
#define MUTEXEE_RETRY_SPIN_EVERY     8
#define MUTEXEE_RETRY_SPIN_EVERY_MAX 32
#define MUTEXEE_FUTEX_LIM           128
#define MUTEXEE_FUTEX_LIM_MAX       256
#define MUTEXEE_PRINT               0 /* print debug output  */

#ifndef MUTEXEE_FAIR
#  define MUTEXEE_FAIR              0 /* enable or not mechanisms for capping
				       the maximum tail latency of the lock */
#endif

#if MUTEXEE_FAIR > 0
#  define LOCK_IN_NAME "MUTEXEE-FAIR"
#else
#  define LOCK_IN_NAME "MUTEXEE"
#endif

#  define MUTEXEE_FTIMEOUTS 0	/* timeout seconds */
#ifndef MUTEXEE_FTIMEOUT
#  define MUTEXEE_FTIMEOUT   3000000 /* timeout nanoseconds - max 1e9-1
					if you want to set it to more than 1 sec
					use MUTEXEE_FTIMEOUTS */ 
#endif

#if 0
  const struct timespec mutexee_max_sleep = { .tv_sec = MUTEXEE_FTIMEOUTS,
					      .tv_nsec = MUTEXEE_FTIMEOUT };
#else
extern const struct timespec mutexee_max_sleep;
#endif

#if MUTEXEE_DO_ADAP == 1
#  define MUTEXEE_ADAP(d)	    d
#else
#  define MUTEXEE_ADAP(d) 
#endif
  /* ******************************************************************************** */

#if defined(PAUSE_IN)
#  undef PAUSE_IN
#endif
#  define PAUSE_IN()				\
  asm volatile ("mfence");

  static inline void
  mutexee_cdelay(const int cycles)
  {
    int cy = cycles;
    while (cy--)
      {
	asm volatile ("");
      }
  }


  //Swap uint32_t
  static inline uint32_t
  mutexee_swap_uint32(volatile uint32_t* target,  uint32_t x)
  {
    asm volatile("xchgl %0,%1"
		 :"=r" ((uint32_t) x)
		 :"m" (*(volatile uint32_t *)target), "0" ((uint32_t) x)
		 :"memory");

    return x;
  }

  //Swap uint8_t
  static inline uint8_t
  mutexee_swap_uint8(volatile uint8_t* target,  uint8_t x) 
  {
    asm volatile("xchgb %0,%1"
		 :"=r" ((uint8_t) x)
		 :"m" (*(volatile uint8_t *)target), "0" ((uint8_t) x)
		 :"memory");

    return x;
  }

#define mutexee_cas(a, b, c) __sync_val_compare_and_swap(a, b, c)
#define atomic_add(a, b) __sync_fetch_and_add(a, b)

  typedef __attribute__((aligned(L_CACHE_LINE_SIZE))) struct mutexee_lock 
  {
    union
    {
      volatile unsigned u;
      struct
      {
	volatile unsigned char locked;
	volatile unsigned char contended;
      } b;
    } l;
    uint8_t padding[4];
    /* uint8_t padding_cl[56]; */

    unsigned int n_spins;
    unsigned int n_spins_unlock;
    size_t n_acq;
    unsigned int n_miss;
    unsigned int n_miss_limit;
    unsigned int is_futex;
    unsigned int n_acq_first_sleep;
    unsigned int retry_spin_every;
    unsigned int padding3;
    uint8_t padding2[L_CACHE_LINE_SIZE - 6 * sizeof(size_t)];
  } mutexee_lock_t;

#define STATIC_ASSERT(a, msg)           _Static_assert ((a), msg);

  /* STATIC_ASSERT((sizeof(mutexee_lock_t) == 64) || (sizeof(mutexee_lock_t) == 4),  */
  /* 		"sizeof(mutexee_lock_t)"); */


#define MUTEXEE_INITIALIZER				\
  {							\
    .l.u = 0,						\
      .n_spins = MUTEXEE_SPIN_TRIES_LOCK,		\
      .n_spins_unlock = MUTEXEE_SPIN_TRIES_UNLOCK,	\
      .n_acq = 0,	              			\
      .n_miss = 0,					\
      .n_miss_limit = MUTEXEE_FUTEX_LIM,		\
      .is_futex = 0,					\
      .n_acq_first_sleep = 0,				\
      .retry_spin_every = MUTEXEE_RETRY_SPIN_EVERY,	\
      }

  typedef struct upmutex_cond1
  {
    mutexee_lock_t* m;
    int seq;
    int pad;
#if PADDING == 1
    uint8_t padding[L_CACHE_LINE_SIZE - 16];
#endif
  } upmutex_cond1_t;

#define UPMUTEX_COND1_INITIALIZER {NULL, 0, 0}

  static inline int
  sys_futex(void* addr1, int op, int val1, struct timespec* timeout, void* addr2, int val3)
  {
      int ret = syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
      errno = 0;
      return ret;
  }

  static inline int
  mutexee_init(mutexee_lock_t* m, const pthread_mutexattr_t* a)
  {
    (void) a;
    m->l.u = 0;
    m->n_spins = MUTEXEE_SPIN_TRIES_LOCK;
    m->n_spins_unlock = MUTEXEE_SPIN_TRIES_UNLOCK;
    m->n_acq = 0;
    m->n_miss = 0;
    m->n_miss_limit = MUTEXEE_FUTEX_LIM;
    m->is_futex = 0;
    m->n_acq_first_sleep = 0;
    m->retry_spin_every = MUTEXEE_RETRY_SPIN_EVERY;
    return 0;
  }

  static inline int
  mutexee_destroy(mutexee_lock_t* m)
  {
    /* Do nothing */
    (void) m;
    return 0;
  }

#define __mutexee_unlikely(x) __builtin_expect((x), 0)

  static inline uint64_t mutexee_getticks(void)
  {
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
  }

#define MUTEXEE_FOR_N_CYCLES(n, do)		\
  {						\
  uint64_t ___s = mutexee_getticks();		\
  while (1)					\
    {						\
      do;					\
      uint64_t ___e = mutexee_getticks();	\
      if ((___e - ___s) > n)			\
	{					\
	  break;				\
	}					\
    }						\
  }

  static inline int
  mutexee_lock(mutexee_lock_t* m)
  {
    if (!mutexee_swap_uint8(&m->l.b.locked, 1))
      {
	return 0;
      }

#if MUTEXEE_DO_ADAP == 1
    const register unsigned int time_spin = m->n_spins;
#else
    const unsigned int time_spin = MUTEXEE_SPIN_TRIES_LOCK;
#endif
    MUTEXEE_FOR_N_CYCLES(time_spin,
			 if (!mutexee_swap_uint8(&m->l.b.locked, 1)) 
			   {
			     return 0;
			   }
			 PAUSE_IN();
			 );
    

    /* Have to sleep */
#if MUTEXEE_FAIR > 0
    int once = 1;
    while (mutexee_swap_uint32(&m->l.u, 257) & 1)
      {
	PAUSE_IN();
	if (once)
	  {
	    int ret = sys_futex(m, FUTEX_WAIT_PRIVATE, 257, 
				(struct timespec *) &mutexee_max_sleep, NULL, 0);
	    if (ret == -1 && errno == ETIMEDOUT)
	      {
		once = 0;
	      }
	  }
      }
#else  /* not fair */
    while (mutexee_swap_uint32(&m->l.u, 257) & 1)
      {
	sys_futex(m, FUTEX_WAIT_PRIVATE, 257, NULL, NULL, 0);
      }    
#endif /* MUTEXEE_FAIR */

    return 0;
  }

  static inline void
  mutexee_lock_training(mutexee_lock_t* m)
  {
    const size_t n_acq_curr =  ++m->n_acq;
    if (__mutexee_unlikely((n_acq_curr & MUTEXEE_ADAP_EVERY) == 0))
      {
	if (!m->is_futex)
	  {
	    if (m->n_miss > m->n_miss_limit)
	      {
#if MUTEXEE_PRINT == 1 
		printf("[MUTEXEE] n_miss = %d  > %d :: switch to mutex\n", m->n_miss, m->n_miss_limit);
#endif
		m->n_spins = MUTEXEE_SPIN_TRIES_LOCK_MIN;
		m->n_spins_unlock = MUTEXEE_SPIN_TRIES_UNLOCK_MIN;
		m->is_futex = 1;
	      }
	  }
	else
	  {
	    unsigned int re = m->retry_spin_every;
	    if (m->is_futex++ == re)
	      {
		if (re < MUTEXEE_RETRY_SPIN_EVERY_MAX)
		  {
		    re <<= 1;
		  }
		m->retry_spin_every = re;
		/* m->n_miss_limit++; */
		if (m->n_miss_limit < MUTEXEE_FUTEX_LIM_MAX)
		  {
		    m->n_miss_limit++;
		  }
		m->is_futex = 0;
#if MUTEXEE_PRINT == 1 
		printf("[MUTEXEE] TRY :: switch to spinlock\n");
#endif
		m->n_spins = MUTEXEE_SPIN_TRIES_LOCK;
		m->n_spins_unlock = MUTEXEE_SPIN_TRIES_UNLOCK;
	      }
	  }
	m->n_miss = 0;
      }
  }


  static inline int
  mutexee_unlock(mutexee_lock_t* m)
  {
    /* Locked and not contended */
    if ((m->l.u == 1) && (mutexee_cas(&m->l.u, 1, 0) == 1)) 
      {
	return 0;
      }

    MUTEXEE_ADAP(mutexee_lock_training(m););

    /* Unlock */
    m->l.b.locked = 0;
    asm volatile ("mfence");

    if (m->l.b.locked) 
      {
	return 0;
      }

    asm volatile ("mfence");
#if MUTEXEE_ADAP == 1
    mutexee_cdelay(m->n_spins_unlock);
#else
    mutexee_cdelay(MUTEXEE_SPIN_TRIES_UNLOCK);
#endif
    asm volatile ("mfence");
    if (m->l.b.locked)
      {
    	return 0;
      }

    /* We need to wake someone up */
    m->l.b.contended = 0;

    MUTEXEE_ADAP(m->n_miss++;);
    sys_futex(m, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
    return 0;
  }

  static inline int
  mutexee_lock_trylock(mutexee_lock_t* m)
  {
    unsigned c = mutexee_swap_uint8(&m->l.b.locked, 1);
    if (!c) return 0;
    return EBUSY;
  }

#if 0
  /* ******************************************************************************** */
  /* condition variables */
  /* ******************************************************************************** */

  static inline int
  upmutex_cond1_init(upmutex_cond1_t* c, const pthread_condattr_t* a)
  {
    (void) a;
  
    c->m = NULL;
  
    /* Sequence variable doesn't actually matter, but keep valgrind happy */
    c->seq = 0;
  
    return 0;
  }

  static inline int 
  upmutex_cond1_destroy(upmutex_cond1_t* c)
  {
    /* No need to do anything */
    (void) c;
    return 0;
  }

  static inline int
  upmutex_cond1_signal(upmutex_cond1_t* c)
  {
    /* We are waking someone up */
    atomic_add(&c->seq, 1);
  
    /* Wake up a thread */
    sys_futex(&c->seq, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
  
    return 0;
  }

  static inline int
  upmutex_cond1_broadcast(upmutex_cond1_t* c)
  {
    mutexee_lock_t* m = c->m;
  
    /* No mutex means that there are no waiters */
    if (!m) return 0;
  
    /* We are waking everyone up */
    atomic_add(&c->seq, 1);
  
    /* Wake one thread, and requeue the rest on the mutex */
    sys_futex(&c->seq, FUTEX_REQUEUE_PRIVATE, 1, (struct timespec *) INT_MAX, m, 0);
  
    return 0;
  }

  static inline int
  upmutex_cond1_wait(upmutex_cond1_t* c, mutexee_lock_t* m)
  {
    int seq = c->seq;

    if (c->m != m)
      {
	if (c->m) return EINVAL;
	/* Atomically set mutex inside cv */
	__attribute__ ((unused)) int dummy = (uintptr_t) mutexee_cas(&c->m, NULL, m);
	if (c->m != m) return EINVAL;
      }
  
    mutexee_unlock(m);
  
    sys_futex(&c->seq, FUTEX_WAIT_PRIVATE, seq, NULL, NULL, 0);
  
    while (mutexee_swap_uint32(&m->l.b.locked, 257) & 1)
      {
	sys_futex(m, FUTEX_WAIT_PRIVATE, 257, NULL, NULL, 0);
      }
  
    return 0;
  }

  static inline int
  mutexee_cond_timedwait(upmutex_cond1_t* c, mutexee_lock_t* m, const struct timespec* ts)
  {
    int ret = 0;
    int seq = c->seq;

    if (c->m != m)
      {
	if (c->m) return EINVAL;
	/* Atomically set mutex inside cv */
	__attribute__ ((unused)) int dummy = (uintptr_t) mutexee_cas(&c->m, NULL, m);
	if (c->m != m) return EINVAL;
      }
  
    mutexee_unlock(m);

    struct timespec rt;
    /* Get the current time.  So far we support only one clock.  */
    struct timeval tv;
    (void) gettimeofday (&tv, NULL);

    /* Convert the absolute timeout value to a relative timeout.  */
    rt.tv_sec = ts->tv_sec - tv.tv_sec;
    rt.tv_nsec = ts->tv_nsec - tv.tv_usec * 1000;
  
    if (rt.tv_nsec < 0)
      {
	rt.tv_nsec += 1000000000;
	--rt.tv_sec;
      }
    /* Did we already time out?  */
    if (__builtin_expect (rt.tv_sec < 0, 0))
      {
	ret = ETIMEDOUT;
	goto timeout;
      }
  
    sys_futex(&c->seq, FUTEX_WAIT_PRIVATE, seq, &rt, NULL, 0);
  
    (void) gettimeofday (&tv, NULL);
    rt.tv_sec = ts->tv_sec - tv.tv_sec;
    rt.tv_nsec = ts->tv_nsec - tv.tv_usec * 1000;
    if (rt.tv_nsec < 0)
      {
	rt.tv_nsec += 1000000000;
	--rt.tv_sec;
      }

    if (rt.tv_sec < 0)
      {
	ret = ETIMEDOUT;
      }

  timeout:
    while (mutexee_swap_uint32(&m->l.b.locked, 257) & 1)
      {
	sys_futex(m, FUTEX_WAIT_PRIVATE, 257, NULL, NULL, 0);
      }

    return ret;
  }

  static inline int
  mutexee_lock_timedlock(mutexee_lock_t* l, const struct timespec* ts)
  {
    fprintf(stderr, "** warning -- pthread_mutex_timedlock not implemented\n");
    return 0;
  }
#endif
#endif

