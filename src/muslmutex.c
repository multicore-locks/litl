#include <stdio.h>
#include <stdlib.h>
#include <muslmutex.h>
#include <assert.h>
#include <pthread.h>
#include "interpose.h"
#include "utils.h"
#include "musl_mutex/pthread_musl.h"
#include "musl_mutex/pthread_impl.h"
#include "musl_mutex/pthread_self_glibc.h"
#include "musl_mutex/pthread_setcancelstate_glibc.h"

musl_mutex_t *musl_mutex_create(const __pthread_mutexattr_t *attr) {
    musl_mutex_t *impl = (musl_mutex_t*) calloc(1, sizeof(musl_mutex_t));

    // #if COND_VAR
    //     REAL(__pthread_mutex_init)(&impl->lock, attr);
    // #endif

    return impl;
}

int musl_mutex_destroy(musl_mutex_t *lock) {
    // #if COND_VAR
    //     REAL(__pthread_mutex_destroy)(lock);
    // #endif
    free(lock);
    return 0;
}

// int musl_cond_init(musl_cond_t *cond, const pthread_condattr_t *attr) {
//     fprintf(stderr, "musl_cond_init\n");
// #if COND_VAR
//     return REAL(pthread_cond_init)(cond, attr);
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

// int musl_cond_timedwait(musl_cond_t *cond, musl_mutex_t *lock, musl_context_t *UNUSED(me),
//                        const struct timespec *ts) {
//     fprintf(stderr, "musl_cond_timedwait\n");
// #if COND_VAR
//     int res;
//     if (ts)
//         res = REAL(pthread_cond_timedwait)(cond, &lock->lock, ts);
//     else
//         res = REAL(pthread_cond_wait)(cond, &lock->lock);

//     return res;
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

// int musl_cond_wait(musl_cond_t *cond, musl_mutex_t *lock, musl_context_t *UNUSED(me)) {
//     fprintf(stderr, "musl_cond_wait\n");
// #if COND_VAR
//     int res = REAL(pthread_cond_wait)(cond, &lock->lock);
//     return res;
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

// int musl_cond_signal(musl_cond_t *cond) {
//     fprintf(stderr, "musl_cond_signal\n");
// #if COND_VAR
//     return REAL(pthread_cond_signal)(cond);
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

// int musl_cond_broadcast(musl_cond_t *cond) {
//     fprintf(stderr, "musl_cond_broadcast\n");
// #if COND_VAR
//     return REAL(pthread_cond_broadcast)(cond);
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

// int musl_cond_destroy(musl_cond_t *cond) {
//     fprintf(stderr, "musl_cond_destroy\n");
// #if COND_VAR
//     return REAL(pthread_cond_destroy)(cond);
// #else
//     fprintf(stderr, "Error cond_var not supported.");
//     assert(0);
// #endif
// }

void musl_thread_start(void) {
}

void musl_thread_exit(void) {
}

void musl_application_init(void) {
}

void musl_application_exit(void) {
}

void musl_init_context(lock_mutex_t *impl,
                           lock_context_t *context,
                           int number) {
}

int __pthread_musl_cond_wait(pthread_cond_t *restrict c, __pthread_mutex_t *restrict m, musl_context_t *restrict me)
{
	return __pthread_musl_cond_timedwait(c, m, me, 0);
}

struct waiter {
	struct waiter *prev, *next;
	volatile int state, barrier;
	volatile int *notify;
};

/* Self-synchronized-destruction-safe lock functions */

static inline void lock(volatile int *l)
{
	if (a_cas(l, 0, 1)) {
		a_cas(l, 1, 2);
		do __wait(l, 0, 2, 1);
		while (a_cas(l, 0, 2));
	}
}

static inline void unlock(volatile int *l)
{
	if (a_swap(l, 0)==2)
		__wake(l, 1, 1);
}

static inline void unlock_requeue(volatile int *l, volatile int *r, int w)
{
	a_store(l, 0);
	if (w) __wake(l, 1, 1);
	else __syscall(SYS_futex, l, FUTEX_REQUEUE|FUTEX_PRIVATE, 0, 1, r) != -ENOSYS
		|| __syscall(SYS_futex, l, FUTEX_REQUEUE, 0, 1, r);
}

enum {
	WAITING,
	SIGNALED,
	LEAVING,
};

int __pthread_musl_cond_timedwait(musl_cond_t *restrict c, musl_mutex_t *restrict m, musl_context_t *restrict me, const struct timespec *restrict ts)
{
	struct waiter node = { 0 };
	int e, seq, clock = c->_c_clock, cs, shared=0, oldstate, tmp;
	volatile int *fut;

	if ((m->_m_type&15) && (m->_m_lock&INT_MAX) != pthread_self_glibc())
		return EPERM;

	if (ts && ts->tv_nsec >= 1000000000UL)
		return EINVAL;

	// fprintf(stderr, "__pthread_testcancel 170\n");
	pthread_testcancel(); // TODO: Add this back

	if (c->_c_shared) {
		shared = 1;
		fut = &c->_c_seq;
		seq = c->_c_seq;
		a_inc(&c->_c_waiters);
	} else {
		lock(&c->_c_lock);

		seq = node.barrier = 2;
		fut = &node.barrier;
		node.state = WAITING;
		node.next = c->_c_head;
		c->_c_head = &node;
		if (!c->_c_tail) c->_c_tail = &node;
		else node.next->prev = &node;

		unlock(&c->_c_lock);
	}

	__pthread_musl_mutex_unlock(m, me);

	pthread_setcancelstate_glibc(PTHREAD_CANCEL_MASKED, &cs);
	if (cs == PTHREAD_CANCEL_DISABLE) pthread_setcancelstate_glibc(cs, 0);

	do e = __timedwait_cp(fut, seq, clock, ts, !shared);
	while (*fut==seq && (!e || e==EINTR));
	if (e == EINTR) e = 0;

	if (shared) {
		/* Suppress cancellation if a signal was potentially
		 * consumed; this is a legitimate form of spurious
		 * wake even if not. */
		if (e == ECANCELED && c->_c_seq != seq) e = 0;
		if (a_fetch_add(&c->_c_waiters, -1) == -0x7fffffff)
			__wake(&c->_c_waiters, 1, 0);
		oldstate = WAITING;
		goto relock;
	}

	oldstate = a_cas(&node.state, WAITING, LEAVING);

	if (oldstate == WAITING) {
		/* Access to cv object is valid because this waiter was not
		 * yet signaled and a new signal/broadcast cannot return
		 * after seeing a LEAVING waiter without getting notified
		 * via the futex notify below. */

		lock(&c->_c_lock);
		
		if (c->_c_head == &node) c->_c_head = node.next;
		else if (node.prev) node.prev->next = node.next;
		if (c->_c_tail == &node) c->_c_tail = node.prev;
		else if (node.next) node.next->prev = node.prev;
		
		unlock(&c->_c_lock);

		if (node.notify) {
			if (a_fetch_add(node.notify, -1)==1)
				__wake(node.notify, 1, 1);
		}
	} else {
		/* Lock barrier first to control wake order. */
		lock(&node.barrier);
	}

relock:
	/* Errors locking the mutex override any existing error or
	 * cancellation, since the caller must see them to know the
	 * state of the mutex. */
	if ((tmp = __pthread_musl_mutex_lock(m, me))) e = tmp;

	if (oldstate == WAITING) goto done;
    
	if (!node.next && !(m->_m_type & 8))
		a_inc(&m->_m_waiters);

	/* Unlock the barrier that's holding back the next waiter, and
	 * either wake it or requeue it to the mutex. */
	if (node.prev) {
		int val = m->_m_lock;
		if (val>0) a_cas(&m->_m_lock, val, val|0x80000000);
		unlock_requeue(&node.prev->barrier, &m->_m_lock, m->_m_type & (8|128));
	} else if (!(m->_m_type & 8)) {
		a_dec(&m->_m_waiters);		
	}

	/* Since a signal was consumed, cancellation is not permitted. */
	if (e == ECANCELED) e = 0;

done:
	pthread_setcancelstate_glibc(cs, 0);

	if (e == ECANCELED) {
        fprintf(stderr, "__pthread_testcancel 266\n");
		// __pthread_testcancel(); // TODO: Add this back
        pthread_testcancel();
		pthread_setcancelstate_glibc(PTHREAD_CANCEL_DISABLE, 0);
	}

	return e;
}

int __private_cond_signal(musl_cond_t *c, int n)
{
	struct waiter *p, *first=0;
	volatile int ref = 0;
	int cur;

	lock(&c->_c_lock);
	for (p=c->_c_tail; n && p; p=p->prev) {
		if (a_cas(&p->state, WAITING, SIGNALED) != WAITING) {
			ref++;
			p->notify = &ref;
		} else {
			n--;
			if (!first) first=p;
		}
	}
	/* Split the list, leaving any remainder on the cv. */
	if (p) {
		if (p->next) p->next->prev = 0;
		p->next = 0;
	} else {
		c->_c_head = 0;
	}
	c->_c_tail = p;
	unlock(&c->_c_lock);

	/* Wait for any waiters in the LEAVING state to remove
	 * themselves from the list before returning or allowing
	 * signaled threads to proceed. */
	while ((cur = ref)) __wait(&ref, 0, cur, 1);

	/* Allow first signaled waiter, if any, to proceed. */
	if (first) unlock(&first->barrier);

	return 0;
}

weak_alias(__pthread_cond_timedwait, pthread_cond_timedwait);

int __pthread_musl_cond_signal(musl_cond_t *c)
{
	if (!c->_c_shared) return __private_cond_signal(c, 1);
	if (!c->_c_waiters) return 0;
	a_inc(&c->_c_seq);
	__wake(&c->_c_seq, 1, 0);
	return 0;
}

int __pthread_musl_cond_broadcast(musl_cond_t *c)
{
	if (!c->_c_shared) return __private_cond_signal(c, -1);
	if (!c->_c_waiters) return 0;
	a_inc(&c->_c_seq);
	__wake(&c->_c_seq, -1, 0);
	return 0;
}

int __pthread_musl_cond_destroy(musl_cond_t *c)
{
	if (c->_c_shared && c->_c_waiters) {
		int cnt;
		a_or(&c->_c_waiters, 0x80000000);
		a_inc(&c->_c_seq);
		__wake(&c->_c_seq, -1, 0);
		while ((cnt = c->_c_waiters) & 0x7fffffff)
			__wait(&c->_c_waiters, 0, cnt, 0);
	}
	return 0;
}

int __pthread_musl_cond_init(musl_cond_t *restrict c, const __pthread_condattr_t *restrict a)
{
	*c = (musl_cond_t){0};
	if (a) {
		c->_c_clock = a->__attr & 0x7fffffff;
		if (a->__attr>>31) c->_c_shared = (void *)-1;
	}
	return 0;
}
