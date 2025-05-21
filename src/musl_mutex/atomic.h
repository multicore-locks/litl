#ifndef _ATOMIC_H
#define _ATOMIC_H

#include "stdint.h"
#include "atomic_archx86_64.h"

#ifndef a_pre_llsc
#define a_pre_llsc()
#endif

#ifndef a_post_llsc
#define a_post_llsc()
#endif

#ifndef a_cas
#define a_cas a_cas
static inline int a_cas(volatile int *p, int t, int s)
{
	int old;
	a_pre_llsc();
	do old = a_ll(p);
	while (old==t && !a_sc(p, s));
	a_post_llsc();
	return old;
}
#endif

#ifndef a_swap
#define a_swap a_swap
static inline int a_swap(volatile int *p, int v)
{
	int old;
	a_pre_llsc();
	do old = a_ll(p);
	while (!a_sc(p, v));
	a_post_llsc();
	return old;
}
#endif

#endif


#ifndef a_cas
#error missing definition of a_cas
#endif

#ifndef a_swap
#define a_swap a_swap
static inline int a_swap(volatile int *p, int v)
{
	int old;
	do old = *p;
	while (a_cas(p, old, v) != old);
	return old;
}
#endif

#ifndef a_inc
#define a_inc a_inc
static inline void a_inc(volatile int *p)
{
	a_fetch_add(p, 1);
}
#endif

#ifndef a_dec
#define a_dec a_dec
static inline void a_dec(volatile int *p)
{
	a_fetch_add(p, -1);
}
#endif

#ifndef a_store
#define a_store a_store
static inline void a_store(volatile int *p, int v)
{
#ifdef a_barrier
	a_barrier();
	*p = v;
	a_barrier();
#else
	a_swap(p, v);
#endif
}
#endif

#ifndef a_barrier
#define a_barrier a_barrier
static void a_barrier()
{
	volatile int tmp = 0;
	a_cas(&tmp, 0, 0);
}
#endif

#ifndef a_spin
#define a_spin a_barrier
#endif