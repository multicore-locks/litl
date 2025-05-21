#include "pthread_impl.h"
#include "pthread_self_glibc.h"
#include <stdio.h>
#include <assert.h>

int __pthread_musl_mutex_trylock_owner(__pthread_mutex_t *m)
{
	// fprintf(stderr, "Error pthread_musl_mutex_trylock_owner.\n");
	int old, own;
	int type = m->_m_type;
	// pthread_t self = pthread_self();
	unsigned long tid = pthread_self_glibc();

	old = m->_m_lock;
	own = old & 0x3fffffff;
	if (own == tid) {
		if ((type&8) && m->_m_count<0) {
			old &= 0x40000000;
			m->_m_count = 0;
			goto success;
		}
		if ((type&3) == PTHREAD_MUTEX_RECURSIVE) {
			if ((unsigned)m->_m_count >= INT_MAX) return EAGAIN;
			m->_m_count++;
			return 0;
		}
	}
	if (own == 0x3fffffff) {
		// fprintf(stderr, "return ENOTRECOVERABLE 29;\n");
		return ENOTRECOVERABLE;
	} 
	if (own || (old && !(type & 4))) {
		// fprintf(stderr, "return EBUSY 33;\n");
		return EBUSY;
	} 

	//Work with robust_list
	/*
	if (type & 128) {
		if (!self->robust_list.off) {
			self->robust_list.off = (char*)&m->_m_lock-(char *)&m->_m_next;
			__syscall(SYS_set_robust_list, &self->robust_list, 3*sizeof(long));
		}
		if (m->_m_waiters) tid |= 0x80000000;
		self->robust_list.pending = &m->_m_next;
	}
	*/
	tid |= old & 0x40000000;

	if (a_cas(&m->_m_lock, old, tid) != old) {
		//self->robust_list.pending = 0;
		if ((type&12)==12 && m->_m_waiters) {
			// fprintf(stderr, "return ENOTRECOVERABLE 53;\n");
			return ENOTRECOVERABLE;
		}
		// fprintf(stderr, "return EBUSY 56;\n");
		return EBUSY;
	}

success:
	if ((type&8) && m->_m_waiters) {
		int priv = (type & 128) ^ 128;
		__syscall(SYS_futex, &m->_m_lock, FUTEX_UNLOCK_PI|priv);
		//self->robust_list.pending = 0;
		// fprintf(stderr, "return (type&4) ? ENOTRECOVERABLE : EBUSY;\n");
		return (type&4) ? ENOTRECOVERABLE : EBUSY;
	}
	
	/*
	volatile void *next = self->robust_list.head;
	m->_m_next = next;
	m->_m_prev = &self->robust_list.head;
	if (next != &self->robust_list.head) *(volatile void *volatile *)
		((char *)next - sizeof(void *)) = &m->_m_next;
	self->robust_list.head = &m->_m_next;
	self->robust_list.pending = 0;
	*/

	if (old) {
		m->_m_count = 0;
		// fprintf(stderr, "return EOWNERDEAD 81;\n");
		return EOWNERDEAD;
	}

	// fprintf(stderr, "return 0;\n");
	return 0;
}

int __pthread_musl_mutex_trylock(__pthread_mutex_t *m, musl_context_t *me)
{
	// fprintf(stderr, "Error __pthread_musl_mutex_trylock.\n");
	// fprintf(stderr, "Error cond_var not supported.");
    // assert(1);
	// return 0;
	if ((m->_m_type&15) == PTHREAD_MUTEX_NORMAL) {
		// fprintf(stderr, "return a_cas(&m->_m_lock, 0, EBUSY) & EBUSY;\n");
		return a_cas(&m->_m_lock, 0, EBUSY) & EBUSY;
	}

	// fprintf(stderr, "return __pthread_mutex_trylock_owner(m);\n");
	return __pthread_musl_mutex_trylock_owner(m);
}
