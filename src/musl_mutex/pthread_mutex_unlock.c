#include "pthread_impl.h"
#include <stdio.h>

int __pthread_musl_mutex_unlock(__pthread_mutex_t *m, musl_context_t *me)
{
	// fprintf(stderr, "Error __pthread_musl_mutex_unlock.\n");
	unsigned long self;
	int waiters = m->_m_waiters;
	int cont;
	int type = m->_m_type & 15;
	int priv = (m->_m_type & 128) ^ 128;
	int new = 0;
	int old;

	if (type != PTHREAD_MUTEX_NORMAL) {
		// fprintf(stderr, "type != PTHREAD_MUTEX_NORMAL\n");
		// self = __pthread_self();
		old = m->_m_lock;
		int own = old & 0x3fffffff;
		// if (own != self->tid)
		// 	return EPERM;
		if ((type&3) == PTHREAD_MUTEX_RECURSIVE && m->_m_count) {
			// fprintf(stderr, "type&3 == PTHREAD_MUTEX_RECURSIVE && m->_m_count\n");
			return m->_m_count--, 0;
		}
		if ((type&4) && (old&0x40000000)) {
			new = 0x7fffffff;
		}
		if (!priv) {
			// self->robust_list.pending = &m->_m_next;
			// fprintf(stderr, "!priv\n");
			__vm_lock();
		}
		// volatile void *prev = m->_m_prev;
		// volatile void *next = m->_m_next;
		// *(volatile void *volatile *)prev = next;
		// if (next != &self->robust_list.head) *(volatile void *volatile *)
		// 	((char *)next - sizeof(void *)) = prev;
	}
	if (type&8) {
		if (old<0 || a_cas(&m->_m_lock, old, new)!=old) {
			if (new) a_store(&m->_m_waiters, -1);
			__syscall(SYS_futex, &m->_m_lock, FUTEX_UNLOCK_PI|priv);
		}
		cont = 0;
		waiters = 0;
	} else {
		cont = a_swap(&m->_m_lock, new);
	}
	if (type != PTHREAD_MUTEX_NORMAL && !priv) {
		// self->robust_list.pending = 0;
		// fprintf(stderr, "type != PTHREAD_MUTEX_NORMAL && !priv\n");
		__vm_unlock();
	}
	if (waiters || cont<0)
		__wake(&m->_m_lock, 1, priv);
	
	// fprintf(stderr, "return 0 58;\n");
	return 0;
}

// weak_alias(__pthread_musl_mutex_unlock, pthread_mutex_unlock);
