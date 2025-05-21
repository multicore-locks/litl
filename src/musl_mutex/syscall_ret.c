#include "syscall.h"
#include <errno.h>
// #include <stdio.h>

long __syscall_ret(unsigned long r)
{
	// fprintf(stderr, "Error __syscall_ret.\n");
	if (r > -4096UL) {
		// errno = -r;
		return -1;
	}
	return r;
}
