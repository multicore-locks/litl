#ifndef LIBC_H
#define LIBC_H

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#define hidden __attribute__((visibility("hidden")))

struct __locale_map;

struct __locale_struct {
	const struct __locale_map *cat[6];
};

struct tls_module {
	struct tls_module *next;
	void *image;
	size_t len, size, align, offset;
};

struct __libc {
	char can_do_threads;
	char threaded;
	char secure;
	volatile signed char need_locks;
	int threads_minus_1;
	size_t *auxv;
	struct tls_module *tls_head;
	size_t tls_size, tls_align, tls_cnt;
	size_t page_size;
	struct __locale_struct global_locale;
};

#ifndef PAGE_SIZE
#define PAGE_SIZE libc.page_size
#endif

extern hidden struct __libc __libc;
#define libc __libc

void __init_libc(char **, char *);
void __init_tls(size_t *);
void __init_ssp(void *);
void __libc_start_init(void);
void __funcs_on_exit(void);
void __funcs_on_quick_exit(void);
void __libc_exit_fini(void);
void __fork_handler(int);

extern size_t __hwcap;
extern size_t __sysinfo;
extern char *__progname, *__progname_full;

extern hidden const char __libc_version[];

hidden void __synccall(void (*)(void *), void *);
hidden int __setxid(int, int, int, int);

#endif
