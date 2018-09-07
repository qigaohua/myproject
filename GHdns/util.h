#ifndef __UTIL_H_
#define __UTIL_H_ 
#include <stdio.h>
#include <inttypes.h>
#include <sys/time.h>

#define UNCONST(a)		((void *)(unsigned long)(const void *)(a))

#define timeval_to_double(tv) ((tv)->tv_sec * 1.0 + (tv)->tv_usec * 1.0e-6)
#define timernorm(tvp)							\
	do {								\
		while ((tvp)->tv_usec >= 1000000) {			\
			(tvp)->tv_sec++;				\
			(tvp)->tv_usec -= 1000000;			\
		}							\
	} while (0 /* CONSTCOND */);

#if __GNUC__ > 2 || defined(__INTEL_COMPILER)
# define _noreturn __attribute__((__noreturn__))
# define _packed   __attribute__((__packed__))
# define _unused   __attribute__((__unused__))
#else
# define _noreturn
# define _packed
# define _unused
#endif

extern int clock_monotonic;
int get_monotonic(struct timeval *);
int writepid(int, pid_t);

void* xmalloc(size_t size);
void* xzalloc(size_t size);
void* xrealloc(void *ptr, size_t size);
void daemon_init(); 
uint16_t random_uint16(void);
int copy_uint16(void *dst, void *src);
int copy_uint32(void *dst, void *src);
void dump(FILE *out, const char *buff, size_t len);
void dump_line(FILE *fp, const char *addr, const size_t len);

#endif

