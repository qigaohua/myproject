#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>
#include <ctype.h>

#include "util.h"

/* 0 ~ 65536 的随机数 */
uint16_t random_uint16(void)
{
    srand((unsigned)time(NULL));
    return (uint16_t)rand() % 65536;
}

int copy_uint16(void *dst, void *src)
{
    ((uint8_t*)dst)[0] = ((uint8_t *)src)[0];
    ((uint8_t*)dst)[1] = ((uint8_t *)src)[1];

    return 2;
}

int copy_uint32(void *dst, void *src)
{
    ((uint8_t*)dst)[0] = ((uint8_t *)src)[0];
    ((uint8_t*)dst)[1] = ((uint8_t *)src)[1];
    ((uint8_t*)dst)[2] = ((uint8_t *)src)[2];
    ((uint8_t*)dst)[3] = ((uint8_t *)src)[3];

    return 4;
}

void* xmalloc(size_t size)
{
    void *value = malloc(size);

    if (NULL != value)
        return value;

    syslog(LOG_ERR, "malloc() failed (%m)");
    exit(EXIT_FAILURE);
}


void* xzalloc(size_t size)
{
    void *value = xmalloc(size);

    memset(value, 0, size);
    return value;
}

void* xrealloc(void *ptr, size_t size)
{
    void *value = realloc(ptr, size);

    if (NULL != value)
        return value;

    syslog(LOG_ERR, "realloc() failed (%m)");
    exit(EXIT_FAILURE);
}

void dump_line(FILE *fp, const char *addr, const size_t len)
{
    size_t i;
    for (i = 0; i < 16; i++) {
       if (i < len) 
          fprintf(fp, "%02X ", *(uint8_t *)&addr[i]); 
       else 
          fprintf(fp, ".. "); 

       if (!((i+1) % 8))
          fprintf(fp, " | "); 
    }
    printf ("\t");

    for(i = 0; i < 16; i ++) {
        char c = 0x7f & *(uint8_t *)&addr[i];
        if (i < len && isprint(addr[i])) 
            fprintf(fp, "%c", c); 
        else 
            fprintf(fp, "."); 

        if (!((i+1) % 8))
            fprintf(fp, " "); 
    }
}

void dump(FILE *out, const char *buff, size_t len)
{
    size_t i;
    for (i = 0; i < len; i += 16) {
        dump_line(out, buff + i, ((len - i)) < 16 ? (len - i) : 16);
        printf ("\n");
    }
}

int clock_monotonic;
/* Handy function to get the time.
 * We only care about time advancements, not the actual time itself
 * Which is why we use CLOCK_MONOTONIC, but it is not available on all
 * platforms.
 */
#define NO_MONOTONIC "host does not support a monotonic clock - timing can skew"
int
get_monotonic(struct timeval *tp)
{
	static int posix_clock_set = 0;
#if defined(_POSIX_MONOTONIC_CLOCK) && defined(CLOCK_MONOTONIC)
	struct timespec ts;
	static clockid_t posix_clock;

	if (!posix_clock_set) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
			posix_clock = CLOCK_MONOTONIC;
			clock_monotonic = posix_clock_set = 1;
		}
	}

	if (clock_monotonic) {
		if (clock_gettime(posix_clock, &ts) == 0) {
			tp->tv_sec = ts.tv_sec;
			tp->tv_usec = ts.tv_nsec / 1000;
			return 0;
		}
	}
#endif

	/* Something above failed, so fall back to gettimeofday */
	if (!posix_clock_set) {
		syslog(LOG_WARNING, NO_MONOTONIC);
		posix_clock_set = 1;
	}
	return gettimeofday(tp, NULL);
}


#ifdef __DAEMON__
void daemon_init() 
{
    int ret, i;
    pid_t pid;
    struct sigaction sa;

    ret = umask(0);
    pid = fork();
    if (pid < 0) {
        exit(1);
    } else if (pid != 0) {
        exit(0);
    }

    ret = setsid();
    if (ret == ((pid_t) -1)) {
        exit(1);
    }

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    ret = sigaction(SIGHUP, &sa, NULL);
    if (ret < 0) {
        exit(1);
    }

    pid = fork();
    if (pid < 0) {
        exit(1);
    } else if (pid != 0) {
        exit(0);
    }

    ret = chdir("/");
    if (ret) {
        exit(1);
    }
    return;
}
#endif

