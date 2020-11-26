#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <fcntl.h>

#include "util.h"


/********************************log***********************************/
static int g_local_level = LOG_LEVEL_INFO;
static const char *log_level_type[] = {
    "emerg",
    "error",
    "warn",
    "info",
    "debug",
};

void util_set_log_level (int level)
{
    if (level < 0 || level >= LOG_LEVEL_NUM) {
        printf("Invailed prarm\n");
        exit(EXIT_FAILURE);
    }
    
    g_local_level = level;
}

int util_log (int level, const char *fmt, ...) 
{
    uint32_t cur_len = 0;
    char wbuff[1024] = {0};

    if (level < 0 || level >= LOG_LEVEL_NUM) {
        return -1;
    }

    if (g_local_level < level) 
        return 0;
    
    time_t t = time(NULL);
    struct tm tm;
    va_list valist;

    tzset();
    localtime_r(&t, &tm);
    strftime(wbuff, sizeof(wbuff), "[%Y-%m-%d %H:%M:%S] ", &tm);
    cur_len = strlen(wbuff);

    snprintf(wbuff + cur_len, sizeof(wbuff)-cur_len-1, "%s ", log_level_type[level]);
    cur_len =  strlen(wbuff);

    va_start(valist, fmt);
    vsnprintf(wbuff + cur_len, sizeof(wbuff) - cur_len - 1, fmt, valist);
    va_end(valist);

    fprintf(stdout, wbuff, strlen(wbuff));

    return 0;
}


/********************************memory*******************************************/
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

/*******************************time**********************************/
int get_monotonic(struct timeval *tv)
{
    struct timespec ts;

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        _warn("clock_gettime[CLOCK_MONOTONIC] failed %m");
        return gettimeofday(tv, NULL);
    }

    tv->tv_sec = ts.tv_sec;
    tv->tv_usec = ts.tv_nsec / 1000 ;

    return 0;
}

/********************************描述符**************************************/

int set_nonblock (int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1 ||
            (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)) {
        _error("set_nonblock failed.");
        return -1;
    }

    return 0;
}

int set_cloexec (int fd) 
{
    int flags;

    if ((flags = fcntl(fd, F_GETFD, 0)) == -1 ||
            fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1 ) {
        _error("set_cloexec failed %m.");
        return -1;
    }

    return 0;
}

#if 0
int main()
{
    util_set_log_level(LOG_LEVEL_ERROR);

    _debug("it is debug msg");
    _info("it is info msg");
    _warn("it is warn msg");
    _error("it is error msg");
    _emerg("it is emerg msg");
}
#endif
