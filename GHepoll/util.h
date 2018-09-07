#ifndef __UTIL_H_
#define __UTIL_H_ 
#include <stdio.h>


enum {
    LOG_LEVEL_EMERG = 0,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
};
#define LOG_LEVEL_NUM   5

#define CHECK_FMT(a,b) __attribute__((format(printf, a, b)))
#define _debug(fmt, ...)  util_log(LOG_LEVEL_DEBUG, __FILE__":%d " fmt"\n", __LINE__,  ##__VA_ARGS__)
#define _info(fmt, ...)   util_log(LOG_LEVEL_INFO, __FILE__":%d " fmt"\n", __LINE__,  ##__VA_ARGS__)
#define _warn(fmt, ...)   util_log(LOG_LEVEL_WARN, __FILE__":%d " fmt"\n", __LINE__,  ##__VA_ARGS__)
#define _error(fmt, ...)  util_log(LOG_LEVEL_ERROR, __FILE__":%d " fmt"\n", __LINE__,  ##__VA_ARGS__)
#define _emerg(fmt, ...)  do { util_log(LOG_LEVEL_EMERG, __FILE__":%d " fmt"\n", __LINE__,  ##__VA_ARGS__);exit(1);}while(0)

void util_set_log_level (int level);
int util_log(int level, const char *fmt, ...) CHECK_FMT(2,3) ;
void* xmalloc(size_t size);
void* xzalloc(size_t size);
void* xrealloc(void *ptr, size_t size);
int get_monotonic(struct timeval *tv);
int set_nonblock (int fd);
int set_cloexec (int fd); 

#endif

