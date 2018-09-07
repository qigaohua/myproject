#ifndef __LOG_H__
#define __LOG_H__ 
#include <syslog.h>


#define GH_LOG_ERROR    (1 << 0)
#define GH_LOG_WARN     (1 << 1)
#define GH_LOG_MSG      (1 << 2)
#define GH_LOG_DEBUG    (1 << 3)

#define MAX_LINE  5000
#define KEEP_LINE 500

#define CHECK_FMT(a,b) __attribute__((format(printf, a, b)))

typedef void (*log_print_func)(int, const char*);
typedef void (*log_exit_func)(int);

void log_error(int errcode, const char *fmt, ...) CHECK_FMT(2, 3);
void log_xerror(int errcode, const char *fmt, ...) CHECK_FMT(2, 3);
void log_warn(const char *fmt, ...) CHECK_FMT(1,2);
void log_xwarn(const char *fmt, ...) CHECK_FMT(1,2);
void log_xmsg(const char *fmt, ...) CHECK_FMT(1,2);
void log_recold_file(int severity, const char *file, const char *fmt, ...) CHECK_FMT(3, 4);
void log_set_print_cb(log_print_func cb);
void log_set_exit_cb(log_exit_func cb);


void log_debug(const char *fmt, ...);


#define LOG_ERROR(fmt, ...) \
    do { \
        syslog(LOG_ERR, "[%s][%d]:" fmt"\n", __FILE__, __LINE__,  ##__VA_ARGS__);\
        log_error(1, "[%s:%d] " fmt, __FILE__, __LINE__,  ##__VA_ARGS__); \
    } while(0);

#define LOGG_INFO(fmt, ...) \
    do { \
        syslog(LOG_INFO, "[%s][%d]:" fmt"\n", __FILE__, __LINE__,  ##__VA_ARGS__);\
        log_xmsg("[%s:%d] " fmt, __FILE__, __LINE__,  ##__VA_ARGS__); \
    } while(0);

#define LOGG_WARN(fmt, ...) \
    do { \
        syslog(LOG_INFO, "[%s][%d]:" fmt"\n", __FILE__, __LINE__,  ##__VA_ARGS__);\
        log_xwarn("[%s:%d] " fmt, __FILE__, __LINE__,  ##__VA_ARGS__); \
    } while(0);
#endif
