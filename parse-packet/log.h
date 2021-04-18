#ifndef __LOG_H__
#define __LOG_H__

// color
#if defined (__WIN32__) || defined (WIN32) || defined (_MSC_VER)
#define B_RED(str)      str
#define B_GREEN(str)    str
#define B_YELLOW(str)   str
#define B_BLUE(str)     str
#define B_MAGENTA(str)  str
#define B_CYAN(str)     str
#define B_WHITE(str)    str
#define RED(str)        str
#define GREEN(str)      str
#define YELLOW(str)     str
#define BLUE(str)       str
#define MAGENTA(str)    str
#define CYAN(str)       str
#define WHITE(str)      str
#else
#define FG_BLACK        30
#define FG_RED          31
#define FG_GREEN        32
#define FG_YELLOW       33
#define FG_BLUE         34
#define FG_MAGENTA      35
#define FG_CYAN         36
#define FG_WHITE        37
#define BG_BLACK        40
#define BG_RED          41
#define BG_GREEN        42
#define BG_YELLOW       43
#define BG_BLUE         44
#define BG_MAGENTA      45
#define BG_CYAN         46
#define BG_WHITE        47
#define B_RED(str)      "\033[1;31m" str "\033[0m"
#define B_GREEN(str)    "\033[1;32m" str "\033[0m"
#define B_YELLOW(str)   "\033[1;33m" str "\033[0m"
#define B_BLUE(str)     "\033[1;34m" str "\033[0m"
#define B_MAGENTA(str)  "\033[1;35m" str "\033[0m"
#define B_CYAN(str)     "\033[1;36m" str "\033[0m"
#define B_WHITE(str)    "\033[1;37m" str "\033[0m"
#define RED(str)        "\033[31m" str "\033[0m"
#define GREEN(str)      "\033[32m" str "\033[0m"
#define YELLOW(str)     "\033[33m" str "\033[0m"
#define BLUE(str)       "\033[34m" str "\033[0m"
#define MAGENTA(str)    "\033[35m" str "\033[0m"
#define CYAN(str)       "\033[36m" str "\033[0m"
#define WHITE(str)      "\033[37m" str "\033[0m"
#endif


#define GH_LOG_ERROR    0
#define GH_LOG_WARN     1
#define GH_LOG_MSG      2
#define GH_LOG_DEBUG    3
#define GH_LOG_MAX      4

// #define MAX_LINE  5000
// #define KEEP_LINE 500
#define LOG_FILE_MAXSIZE  50 * 1024 * 1024
// #define LOG_FILE_MAXSIZE  100  // for test

#define __USE_SYSLOG__  /* 打印日志到syslog */


#define CHECK_FMT(a,b) __attribute__((format(printf, a, b)))

// typedef void (*log_print_func)(int, const char*);
typedef void (*log_exit_func)(int);

void log_error(int errcode, const char *file, int line, const char *fmt, ...) CHECK_FMT(4, 5);
void log_xerror(int errcode,  const char *file, int line, const char *fmt, ...) CHECK_FMT(4, 5);
void log_warn(const char *file, int line, const char *fmt, ...) CHECK_FMT(3,4);
void log_xwarn(const char *file, int line, const char *fmt, ...) CHECK_FMT(3,4);
void log_xmsg(const char *file, int line, const char *fmt, ...) CHECK_FMT(3,4);
void log_debug(const char *file, int line, const char *fmt, ...) CHECK_FMT(3,4);

// void log_recold_file(int level, const char *file, int line, const char *fmt, ...);
// void log_set_print_cb(log_print_func cb);
void log_set_exit_cb(log_exit_func cb);

int log_init(int level, const char *logfile);


#define loge(...) log_error(EXIT_FAILURE, __FILE__, __LINE__,  __VA_ARGS__)
#define logxe(...) log_xerror(EXIT_FAILURE, __FILE__, __LINE__,  __VA_ARGS__)
#define logw(...) log_warn(__FILE__, __LINE__,  __VA_ARGS__)
#define logxw(...) log_xwarn(__FILE__, __LINE__,  __VA_ARGS__)
#define logm(...) log_xmsg(__FILE__, __LINE__,  __VA_ARGS__)
#define logd(...) log_debug(__FILE__, __LINE__,  __VA_ARGS__)



#endif
