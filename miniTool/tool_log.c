#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#include "tool_log.h"



log_print_func log_print_cb = NULL;
log_exit_func  log_exit_cb = NULL;


void log_set_print_cb(log_print_func cb)
{
    log_print_cb = cb;
}

/* 设置自定义error类型退出函数，默认exit() */
void log_set_exit_cb(log_exit_func cb)
{
    log_exit_cb = cb;
}

int get_file_lines(const char *file)
{
    char c, lc = 0;
    int line_nums = 0;

    /* get file nums */
    FILE *fp = fopen(file, "r");
    if (!fp) {
        return -1;
    }
    while((c = fgetc(fp)) != EOF) {
        if (c == '\n') line_nums++;
        lc = c;
    }
    if (lc != '\n') line_nums++;
    fclose(fp);

    return line_nums;
}

int System(char *cmd)
{
    int ret = -1;
    
    if (!cmd) {
        log_warn("param null.");
        return -1;
    }
    
    ret = system(cmd);
    if (ret == -1) {
        log_debug("System() failed. [cmd:%s]", cmd);
    } else {
        if (WIFEXITED(ret)) { /* normal exit script ? */
            ret = WEXITSTATUS(ret);
            if (ret != 0) {
                log_debug("run shell script fail,  [cmd:%s] [exit code: %d]", cmd, ret);
            } else {
                log_debug("System run ok, [cmd : %s]", cmd);
            }
        } else {
            ret = WEXITSTATUS(ret);
            log_debug("shell script [%s] exit, status = [%d]", cmd, ret);
        }
    }
    
    return ret;
} 

int truncate_file(const char *file, int truncate_line)
{
    char cmd[256] = {0};

    if (truncate_line > 0) {
        snprintf(cmd, sizeof(cmd), "sed -i \'1,%dd\' %s", truncate_line,  file);
        if (System(cmd)) {
            log_warn("run cmd err.[cmd : %s]", cmd);
            return -1;
        }
    }

    return 0;
}

static void log_exit(int errcode)
{
    if (log_exit_cb) {
        log_exit_cb(errcode);
        exit(errcode);
    } else 
        exit(errcode);
}

static void log_print_of_severity(int severity, const char *msg, FILE* fp)
{
    if (log_print_cb) 
        log_print_cb(severity, msg);
    else {
        const char* severity_str;
        switch (severity) {
            case GH_LOG_ERROR:
                severity_str = "err";
                break;
            case GH_LOG_WARN:
                severity_str = "warn";
                break;
            case GH_LOG_MSG:
                severity_str = "msg";
                break;
            case GH_LOG_DEBUG:
                severity_str = "debug";
                break;
            default:
                severity_str = "???";
        }
        if (!fp) 
            fprintf(stderr, "<%s> %s\n", severity_str, msg);
        else
            fprintf(fp, "<%s> %s\n", severity_str, msg);
    }
}

static void log_print(int severity, const char *fmt,  const char *errstr, va_list ap, FILE* fp)
{
    char buff[1024] = {0};
    size_t len;
    
    if (fmt)
        vsnprintf(buff, sizeof(buff), fmt, ap);
    else 
        buff[0] = '\0';

    if (errstr) {
        len = strlen(buff);
        if (len < sizeof(buff) - 3) {
            snprintf(buff + len, sizeof(buff) - len, ": %s", errstr);
        }
    }

    log_print_of_severity(severity, buff, fp);
}

void log_error(int errcode, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_ERROR, fmt, strerror(errno), ap, NULL);
    va_end(ap);
    log_exit(errcode);
}

void log_xerror(int errcode, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_ERROR, fmt, NULL, ap, NULL);
    va_end(ap);
    log_exit(errcode);
}


void log_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_WARN, fmt, strerror(errno), ap, NULL);
    va_end(ap);
}


void log_xwarn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_WARN, fmt, NULL, ap, NULL);
    va_end(ap);
}


void log_xmsg(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_MSG, fmt, NULL, ap, NULL);
    va_end(ap);
}

#ifdef __DEBUG__
void log_debug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    log_print(GH_LOG_DEBUG, fmt, strerror(errno), ap, NULL);
    va_end(ap);
}
#else 
void log_debug(const char *fmt, ...)
{
    (void)fmt;
}

#endif


void log_recold_file(int severity, const char *file, const char *fmt, ...)
{
    int line;
    FILE *fp = NULL;
    va_list ap;

    if (!file) return;

    line = get_file_lines(file);
    if (line > MAX_LINE)
        truncate_file(file, line - KEEP_LINE); 
        
    fp = fopen(file, "a+");
    if (!fp) 
        log_error(1, "open file failed.");

    va_start(ap, fmt);
    if (severity & GH_LOG_MSG)
        log_print(severity, fmt, NULL, ap, fp);
    else 
        log_print(severity, fmt, strerror(errno), ap, fp);
        
    va_end(ap);
}

#if 0
int main()
{
    log_debug("debug_test");
    log_xmsg("xmsg_test");
    log_warn("warn_test");
    log_xwarn("xwarn_test");
    log_recold_file(GH_LOG_MSG, "log.txt", "%s", "recode file test");

    LOGG_INFO("log_info test");
    LOG_ERROR("log_error test");

    log_xerror(1, "xerror test");
    
    log_xmsg("no print");

    return 0;
}
#endif
