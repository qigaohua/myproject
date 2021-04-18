/**
 * @file log.c
 * @brief  打印日志
 * @author qigaohua, qigaohua168@163.com
 * @version 1.0.0
 * @date 2020-06-12
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <time.h>

#include "log.h"



const char* g_level_str[] = {
    "ERROR",
    "WARN",
    "INFO",
    "DEBUG",
    NULL,
};


static log_exit_func  log_exit_cb = NULL;


static FILE* g_fp ;
static int   g_log_level = GH_LOG_MSG;
static char  log_dirpath[256];
static char  log_filename[256];



/* 设置自定义error类型退出函数，默认exit() */
void log_set_exit_cb(log_exit_func cb)
{
    log_exit_cb = cb;
}

#if 0

static int get_file_lines(const char *file)
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
        logw("param null.");
        return -1;
    }

    ret = system(cmd);
    if (ret == -1) {
        logd("System() failed. [cmd:%s]", cmd);
    } else {
        if (WIFEXITED(ret)) { /* normal exit script ? */
            ret = WEXITSTATUS(ret);
            if (ret != 0) {
                logd("run shell script fail,  [cmd:%s] [exit code: %d]", cmd, ret);
            } else {
                logd("System run ok, [cmd : %s]", cmd);
            }
        } else {
            ret = WEXITSTATUS(ret);
            logd("shell script [%s] exit, status = [%d]", cmd, ret);
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
            logw("run cmd err.[cmd : %s]", cmd);
            return -1;
        }
    }

    return 0;
}

#endif

static void log_exit(int errcode)
{
    if (log_exit_cb) {
        log_exit_cb(errcode);
        exit(errcode);
    } else
        exit(errcode);
}


static long get_logfile_size(FILE *fp)
{
    long size, curoffset;

    if ( !fp || fp == stderr)
        return -1;

    curoffset = ftell(fp);
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, curoffset, SEEK_SET);

    return size;
}



/**
 * @brief save_logfile 日志文件过大时，保存文件重命名，重新打开新的日志文件
 *
 * @param fp 日志文件描述符
 *
 * @return 新的日志文件描述符
 */
static FILE *save_logfile(FILE *fp)
{
    char new_filename[512] = {0};
    char datefmt[32] = {0};
    struct tm tm;

    if ( !fp || fp == stderr )
        return fp;

    if (-1 == chdir(log_dirpath))
        return fp;

    fflush(fp);
    if (fclose(fp) == EOF)
        return fp;

    time_t t = time(NULL);
    localtime_r(&t, &tm);
    // 日志量不大，去掉后面-%H:%M:%S
    strftime(datefmt, sizeof datefmt, "%Y%m%d-%H:%M:%S", &tm);
    snprintf(new_filename, sizeof new_filename, "%s.%s", log_filename, datefmt);
    if (-1 == rename(log_filename, new_filename)) {
        fprintf(stderr, "rename `%s' failed: %s\n", log_filename,
                strerror(errno));
#ifdef __USE_SYSLOG__
        syslog(LOG_ERR, "rename `%s' failed: %s\n", log_filename,
                strerror(errno));
#endif
        // 重命名失败，则过去日志没了
    }

    // 重新写
    fp = fopen(log_filename, "w");
    if ( !fp ) {
        // 不大可能
        fprintf(stderr, "fopen `%s' failed: %s\n", log_filename,
                strerror(errno));
        fp = stderr;
    }

    return fp;
}



/**
 * @brief log_print 日志打印
 *
 * @param level 日志级别
 * @param file   日志信息文件
 * @param line   日志信息行
 * @param errstr 系统错误信息
 * @param fmtbuf 用户打印信息
 *
 * @return
 */
static int log_print(int level, const char *file, int line,
        const char *errstr, const char *fmtbuf)
{
    char buff[1024] = {0};
    int len = 0;

    if ( !g_fp )
        g_fp = stderr;

#ifndef __USE_SYSLOG__
    if ( g_fp != stderr ) {
#endif
            len = snprintf(buff, sizeof buff, "[%7s]", g_level_str[level]);
            len += snprintf(buff + len, sizeof(buff)-len-1, " %s:%d", file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, " %s", fmtbuf);
            if (errstr)
                len += snprintf(buff + len, sizeof(buff) - len - 1, ": %s", errstr);
#ifndef __USE_SYSLOG__
    }
    else {
        switch (level) {
        case GH_LOG_ERROR:
            len = snprintf(buff, sizeof buff, B_RED("[%7s]"), g_level_str[GH_LOG_ERROR]);
            len += snprintf(buff + len, sizeof(buff)-len-1, RED(" %s:%d"), file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, RED(" %s"), fmtbuf);
            if (errstr)
            len += snprintf(buff + len, sizeof(buff) - len - 1, RED(": %s"), errstr);
            break;
        case GH_LOG_WARN:
            len = snprintf(buff, sizeof buff, B_YELLOW("[%7s]"), g_level_str[GH_LOG_WARN]);
            len += snprintf(buff + len, sizeof(buff)-len-1, YELLOW(" %s:%d"), file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, YELLOW(" %s"), fmtbuf);
            if (errstr)
            len += snprintf(buff + len, sizeof(buff) - len - 1, YELLOW(": %s"), errstr);
            break;
        case GH_LOG_MSG:
            len = snprintf(buff, sizeof buff, B_GREEN("[%7s]"), g_level_str[GH_LOG_MSG]);
            len += snprintf(buff + len, sizeof(buff)-len-1, GREEN(" %s:%d"), file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, GREEN(" %s"), fmtbuf);
            if (errstr)
            len += snprintf(buff + len, sizeof(buff) - len - 1, GREEN(": %s"), errstr);
            break;
        case GH_LOG_DEBUG:
            len = snprintf(buff, sizeof buff, B_WHITE("[%7s]"), g_level_str[GH_LOG_DEBUG]);
            len += snprintf(buff + len, sizeof(buff)-len-1, WHITE(" %s:%d"), file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, WHITE(" %s"), fmtbuf);
            if (errstr)
            len += snprintf(buff + len, sizeof(buff) - len - 1, WHITE(": %s"), errstr);
            break;
        default:
            len = snprintf(buff, sizeof buff, "[%7s]", "???");
            len += snprintf(buff + len, sizeof(buff)-len-1, " %s:%d", file, line);
            len += snprintf(buff + len, sizeof(buff)-len-1, " %s", fmtbuf);
            if (errstr)
            len += snprintf(buff + len, sizeof(buff) - len - 1, ": %s", errstr);
            ;
        }
    }
#endif
    buff[len] = '\0';

    long filesize = get_logfile_size(g_fp);
    if (filesize >= LOG_FILE_MAXSIZE) {
        g_fp = save_logfile(g_fp);
    }
    fprintf(g_fp, "%s\n", buff);
#ifdef __USE_SYSLOG__
    syslog(LOG_ERR, "%s\n", buff);
#endif

    return 0;
}

void log_error(int errcode, const char *file, int line, const char *fmt, ...)
{
    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};

    if (g_log_level < GH_LOG_ERROR)
        return;

    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        log_exit(errcode);
    }

    log_print(GH_LOG_ERROR, file, line,  strerror(errno), fmtbuf);
    log_exit(errcode);
}


void log_xerror(int errcode, const char *file, int line, const char *fmt, ...)
{
    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};

    if (g_log_level < GH_LOG_ERROR)
        return;

    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        log_exit(errcode);
    }

    log_print(GH_LOG_ERROR, file, line,  NULL, fmtbuf);
    log_exit(errcode);
}


void log_warn(const char *file, int line, const char *fmt, ...)
{
    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};

    if (g_log_level < GH_LOG_WARN)
        return;

    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        return ;
    }

    log_print(GH_LOG_WARN, file, line,  strerror(errno), fmtbuf);
}


void log_xwarn(const char *file, int line, const char *fmt, ...)
{
    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};

    if (g_log_level < GH_LOG_WARN)
        return;

    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        return ;
    }

    log_print(GH_LOG_WARN, file, line,  NULL, fmtbuf);
}


void log_xmsg(const char *file, int line, const char *fmt, ...)
{
    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};

    if (g_log_level < GH_LOG_MSG)
        return;

    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        return ;
    }

    log_print(GH_LOG_MSG, file, line, NULL, fmtbuf);
}


void log_debug(const char *file, int line,  const char *fmt, ...)
{
    if (g_log_level < GH_LOG_DEBUG)
        return;


    int ret;
    va_list ap;
    char fmtbuf[1024] = {0};


    va_start(ap, fmt);
    ret = vsnprintf(fmtbuf, sizeof fmtbuf, fmt, ap);
    va_end(ap);

    if (ret < 0) {
        fprintf(stderr, "%s:%d vsnprintf failed.\n", __FILE__, __LINE__);
        return ;
    }

    log_print(GH_LOG_DEBUG, file, line,  NULL, fmtbuf);
}


static int get_chdir(const char *logfile, char *dir, int size)
{
    char *p;
    int dirlen;

    if (!logfile || !dir)
        return -1;

    if ((p = strrchr(logfile, '/')) != NULL) {
        if (logfile[0] != '/') {
            fprintf(stderr, "%s: Not an absolute path.\n", logfile);
#ifdef __USE_SYSLOG__
            syslog(LOG_ERR, "%s: Not an absolute path.\n", logfile);
#endif
            return -1;
        }

        dirlen = p - logfile;
        if (dirlen > size) {
            fprintf(stderr, "Log path length too long.\n");
#ifdef __USE_SYSLOG__
            syslog(LOG_ERR, "Log path length too long.\n");
#endif
            return -2;
        }
        strncpy(dir, logfile, dirlen);
        dir[dirlen] = '\0';

        // get filename add by qgh
        strncpy(log_filename, logfile+dirlen+1, sizeof log_filename);

        return 1;
    }

    return 0;

}


int log_init(int level, const char *logfile)
{
    // char dir[256] = {0};

    if (logfile) {
        if (get_chdir(logfile, log_dirpath, sizeof log_dirpath) == 1) {
            if (access(log_dirpath, F_OK | W_OK) != 0) {
                fprintf(stderr, "%s: log path not exists.\n", log_dirpath);
#ifdef __USE_SYSLOG__
                syslog(LOG_ERR, "%s: log path not exists.\n", log_dirpath);
#endif
                return -1;
            }
        }
        g_fp = fopen(logfile, "w+");
        if ( !g_fp ) {
            fprintf(stderr, "fopen `%s' failed\n", logfile);
#ifdef __USE_SYSLOG__
            syslog(LOG_ERR, "fopen `%s' failed\n", logfile);
#endif
            return -2;
        }
    }
    else
        g_fp = stderr;

    g_log_level = level;

    return 0;
}

#if 0
int main()
{
    if (log_init(GH_LOG_DEBUG,
                "/home/qigaohua/work/gitcode/notes/codelib/log/l.txt"))
        exit(EXIT_FAILURE);

    logm("%s", log_dirpath);
    logm("%s", log_filename);

    logd("debug_test");
    logd(" ");
    logm("xmsg_test");
    logw("warn_test");
    logxw("xwarn_test");
    logxe("xerror test");

    return 0;
}
#endif
