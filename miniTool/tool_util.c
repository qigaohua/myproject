#define _XOPEN_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "tool_log.h"


// 域名限制 (63letters).(63 letters).(63 letters).(62 letters)
int is_ture_domain(char *domain)
{
    int doit_count = 0;
    int each_paragraph_count = 0;
    int len = 0;
    char *p;

    len = strlen(domain);
    if (len < 4 || len > 255) {
        LOGG_WARN("domain not valid, maxlen is 255");
        return 0;
    }

    p = domain + len - 1;
    while(len--) {
        if (isalnum(*p) || *p == '-') {
            each_paragraph_count ++;
            if (doit_count == 0) {
                if (each_paragraph_count > 62) {
                    LOGG_WARN("domain not valid.");
                    return 0;
                }
            } else {
                if (each_paragraph_count > 63) {
                    LOGG_WARN("domain not valid.");
                    return 0;
                }
            }
        } else if (*p == '.') {
            doit_count ++;

            /* .com  '.' 开始的域名 */
            if (doit_count > 3 || len == 0) {
                LOGG_WARN("domain not valied.");
                return 0;
            }
            each_paragraph_count = 0;

        } else {
            LOGG_WARN("domain contains unlawful characters");
            return 0;
        }

        p --;
    }

    return 1;
}


char* timestamp2str(time_t timesec, char **buf)
{
    struct tm *t;
    char strbuff[128] = {0};

    if (timesec < 0) {
        LOGG_WARN("timesec param not valied.");
        return NULL;
    }

    t = localtime(&timesec);
    strftime(strbuff, sizeof(strbuff), "%Y-%m-%d %H:%M:%S", t);

    int len = strlen(strbuff) + 1;
    *buf = (char*)malloc(len);
    if (*buf == NULL)
        LOG_ERROR("malloc failed.");
    strncpy(*buf, strbuff, len);

    return *buf;
}

time_t str2timestamp(const char *timestr)
{
    struct tm t;
    time_t timesec = 0;

    if (!timestr) return -1;

    if (strptime(timestr, "%Y-%m-%d %H:%M:%S", &t) == NULL) {
        LOGG_WARN("input time format error(2000-11-11 00:00:00): %s", timestr);
        return -1;
    }
    timesec = mktime(&t);

    return timesec;
}





