#ifndef __TOOL_UTIL_
#define __TOOL_UTIL_ 
#include <time.h>

#define PROCESS_NAME "miniTool"

int is_ture_domain(char *domain);
char* timestamp2str(time_t timesec, char **buf);
time_t str2timestamp(const char *timestr);

#endif
