#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tool_log.h"
#include "tool_util.h"
#include "tool_option.h"
#include "tool_dns.h"


void timestamp_convert(void *userdata)
{
    char *buff = NULL;
    time_t *data = (time_t*)userdata;
    timestamp2str(*data, &buff);
    printf("%s\n", buff);
    if(buff) free(buff);
}

void time_convert(void *userdata)
{
    char *data = (char*)userdata;
    time_t timesec = str2timestamp(data);
    if (timesec < 0) {LOGG_WARN("input data not valid.");}
    else printf("%ld\n", timesec);
}

int main(int argc, char **argv)
{
    int type = 0;
    void *userdata = NULL;

    if (argc < 2) {
        usage();exit(1);
    }

    type = parse_args(argc, argv, &userdata);
    switch (type) {
        case PARSE_DNS:
            check_dns(userdata);
            break;
        case PARSE_TIMESTAMP_CHANGEOVER:
            timestamp_convert(userdata);
            break;
        case PARSE_TIME_CHANGEOVER:
            time_convert(userdata);
            break;
        case PARSE_ERROR:
            break;
        default:
            ;
    }

    if (userdata)
        free(userdata);

    return 0;
}
