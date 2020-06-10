#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include "tool_option.h"
#include "tool_util.h"
#include "tool_log.h"
#include "tool_dns.h"

/*******************************************************
 * int getopt_long(int argc, char * const argv[],
 *                 const char *optstring,
 *                 const struct option *longopts,
 *                 int *longindex);
 **********************************************************/

const char *optstr = "hvd:t:T:";

const struct option long_opt[] = {
	{"help",    0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
    {"dns",     1, NULL, 'd'},
    {"timestamp convert time", 1, NULL, 't'},
    {"time Convert timestamp", 1, NULL, 'T'},
	{0,0,0,0}
};

#define print_opt_help(opt_index, help_str)             \
    do { \
        printf("\t--%s\t\t-%c\t%s", long_opt[opt_index].name, (char)long_opt[opt_index].val, help_str); \
    } while (0)

void usage()
{
    printf("\nUsage:\n");
    print_opt_help(0, "request help\n");
    print_opt_help(1, "request version\n");
    print_opt_help(2, "request domain ip\n");
    print_opt_help(3, "timestamp convert %Y-%m-%d %H:%M:%S\n");
    print_opt_help(4, "%Y-%m-%d %H:%M:%S convert timestamp\n");

    printf("\n\nExamples:\n");
    printf("\t./%s -d baidu.com\t---\trequest domain ip \n", PROCESS_NAME);
    printf("\t./%s -T \"2018-6-17 00:00:00\"\t---\trequest timestamp \n", PROCESS_NAME);
}


int parse_args(int argc, char **argv, void **data)
{
	int c;

    while ((c = getopt_long(argc, argv, optstr, long_opt, NULL)) != -1) {
        switch (c) {
            case 'h':
                usage();
                break;
            case 'v':
                printf("miniTool 1.0.0\n");
                break;
            case 'd':
            {
                // char *domain = optarg;
                if (!is_ture_domain(optarg))
                    return PARSE_ERROR;

                // domain_dns = domain;
                *data = strdup(optarg);
                return  PARSE_DNS;
            }
            case 't':
            {
                unsigned int timestamp = strtoul(optarg, NULL, 10);
                // printf("%u\n", timestamp);
                *data = malloc(sizeof(unsigned int));

                unsigned int *a = (unsigned int*)*data;
                *a = timestamp;
                return  PARSE_TIMESTAMP_CHANGEOVER;
            }
            case 'T':
            {
                // int len = strlen(optarg) + 1;
                // *data = calloc(1, len);

                // char *str = (char*)*data;
                *data = strdup(optarg);

                // strncpy(str, optarg, len);
                return PARSE_TIME_CHANGEOVER;
            }
            default:
                usage();
        }
    }

	return 0;
}

