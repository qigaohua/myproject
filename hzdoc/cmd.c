#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>


const char *optstr = "hvf:t:i::u";

const struct option long_opt[] = {
    {"help",    0, NULL, 'h'},
    {"vertion", 0, NULL, 'v'},
    {"file",    1, NULL, 'f'},
    {"title",   1, NULL, 't'},
    {"info",    1, NULL, 'i'},
    {"update",  0, NULL, 'u'},
    {0,0,0,0}
};


extern char *cmd_file;
extern char *cmd_title;
extern char cmd_info;
extern char *cmd_info_file;
extern char cmd_update;
extern char cmd_error;

extern char *usage;

int option_parse(char argc, char **argv)
{
    int c;

    while ((c = getopt_long(argc, argv, optstr, long_opt, NULL)) != -1)
    {
        switch (c)
        {
            case 'h':
                printf("%s\n", usage);
                break;

            case 'v':
                printf("hzdoc 1.0.0\n");
                break;

            case 'f':
                cmd_file = strdup(optarg);
                break;

            case 't':
                cmd_title = strdup(optarg);
                break;

            case 'i':
                cmd_info = 1;
                if (optarg) cmd_info_file = strdup(optarg);
                break;

            case 'u':
                cmd_update = 1;
                break;

            default:
                cmd_error = 1;
                ;
        }
    }

    return 0;
}




