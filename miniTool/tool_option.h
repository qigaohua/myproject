#ifndef __TOOL_OPTION_
#define __TOOL_OPTION_ 


enum {
    PARSE_ERROR = -1,
    PARSE_DNS = 1,
    PARSE_TIMESTAMP_CHANGEOVER = 2,
    PARSE_TIME_CHANGEOVER = 3,
};



void usage(); 
int parse_args(int argc, char **argv, void **data);




#endif
