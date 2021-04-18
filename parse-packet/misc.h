#ifndef __MISC_H__
#define __MISC_H



#define PPktReturnNULL return NULL

#define CHECK_ARGS(x, ret) { \
    if (!(x))  { \
        logxw("Args has error."); \
        return ret; \
    } \
}

#define MAIN_DEBUG
#ifdef MAIN_DEBUG
#define xstr(s) str(s)
#define str(s) #s

#define BUG_ON(x) do {      \
        if (((x))) {                \
            fprintf(stderr, "BUG ON at %s:%d(%s)\r\n", __FILE__,__LINE__, __func__);    \
            fprintf(stderr, "Error code : %s\r\n", xstr(x));                            \
            exit(1);                                                                    \
        }                                                                               \
    } while(0)
#else
#define BUG_ON(x)
#endif




#endif // __MISC_H
