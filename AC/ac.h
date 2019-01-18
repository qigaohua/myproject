#ifndef __QGH_AC_H
#define __QGH_AC_H 
#include <stdlib.h>


#define KIND 256 // '0' = 48  'A' = 65 'a' = 97
#define BOOL int
#define False (0)
#define True (!(False))
#define MAX_STRING_LENGTH 1024

typedef struct ac_node AC_NODE_t, *AC_NODE_p;
typedef struct ac_machine AC_MACHINE_t, *AC_MACHINE_p;

struct ac_node {
    AC_NODE_t *next[KIND]; // 类似于字典树  
    AC_NODE_t *failure;    // 类似于kmp, 匹配失败时跳转的节点
    int final;      // 是否是一个字符串的结束
    int pattern_no; // 模式序号, 通过这个可以获得模式的详细信息
};

typedef struct ac_text {
    const char *str;
    size_t len;
} AC_TEXT_t;

typedef struct ac_pattern {
    const char *data;
    size_t len;
    // AC_PATTERN_p next;
} AC_PATTERN_t, *AC_PATTERN_p;

typedef struct ac_match {
    AC_PATTERN_p pattern;
    int pattern_no;
    size_t position;
} AC_MATCH_t, *AC_MATCH_p;

struct ac_machine {
    AC_NODE_p root;

    int pattern_count;     // 当前模式数量 
    int pattern_capacity;  // 总的容量
    AC_PATTERN_t *pattern; //保存所有添加的模式, 动态数组

    AC_NODE_p last_node;
    AC_TEXT_t text;
    size_t position;

    int work_mode; // enum ac_working_mode
    BOOL is_open;
};

typedef enum ac_working_mode
{
    AC_WORKING_MODE_SEARCH = 0, /* default */
    AC_WORKING_MODE_FINDNEXT,
} AC_WORKING_MODE_t;

enum {
    AC_SECCESS = 0,
    AC_STRING_LENGTH_ERROR,
    AC_PARAMETER_ERROR,
    AC_DUPLICATE_PATTERN_ERROR,
    AC_PATTERN_LIMIT_ERROR,
    AC_MACHINE_IS_CLOSED,
    AC_MACHINE_IS_OPEN,
    AC_TEXT_NO_PATTERN,
};


AC_MACHINE_p ac_machine_create();
void ac_machine_destory(AC_MACHINE_p ac_machine);
int ac_add_pattern(AC_MACHINE_p ac_machine, const char *str);
int ac_machine_finalize(AC_MACHINE_p ac_machine);
void ac_machine_settext(AC_MACHINE_p ac_machine, const char *text);
int ac_machine_search(AC_MACHINE_p ac_machine, AC_MATCH_p match);
AC_MATCH_t ac_machine_findnext(AC_MACHINE_p ac_machine);


#endif
