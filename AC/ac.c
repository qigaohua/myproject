#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ac.h"



/**
 * @brief ac_machine_create 创建AC自动机
 *
 * @return 失败：NULL  成功：AC_MACHINE_p
 */
AC_MACHINE_p ac_machine_create()
{
    AC_MACHINE_p ac_machine;

    ac_machine  = (AC_MACHINE_p) malloc(sizeof(AC_MACHINE_t));
    if (!ac_machine) return NULL;

    ac_machine->root = (AC_NODE_p) malloc(sizeof(AC_NODE_t));
    if (ac_machine->root)
        memset(ac_machine->root, 0, sizeof(AC_NODE_t));
    else {
        free(ac_machine);
        return NULL;
    }

    ac_machine->pattern = NULL;;
    ac_machine->pattern_count = 0;
    ac_machine->pattern_capacity = 0;
    ac_machine->last_node = NULL;
    ac_machine->position = 0;
    ac_machine->work_mode = AC_WORKING_MODE_SEARCH;
    ac_machine->is_open = 1;

    return ac_machine;
}


/**
 * @brief ac_root_free 释放Trie树，内部被ac_machine_destory调用
 *
 * @param ac_node
 */
static void ac_root_free(AC_NODE_p ac_node)
{
    int i;
    if (ac_node) {
        for(i = 0; i < KIND; i++) {
            if (ac_node->next[i])
                ac_root_free(ac_node->next[i]);
        }
        free(ac_node);
    }
}



/**
 * @brief ac_machine_destory 销毁AC自动机
 *
 * @param ac_machine
 */
void ac_machine_destory(AC_MACHINE_p ac_machine)
{
    int i;
    if (ac_machine) {
        ac_root_free(ac_machine->root);

        for (i = 0; i < ac_machine->pattern_count; i ++)
            free((void*)ac_machine->pattern[i].data);
        free(ac_machine->pattern);
        free(ac_machine);
    }
}


static int ac_grow_pattern_vector(AC_MACHINE_p ac_machine)
{
    size_t grow = ac_machine->pattern_capacity == 0 ? 8 : ac_machine->pattern_capacity * 2;

    if (ac_machine->pattern_capacity == 0) {
        ac_machine->pattern_capacity = grow;
        ac_machine->pattern = (AC_PATTERN_p) malloc(ac_machine->pattern_capacity * sizeof(AC_PATTERN_t));
        if (!ac_machine->pattern) return -1;
    }
    else {
        AC_PATTERN_p p = ac_machine->pattern;
        ac_machine->pattern_capacity += grow;
        ac_machine->pattern = (AC_PATTERN_p) realloc(ac_machine->pattern, ac_machine->pattern_capacity * sizeof(AC_PATTERN_t));
        if (!ac_machine->pattern) {
            ac_machine->pattern = p;
            return -1;
        }
    }

    return 0;
}


// 构建字典树, 添加模式
int ac_add_pattern(AC_MACHINE_p ac_machine, const char *str)
{
    int i, slen;
    unsigned char index;

    if (!ac_machine || !str ) return AC_PARAMETER_ERROR;
    if (!ac_machine->is_open)
        return AC_MACHINE_IS_CLOSED;

    AC_NODE_p p = ac_machine->root;
    slen = strlen(str);
    if (slen <= 0 || slen > MAX_STRING_LENGTH) return AC_STRING_LENGTH_ERROR;

    for (i = 0; i < slen; i++) {
        // index = str[i] - 'a';
        index = str[i];
        if (index > KIND - 1) return AC_PATTERN_LIMIT_ERROR;
        if (p->next[index] == NULL) {
            p->next[index] = (AC_NODE_p) malloc(sizeof(AC_NODE_t));
            memset(p->next[index], 0, sizeof(AC_NODE_t));
        }
        p = p->next[index];
    }

    // 如果模式已经存在，返回
    if (p->final) 
        return AC_DUPLICATE_PATTERN_ERROR;
    

    p->final = 1; // 设置1，代表一个模式的结束
    p->pattern_no = ac_machine->pattern_count;

    if (ac_machine->pattern_count == ac_machine->pattern_capacity) 
        ac_grow_pattern_vector(ac_machine);

    // 把该模式保存起来，方便以后用到
    ac_machine->pattern[p->pattern_no].data = strdup(str);
    ac_machine->pattern[p->pattern_no].len = slen;
    ac_machine->pattern_count ++;

    return AC_SECCESS;
}


// 设置failure指针
static int ac_set_failure(AC_MACHINE_p ac_machine)
{
    int i;
    int tail = 0, head = 0;
    AC_NODE_p p;
    AC_NODE_p ac_node_queue[50000];

    AC_NODE_p root = ac_machine->root;
    root->failure = NULL;
    ac_node_queue[head ++] = root;
    while (head != tail) {
        AC_NODE_p tmp = ac_node_queue[tail ++];
        
        for (i = 0; i < KIND; i ++) {
            if (tmp->next[i] != NULL) {
                if (tmp == root) // Trie 树第二层的失败节点都为根节点root 
                    tmp->next[i]->failure = root;
                else {
                    p = tmp->failure;
                    while (p) {
                        if (p->next[i]) {
                            tmp->next[i]->failure = p->next[i];
                            break;
                        }
                        p = p->failure;
                    }
                    if (p == NULL)
                        tmp->next[i]->failure = root;
                }
                ac_node_queue[head ++] = tmp->next[i];
            }
        } 
    }

    return AC_SECCESS;
}

// 把所有模式添加完后，调用，调用此函数后，不可再添加模式
int ac_machine_finalize(AC_MACHINE_p ac_machine)
{
    if (!ac_machine) return AC_PARAMETER_ERROR;

    ac_set_failure(ac_machine);
    // 禁止再向ac机中添加模式(pattern)
    ac_machine->is_open = 0;

    return AC_SECCESS;
}


static void ac_machine_reset(AC_MACHINE_p ac_machine)
{
    ac_machine->last_node = ac_machine->root;
    ac_machine->position = 0;
}


void ac_machine_settext(AC_MACHINE_p ac_machine, const char *text)
{
    ac_machine_reset(ac_machine);

    ac_machine->text.str = text;
    ac_machine->text.len = strlen(text);
}


int ac_machine_search(AC_MACHINE_p ac_machine, AC_MATCH_p match)
{
    size_t position = 0;
    unsigned char index;
    AC_NODE_p p_node;
    AC_TEXT_t text = ac_machine->text;

    if (!ac_machine || !text.str) return AC_PARAMETER_ERROR;
    if (ac_machine->is_open) return AC_MACHINE_IS_OPEN;
    if (ac_machine->work_mode == AC_WORKING_MODE_FINDNEXT)
        position = ac_machine->position;
    p_node = ac_machine->last_node;

    ac_machine_reset(ac_machine);

    while (position < text.len) {
        // index = str[position] - 'a';
        index = text.str[position];
        if (p_node->next[index] == NULL) {
            if (p_node == ac_machine->root)
                position ++;
            else 
                p_node = p_node->failure;
        }
        else {
            p_node = p_node->next[index];
            position ++;
        }

        if (p_node->final == 1) {
            // printf("match : %s\n", ac_machine->pattern[p_node->pattern_no].data);
            match->pattern = &ac_machine->pattern[p_node->pattern_no];
            match->position = position - match->pattern->len; 
            match->pattern_no = p_node->pattern_no;

            if (ac_machine->work_mode == AC_WORKING_MODE_FINDNEXT) {
                ac_machine->position = position;
                ac_machine->last_node = p_node;
            }
            return AC_SECCESS;
        }
    }

    return AC_TEXT_NO_PATTERN;
}


AC_MATCH_t ac_machine_findnext(AC_MACHINE_p ac_machine)
{
    AC_MATCH_t match;

    ac_machine->work_mode = AC_WORKING_MODE_FINDNEXT;
    match.pattern_no = -1;

    ac_machine_search(ac_machine, &match);

    ac_machine->work_mode = AC_WORKING_MODE_SEARCH;

    return match;
}

#define TEST
#ifdef TEST
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
int main()
{
    int i;
    // char haystack[] = "ushers测试下ABC12345";
    // char needle[][255]={
    //     "she","he","ABC", "his","hers"
    // };
    char needle[][255]={
        "KMP算法","字典树","AC自动机", "测试","失败指针"
    };

    AC_MACHINE_p ac_machine = ac_machine_create();
    AC_MATCH_t match;

    for (i = 0; i < (int)(sizeof(needle) / sizeof(needle[0])); i ++) {
        ac_add_pattern(ac_machine, needle[i]);
    }
    ac_machine_finalize(ac_machine);

    char buf[1024];
    int fd = open("test.txt", O_RDONLY);

    while (read(fd, buf, 1024)) {
        ac_machine_settext(ac_machine, buf);
        while((match = ac_machine_findnext(ac_machine)).pattern_no != -1) {
            printf("模式: %s  位置: %lu  序号: %d\n", match.pattern->data, match.position, match.pattern_no);
        }
        memset(buf, 0, 1024);
    }


    // ac_machine_search(ac_machine, &match);
    // printf("%s  %lu  %d\n", match.pattern->data, match.position, match.pattern_no);
    // ac_machine_search(ac_machine, &match);
    // printf("%s  %lu  %d\n", match.pattern->data, match.position, match.pattern_no);

    ac_machine_destory(ac_machine);

    return 0;
}



#endif








