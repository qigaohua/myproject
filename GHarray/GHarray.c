/**
 * @file GHarray.c
 * @brief  自定义各种类型的数组 
 * @author qigaohua, qigaohua168@163.com
 * @version 1.0.0
 * @date 2018-05-17
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "GHarray.h"


#ifdef _DEBUG_
#define _array_print(fd, fmt, ...)             \
    fprintf(fd, "%s:%d " fmt"\r\n", __FILE__, __LINE__,  ##__VA_ARGS__)
#else 
#define _array_print(fd, fmt, ...)
#endif


#define _check_param(x, ret)                           \
    do {                                               \
        if (x) {                                       \
            _array_print(stderr, "Invalid param.");    \
            errno = EINVAL;                            \
            return ret;                                \
        } \
    } while (0)                                        



/**
 * @brief gh_array_create 
 *
 * @param size 每个数据块大小
 * @param n    数据块的数量
 * @param func 释放数据时的回调函数，主要释放用户申请的内存, 可以为NULL
 *
 * @return  
 */
gh_array_t *gh_array_create(size_t size, int n, handle_callback func)
{
    gh_array_t *array;


    array = (gh_array_t *)malloc(sizeof(gh_array_t));
    if (NULL == array) {
        _array_print(stderr, "malloc falied : %m.");
        return NULL;
    }
    memset(array, 0, sizeof(gh_array_t));

    array->d = malloc(size * n);
    if (NULL == array->d) {
        _array_print(stderr, "malloc falied : %m.");
        free (array); return NULL;
    }
    memset(array->d, 0, size * n);

    array->alloc = n;
    array->size = size;
    array->useds = 0;
    array->callback = func;

    _array_print(stdout, "array alloc success: %zu @%d", size, n);
    return array;
}


int gh_array_destory (gh_array_t *array)
{
    _check_param(!array, -1);

    if (array->d) {
        if (array->callback) {
            void *d ;
            int i = 0;
            for (; i < array->useds; i ++) {
                d = (char *)array->d + i * array->size;
                array->callback(d);
            }
        }

        free (array->d);
    }
    free (array);

    return 0;
}


void *gh_array_push (gh_array_t *array)
{
    _check_param(!array, NULL);

    if (array->d) {
        void *alloc;

        if (array->useds == array->alloc) {
            /*bug fix: 避免申请失败, 引发的内存泄露 */
            void *p = realloc(array->d, array->alloc * array->size * 2); 
            if (NULL == p) {
                _array_print(stderr, "realloc failed [%m]");
                return NULL;
            }
            array->d = p;

            array->alloc *= 2;
            _array_print(stdout, "array realloc success: %zu @%d",
                    array->size, array->alloc);
        }

        alloc = (char *)array->d + array->useds * array->size;
        array->useds ++;

        return alloc;
    }

    _array_print(stderr, "array push failed."); 
    return NULL;
}


void *gh_array_push_n (gh_array_t *array, int n)
{
    _check_param((!array || n <= 0), NULL);

    if (array->d) {
        void *alloc;

        if (array->useds + n > array->alloc) {
            /* bug fix: 避免申请失败, 引发的内存泄露 */
            void *p = realloc(array->d, 
                    (array->alloc + n) * 2 * array->size);
            if (NULL == p) {
                _array_print(stderr, "realloc failed [%m]");
                return NULL;
            }
            array->d = p;

            array->alloc = (array->alloc + n) * 2;
            _array_print(stdout, "array realloc success: %zu @%d", 
                    array->size, array->alloc);
        }

        alloc = (char *)array->d + array->useds * array->size;
        array->useds += n;

        return alloc;
    }

    _array_print(stderr, "array push failed."); 
    return NULL;
}




/***************************************************************************/
/*                            GHarray test                                 */
/***************************************************************************/

#define TEST
#ifdef TEST

typedef struct test_s {
    int   i;
    short j;
    char  *a;  // 测试回调函数
    char str[16];
} test_t;


void test_free(void *data)
{
    test_t *t = (test_t *)data;

    if (t->a)
        free(t->a);
}


int main ()
{
    int i = 0;
    gh_array_t *array;

    array = gh_array_create(sizeof(test_t), 10, test_free);

    for (; i < 11; i ++) {
        test_t *t = (test_t *)gh_array_push(array);
        t->i = i;
        t->j = i + 1000;

        t->a = (char *)malloc (16);

        strncpy(t->str, "GHarray push", sizeof("GH_array push"));
    }

    test_t *nt = (test_t *)gh_array_push_n(array, 10);
    for (i = 0; i < 10; nt = nt + 1, i ++) {
        nt->i = 12345;
        nt->j = 11111;

        nt->a = (char *)malloc (16);

        strncpy(nt->str, "GHarray push n", sizeof("GH_array push n"));
    }

    for (i = 0; i < array->useds; i ++) {
        test_t *t = (test_t *)((char *)array->d + i * array->size);

        printf("i: %d j: %d  str: %s\n", t->i, t->j, t->str);
    }


    gh_array_destory(array);

    return 0;
}



#endif
