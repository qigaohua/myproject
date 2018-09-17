#ifndef __GH_ARRAY_H
#define __GH_ARRAY_H 
#include <stdlib.h>



typedef struct gh_array_s gh_array_t;
typedef void (*handle_callback)(void *data);

struct gh_array_s {
    int    alloc;
    int    useds; 
    size_t size;
    void   *d;
    handle_callback callback;
};



/* API */

gh_array_t *gh_array_create(size_t size, int n, handle_callback func);
int gh_array_destory (gh_array_t *array);
void *gh_array_push (gh_array_t *array);
void *gh_array_push_n (gh_array_t *array, int n);

#endif
