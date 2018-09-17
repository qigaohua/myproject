#ifndef __GH_MEMPOOL_
#define __GH_MEMPOOL_ 
#include <stdlib.h>


// #define NEED_OTHER_ALIGNMENT
#define GH_DEFAULT_PAGESIZE             4096    /* 查看本机页大小shell命令: getconf PAGESIZE */
#define GH_MAX_ALLOC_MEMORY             ((GH_DEFAULT_PAGESIZE) - 1) 
#define GH_MEMPOOL_ALIGNMENT            16
#define GH_ALIGNMENT                    sizeof(unsigned long)

// 字节对齐
#define gh_memalign_ptr(p, a) \
    (char *)(((uintptr_t)(p) + ((uintptr_t)a - 1)) & ~((uintptr_t)a - 1))


typedef struct gh_mempool_s                 gh_mempool_t;
typedef struct gh_mempool_data_s            gh_mempool_data_t;
typedef struct gh_mempool_large_s           gh_mempool_large_t;


struct gh_mempool_large_s {
    gh_mempool_large_t *next;
    void *alloc;
};

struct gh_mempool_data_s {
    char              *last;
    char              *end;
    gh_mempool_t      *next;
    int               faild;
};

struct gh_mempool_s {
    gh_mempool_data_t  d;
    size_t             max;
    gh_mempool_t       *current;
    gh_mempool_large_t *large;
};



/* API */

gh_mempool_t *gh_mempool_create (size_t size);
void gh_mempool_destory(gh_mempool_t *mempool);
void gh_mempool_reset(gh_mempool_t *mempool);
int  gh_mempool_free (gh_mempool_t *mempool, void *p);
void *gh_mempool_nalloc(gh_mempool_t *mempool, size_t size);
/* 字节对齐 */
void *gh_mempool_alloc(gh_mempool_t *mempool, size_t size);
void *gh_mempool_calloc(gh_mempool_t *mempool, size_t size);


#endif
