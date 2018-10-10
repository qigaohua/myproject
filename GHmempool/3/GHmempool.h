#ifndef __GH_MEMPOOL_
#define __GH_MEMPOOL_ 
#include <stdlib.h>

#include "gh_rbtree.h"

#define USE_MALLOC

typedef struct gh_mempool_s gh_mempool_t, *gh_mempool_pt;
typedef struct gh_mempool_node_s gh_mempool_node_t;

struct gh_mempool_node_s {
    void   *d;
    unsigned long  index;
    size_t blocksize; 
    BOOL   is_used;
};

struct gh_mempool_s {
    void   *d;
    size_t size;
    unsigned long min_key;

    rbt_pt root;
};



/* API */
gh_mempool_t *gh_create_mempool (size_t size);
void gh_mempool_destroy(gh_mempool_t *mp);
void *gh_mempool_alloc(gh_mempool_t *mp, size_t size);
void gh_mempool_free(void *f);

// 内存池整合函数
// 一般在内存申请失败时自动调用， 用户也可以手动调用
void gh_mempool_integrate(gh_mempool_t *mp);

#endif
