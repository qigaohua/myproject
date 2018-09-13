#ifndef __GH_MEMPOOL_
#define __GH_MEMPOOL_ 
#include <stdlib.h>


#define HAVE_MULTITHREADING  /* 使用多线程定义 */

typedef struct gh_mempool_block_s gh_mempool_block_t;
typedef struct gh_mempool_s gh_mempool_t;
typedef struct block_s    block_t;
typedef struct mempool_block_info_s mempool_block_info_t;


struct gh_mempool_block_s {
    void *d;
    gh_mempool_block_t *next;
};

struct gh_mempool_s {
    /* 不同内存块的数量 */
    int total;

    /* 内存块大小 */
    size_t blocksize;

    /* 内存块数量 */
    int blockcount;


    gh_mempool_block_t *used;
    gh_mempool_block_t *unused;
};

struct block_s {
    int blockcount ;
    size_t blocksize;
};

struct mempool_block_info_s {
    int total;
    block_t *block;
};

int gh_mempool_sort_block (mempool_block_info_t *binfo);
int gh_mempool_quick_sort(block_t *bk, int start, int end);



/* USER API */

gh_mempool_t **gh_mempool_create (mempool_block_info_t *binfo);
void gh_mempool_destory (gh_mempool_t **mpool);
void *gh_mempool_alloc (gh_mempool_t **mpool, size_t size);
int gh_mempool_free (gh_mempool_t **mpool, void *f);
void gh_mempool_echo_info (gh_mempool_t **mpool);

#endif
