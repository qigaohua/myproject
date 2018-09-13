/**
 * @file GHmempool.c
 * @brief 
 * @author qigaohua, qigaohua168@163.com
 * @version 1.0.0
 * @date 2018-04-13
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <pthread.h>

#include "GHmempool.h"


#define gh_free free

#ifdef HAVE_MULTITHREADING
static   pthread_mutex_t    ghmempool_lock;
#endif

#if 0
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({                       \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);     \
        (type *)( (char *)__mptr - offsetof(type,member) ); })
#endif



static void *gh_memalign (size_t alignment, size_t size)
{
    int ret;
    void *p = NULL;

    ret = posix_memalign(&p, alignment, size);
    if (ret) {
        fprintf(stderr, "posix_memalign(%zu, %zu) falied\n", alignment, size);
        exit(EXIT_FAILURE);
    }
    
#ifdef _DEBUG_
    fprintf(stdout, "posix_memalign: %p:%zu @%zu\n", alignment, size);
#endif
    return p;
}


static void *gh_malloc(size_t size)
{
    void *p = malloc(size);

    if (p == NULL) {
        fprintf(stderr, "malloc falied : %m\n");
        exit(EXIT_FAILURE);
    }

    return p;
}

static void *gh_calloc(size_t size)
{
    void *p = gh_malloc(size);

    memset(p, 0, size);
    return p;
}


#if 0
gh_mempool_t **gh_mempool_create (int numType, size_t *blocksize, int *blockcount)
{
    int i = 0;
    gh_mempool_t **mpool;

    if (numType <= 0 || blocksize == NULL || blockcount == NULL)
        return NULL;

    mpool = (gh_mempool_t **)gh_calloc(sizeof(gh_mempool_t *) * numType); 

    for (; i < numType; i ++) {
        mpool[i] = (gh_mempool_t *)gh_calloc(sizeof(gh_mempool_t));

        mpool[i]->total = numType;

        if (blocksize[i] > 0){
            mpool[i]->blocksize = blocksize[i];
        } 
        else 
            goto END;

        if (blockcount[i] > 0) mpool[i]->blockcount = blockcount[i]; 
        else 
            continue;

        // mpool[i]->unused = gh_calloc(sizeof(gh_mempool_block_t) * blockcount[i]);
        int j = 0;
        for (; j < blockcount[i]; j ++) {
            gh_mempool_block_t *b = gh_calloc(sizeof(gh_mempool_block_t));

            void *d = gh_calloc(blocksize[i] + sizeof(int));
            int *type = (int *)d;
            b->d = (void*)(type + 1);
            *type = i;

            if (mpool[i]->unused) {
                b->next = mpool[i]->unused;
                mpool[i]->unused = b;
            } else {
                b->next = NULL;
                mpool[i]->unused = b;
            } 
        }
        mpool[i]->used = NULL;
    }

    return mpool;
END:
    gh_free(mpool);
    return NULL;
}
#endif

gh_mempool_t **gh_mempool_create (mempool_block_info_t *binfo)
{
    int i = 0, j;
    gh_mempool_t **mpool;

    if (!binfo || binfo->total <= 0 || !binfo->block) {
        errno = EINVAL;
        return NULL;
    } 
    /* 按内存块大小排序，避免申请内存块错误 */
    gh_mempool_sort_block (binfo);

    mpool = (gh_mempool_t **)gh_calloc(sizeof(gh_mempool_t *) * binfo->total); 

    for (; i < binfo->total; i ++) {
        mpool[i] = (gh_mempool_t *)gh_calloc(sizeof(gh_mempool_t));

        mpool[i]->total = binfo->total;

        if (binfo->block[i].blocksize > 0){
            mpool[i]->blocksize = binfo->block[i].blocksize;
        } 
        else 
            continue;

        if (binfo->block[i].blockcount > 0) mpool[i]->blockcount = binfo->block[i].blockcount; 
        else 
            continue;

        // mpool[i]->unused = gh_calloc(sizeof(gh_mempool_block_t) * blockcount[i]);
        for (j = 0; j < mpool[i]->blockcount; j ++) {
            gh_mempool_block_t *b = gh_calloc(sizeof(gh_mempool_block_t));

            /* 把内存块大小的索引赋值给待分配内存的前4个字节内存，方便释放时直接定位 */
            void *d = gh_calloc(mpool[i]->blocksize + sizeof(int));
            int *type = (int *)d;
            b->d = (void*)(type + 1);
            *type = i;

            if (mpool[i]->unused) {
                b->next = mpool[i]->unused;
                mpool[i]->unused = b;
            } else {
                b->next = NULL;
                mpool[i]->unused = b;
            } 
        }
        mpool[i]->used = NULL;

    }

#ifdef HAVE_MULTITHREADING
        pthread_mutex_init(&ghmempool_lock, NULL);
#endif

    return mpool;
}


void gh_mempool_destory (gh_mempool_t **mpool)
{
    int i = 0;
    int total  = mpool[0]->total;
    gh_mempool_block_t *b, *n = NULL;

    for (; i < total; i++) {
        if (mpool[i]->unused) {
            for (b = mpool[i]->unused; b; n = b, b = n->next) {
                void *d = (void*)((int*)b->d - 1);
                gh_free(d);
                gh_free(b);
            }
        }
        if (mpool[i]->used) {
            for (b = mpool[i]->used; b; n = b, b = n->next) {
                void *d = (void*)((int*)b->d - 1);
                gh_free(d);
                gh_free(b);
            }

        }
        gh_free(mpool[i]);
    }

#ifdef HAVE_MULTITHREADING
    pthread_mutex_destroy(&ghmempool_lock);
#endif

    gh_free(mpool);
}

void *gh_mempool_alloc (gh_mempool_t **mpool, size_t size)
{
    int i = 0;
    int total  = mpool[0]->total;

    if (NULL == mpool || NULL == *mpool) {
        errno = EINVAL;
        return NULL;
    }

    for (; i < total; i++) {
#ifdef HAVE_MULTITHREADING 
        pthread_mutex_lock(&ghmempool_lock);
#endif
        if (size <= mpool[i]->blocksize && mpool[i]->unused) {
            gh_mempool_block_t *b = mpool[i]->unused; 
            mpool[i]->unused = b->next;

            if (mpool[i]->used) {
                b->next = mpool[i]->used;
                mpool[i]->used = b;
            } else {
                b->next = NULL;
                mpool[i]->used = b;
            }

#ifdef HAVE_MULTITHREADING 
            pthread_mutex_unlock(&ghmempool_lock);
#endif

            // printf(">>>>>>>>>>>>>>>>>>>>%p  %p\n", &b->d, &b->num);
            return b->d;
        }
#ifdef HAVE_MULTITHREADING 
        pthread_mutex_unlock(&ghmempool_lock);
#endif
    }

    /* 内存块用完，不扩充内存池，则直接malloc  */
    void *alloc = gh_calloc(size + sizeof(int));
    int *tags = (int *)alloc;
    alloc = (void *)(tags + 1);
    *tags = 286718345;

    fprintf(stdout, "warn: blocksize @%zu use up.\n", size);

    return alloc;
}

int gh_mempool_free (gh_mempool_t **mpool, void *f)
{
    if (!mpool || !*mpool || !f) {
        errno = EINVAL;
        return -1;
    }

    int total = mpool[0]->total;
    int index = *((int *)f - 1);

    // printf("%lu   %p\n", offsetof(gh_mempool_block_t, d), &f);
    // gh_mempool_block_t *c = container_of(&f, gh_mempool_block_t, d);
    
    if (index == 286718345) {
        f = (void*)((unsigned int *)f - 1); 
        gh_free(f);
        return 0;
    } 
    else if(index < 0 || index >= total) {
        return -1;
        fprintf(stderr, "error: index out of range\n");
    } 

    gh_mempool_block_t *b = mpool[index]->used, *n = NULL;

#ifdef HAVE_MULTITHREADING 
    pthread_mutex_lock(&ghmempool_lock);
#endif
    for (; b; n = b, b = b->next) {
        if (b->d == f) {
            if (n) {
                n->next = b->next;
            } else {
                mpool[index]->used = b->next;
            }    

            b->next = mpool[index]->unused;
            mpool[index]->unused = b;

#ifdef HAVE_MULTITHREADING 
            pthread_mutex_unlock(&ghmempool_lock);
#endif

            return 0;
        }
    }

#ifdef HAVE_MULTITHREADING 
    pthread_mutex_unlock(&ghmempool_lock);
#endif

    fprintf(stderr, "error: The memory not exist, can't free.\n");
    return -1;
}

/* 打印内存池当前信息 */
void gh_mempool_echo_info (gh_mempool_t **mpool)
{
    int i = 0, used;
    int total = mpool[0]->total;
    double userate[total];

    for (; i < total; i ++) {
        used = 0;
        gh_mempool_block_t *b;

        for (b = mpool[i]->used; b; b = b->next) {
            fprintf(stdout, "  used: #%p ~ #%p @%zu\n", b->d, (char*)b->d + mpool[i]->blocksize, mpool[i]->blocksize);
            used ++;
        }

        for (b = mpool[i]->unused; b; b = b->next) {
            fprintf(stdout, "unused: #%p ~ #%p @%zu\n", b->d, (char*)b->d + mpool[i]->blocksize, mpool[i]->blocksize);
        }

        userate[i] = (used / (double)mpool[i]->blockcount) * 100;

        fprintf(stdout, "\n");
    }

    for (i = 0; i < total; i ++) 
        fprintf(stdout, "blocksize: %zu \t@userate: %.2f%%\n", mpool[i]->blocksize, userate[i]);

    fprintf(stdout, "\n\n");
}


/* 快速排序算法 */
int gh_mempool_quick_sort(block_t *bk, int start, int end)
{

    int right, left;
    block_t tmp;

    if (NULL == bk)
        return -1;

    left = start;
    right = end;

    /* 递归退出判断 */
    if (left < right) {
        tmp = bk[left];

        while (left < right) {
            while (left < right && bk[right].blocksize >= tmp.blocksize)
                right --; 
            bk[left] = bk[right];

            while (left < right && bk[left].blocksize <= tmp.blocksize)
                left ++; 
            bk[right] = bk[left];

        }

        bk[right] = tmp;
        gh_mempool_quick_sort(bk, start, left - 1);
        gh_mempool_quick_sort(bk, right + 1, end);
    }

    return 0;
}



int gh_mempool_sort_block (mempool_block_info_t *binfo)
{

    if (binfo == NULL) {
        return -1;
    }

    gh_mempool_quick_sort(binfo->block, 0, binfo->total - 1);

    return 0;
}






/*******************************************************************************/
/*                               GHmempool Test                                */
/*******************************************************************************/
#define TEST


#ifdef TEST

gh_mempool_t **mpool;

void *pthread_func1(void *data)
{
    char *a = (char*)gh_mempool_alloc(mpool, 56);
    sleep(1);
    char *b = (char*)gh_mempool_alloc(mpool, 100);
    char *c = (char*)gh_mempool_alloc(mpool, 8);
    char *d = (char*)gh_mempool_alloc(mpool, 15);
    char *e = (char*)gh_mempool_alloc(mpool, 31);
    strncpy(c, "12313", 6);
    strncpy(b, "12313213123", 12);
    strncpy(d, "12313213123", 12);
    strncpy(e, "12313213123", 12);
    gh_mempool_echo_info(mpool);

    gh_mempool_free(mpool, a);
    sleep(1);
    gh_mempool_free(mpool, b);
    gh_mempool_free(mpool, c);
    gh_mempool_free(mpool, d);
    gh_mempool_free(mpool, e);

    return (void*)0;
}

void *pthread_func2(void *data)
{
    char *a = (char*)gh_mempool_alloc(mpool, 56);
    char *b = (char*)gh_mempool_alloc(mpool, 100);
    sleep(1);
    char *c = (char*)gh_mempool_alloc(mpool, 8);
    char *d = (char*)gh_mempool_alloc(mpool, 15);
    sleep(1);
    char *e = (char*)gh_mempool_alloc(mpool, 31);
    strncpy(c, "12313", 6);
    strncpy(b, "12313213123", 12);
    strncpy(d, "12313213123", 12);
    strncpy(e, "12313213123", 12);
    gh_mempool_echo_info(mpool);

    gh_mempool_free(mpool, a);
    gh_mempool_free(mpool, b);
    gh_mempool_free(mpool, c);
    sleep(1);
    gh_mempool_free(mpool, d);
    gh_mempool_free(mpool, e);

    return (void*)0;
}
int main () 
{

    // size_t blocksize[5] = { 16, 32, 8, 12, 13 };
    // int blockcount[5] = { 20, 10, 5, 2, 1 };

    mempool_block_info_t binfo;
    binfo.total = 5;
    binfo.block = gh_calloc(sizeof(struct block_s) * 5);
    binfo.block[0].blockcount = 10;
    binfo.block[1].blockcount = 1;
    binfo.block[2].blockcount = 2;
    binfo.block[3].blockcount = 5;
    binfo.block[4].blockcount = 20;

    binfo.block[0].blocksize = 16;
    binfo.block[1].blocksize = 128;
    binfo.block[2].blocksize = 64;
    binfo.block[3].blocksize = 32;
    binfo.block[4].blocksize = 8;

    // mpool = gh_mempool_create(5, blocksize, blockcount);
    mpool = gh_mempool_create(&binfo);
    free(binfo.block);


    gh_mempool_echo_info(mpool);

    char *a = (char*)gh_mempool_alloc(mpool, 56);
    char *b = (char*)gh_mempool_alloc(mpool, 100);
    char *c = (char*)gh_mempool_alloc(mpool, 8);
    char *f = (char*)gh_mempool_alloc(mpool, 15);
    char *g = (char*)gh_mempool_alloc(mpool, 31);
    gh_mempool_echo_info(mpool);

    // gh_mempool_free(mpool, d);
    gh_mempool_free(mpool, a);
    gh_mempool_free(mpool, b);
    gh_mempool_free(mpool, c);
    gh_mempool_free(mpool, f);
    gh_mempool_free(mpool, g);
    gh_mempool_echo_info(mpool);

    /* test mempool use up */
    char *e = (char*)gh_mempool_alloc(mpool, 200);
    strncpy(e, "12313213123", 12);
    gh_mempool_free(mpool, e);
    // gh_mempool_echo_info(mpool);

    /* test free failed */
    char *h = malloc(4);
    gh_mempool_free(mpool, h);


    pthread_t pid1, pid2, pid3, pid4;

    pthread_create (&pid1, NULL, pthread_func1, NULL);
    pthread_create (&pid2, NULL, pthread_func2, NULL);
    pthread_create (&pid3, NULL, pthread_func1, NULL);
    pthread_create (&pid4, NULL, pthread_func2, NULL);

    pthread_join (pid1, NULL);    
    pthread_join (pid2, NULL); 
    pthread_join (pid3, NULL);    
    pthread_join (pid4, NULL); 

    gh_mempool_echo_info(mpool);

    gh_mempool_destory(mpool);
    return 0;
}


#endif




