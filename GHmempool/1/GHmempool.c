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

#include "GHmempool.h"


#define gh_free    free
static void *gh_memalign(size_t alignment, size_t size);
static void *gh_malloc(size_t size);
static void *gh_calloc(size_t size);
static void *gh_mempool_alloc_block(gh_mempool_t *mempool, size_t size);
static void *gh_mempool_alloc_small(gh_mempool_t *mempool, size_t size, int align);
static void *gh_mempool_alloc_large(gh_mempool_t *mempool, size_t size);



gh_mempool_t *gh_mempool_create (size_t size)
{
    gh_mempool_t *p = NULL;

#ifdef NEED_OTHER_ALIGNMENT
    p = gh_memalign(GH_MEMPOOL_ALIGNMENT, size);
#else 
    p = gh_calloc(size);
#endif

    p->d.last = (char*)p + sizeof(gh_mempool_t);
    p->d.end  = (char*)p + size;
    p->d.next = NULL;
    p->d.faild = 0;

    p->max = size > GH_MAX_ALLOC_MEMORY ? GH_MAX_ALLOC_MEMORY : size; 

    p->current = p;
    p->large = NULL;

    return p;
}

void gh_mempool_destory(gh_mempool_t *mempool)
{
    gh_mempool_t *p, *n;
    gh_mempool_large_t *large;

    if (mempool == NULL) 
        return ;

    for (large = mempool->large; large; large = large->next)
        if (large->alloc)
            gh_free(large->alloc);

    for (p = mempool, n = p->d.next ;; p = n, n = n->d.next) {
        // n = p->d.next;
        gh_free(p);
        if (n == NULL)
            break;
    }

}

void gh_mempool_reset(gh_mempool_t *mempool)
{
    gh_mempool_t *p;
    gh_mempool_large_t *large;

    if (mempool == NULL) 
        return ;

    for (large = mempool->large; large; large = large->next)
        if (large->alloc) {
            gh_free(large->alloc);
            large->alloc = NULL;
        }

    for (p = mempool; p; p = p->d.next) {
        p->d.last = (char *)p + sizeof(gh_mempool_t);
        p->d.faild = 0;
    }

    mempool->current = mempool;
    mempool->large = NULL;
}


int gh_mempool_free (gh_mempool_t *mempool, void *p)
{
    gh_mempool_large_t *large;

    if (mempool == NULL || p == NULL) {
        errno = EINVAL;
        return -1;
    } 

    for (large = mempool->large; large; large = large->next) {
        if (p == large->alloc) {
            gh_free(large->alloc);
            large->alloc = NULL;

            return 0;
        } 
    }

    errno = ENXIO;
    return -1;
}


static void *gh_mempool_alloc_block(gh_mempool_t *mempool, size_t size)
{
    char *m;
    gh_mempool_t *p, *alloc; 
    size_t psize = (size_t)(mempool->d.end - (char*)mempool);

#ifdef NEED_OTHER_ALIGNMENT
    m = gh_memalign(GH_ALIGNMENT, psize);
#else 
    m = gh_calloc(psize);
#endif

    alloc = (gh_mempool_t *)m;
    alloc->d.end = m + psize;
    alloc->d.next = NULL;
    alloc->d.faild = 0;
    alloc->max = psize;

    m += sizeof(gh_mempool_t);
    alloc->d.last = m + size;

    m = gh_memalign_ptr(m, GH_ALIGNMENT);

    for (p = mempool->current; p->d.next; p = p->d.next) {
        if (p->d.faild ++ > 4) 
            mempool->current = p->d.next;
    }

    p->d.next = alloc;

    return m;
}

static void *gh_mempool_alloc_small(gh_mempool_t *mempool, size_t size, int align)
{
    void *a;
    gh_mempool_t *p = mempool->current;

    do {
        if ((size_t)(p->d.end - p->d.last) > size) {
            a = p->d.last;

            if (align) 
                a = gh_memalign_ptr(a, GH_ALIGNMENT);

            p->d.last = p->d.last + size;
            return a;
        }
        p = p->d.next;

    } while(p);

    return gh_mempool_alloc_block(mempool, size);
}

static void *gh_mempool_alloc_large(gh_mempool_t *mempool, size_t size)
{
#if 0
    void *a;
    gh_mempool_large_t  *large;

#ifdef NEED_OTHER_ALIGNMENT
    a = gh_memalign(GH_MEMPOOL_ALIGNMENT, size + sizeof(gh_mempool_large_t));
#else 
    a = malloc(size);
#endif

    large = (gh_mempool_large_t *)a;
    large->next = mempool->large;
    mempool->large = large;

    // for (p = mempool->large; p; p = p->next)
    return large->alloc;
#endif

    void *a = NULL;
    gh_mempool_large_t *large;
    int n = 0;


    a = gh_calloc(size);

    for (large = mempool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = a;
            return a;
        }

        if (n++ > 3)
            break;
    }

    large = gh_mempool_alloc_small(mempool, sizeof(gh_mempool_large_t), 1);
    large->alloc = a;
    large->next = mempool->large;
    mempool->large = large;

    return a;
}

void *gh_mempool_alloc(gh_mempool_t *mempool, size_t size)
{
    if (NULL == mempool || size <= 0) {
        errno = EINVAL;
        return NULL;
    } 

    if (size < mempool->max) {
        return gh_mempool_alloc_small(mempool, size, 1);
    } 

    return gh_mempool_alloc_large(mempool, size);
}

#if 0
#ifdef NEED_FREE_SMALL
int gh_mempool_free_small (gh_mempool_t *mempool, void *f)
{
    gh_mempool_t *p;

    if (mempool == NULL || f == NULL)
        return -1;

    unsigned short *tags = (unsigned short *)f - 2;
    unsigned short *size = (unsigned short *)f - 1;

    for (p = mempool; p; p = p->d.next) {
        if (p->tags == *tags) {
            p->d.last = p->d.last - *size - 2;
            return 0;
        }
    }

    return -1;
}
#endif
#endif


void *gh_mempool_nalloc(gh_mempool_t *mempool, size_t size)
{
    if (NULL == mempool || size <= 0) {
        errno = EINVAL;
        return NULL;
    } 

    if (size < mempool->max) {
        return gh_mempool_alloc_small(mempool, size, 0);
    }

    return gh_mempool_alloc_large(mempool, size);
}


void *gh_mempool_calloc(gh_mempool_t *mempool, size_t size)
{
    void *p = gh_mempool_alloc(mempool, size);

    if (p) 
        memset(p, 0, size);

    return p;
}


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


void gh_mempool_echo_info (gh_mempool_t *mempool)
{
    gh_mempool_t *p;

    if (NULL == mempool)
        return ;

    if (mempool->large) {
        gh_mempool_large_t *l = mempool->large;
        for (; l; l = l->next) {
            if (l->alloc)
                fprintf (stdout, "large alloc: %p \n", l->alloc);
        }
    }

    for (p = mempool; p; p = p->d.next) {
        fprintf (stdout, "small alloc: #%p ~ #%p  last: #%p   max: %zu\n", p->d.end - p->max, p->d.end, p->d.last, p->max);
    }

    fprintf(stdout, "\n");
}






/************************************************************************/
/*                            GHmempool Test                            */
/************************************************************************/


#define TEST

#ifdef TEST

int main ()
{
    gh_mempool_t *mpool = gh_mempool_create(1024);

    char *a = gh_mempool_nalloc(mpool, 31);
    gh_mempool_echo_info(mpool);
    strncpy(a, "111111111", 10);

    char *b = gh_mempool_calloc(mpool, 2111);
    gh_mempool_echo_info(mpool);
    strncpy(b, "111111111", 10);

    char *c = gh_mempool_alloc(mpool, 31);
    gh_mempool_echo_info(mpool);
    strncpy(c, "111111111", 10);

    char *d = gh_mempool_alloc(mpool, 1000);
    gh_mempool_echo_info(mpool);
    strncpy(d, "111111111", 10);

    gh_mempool_free(mpool, b);
    gh_mempool_echo_info(mpool);

    gh_mempool_reset(mpool);
    gh_mempool_echo_info(mpool);

    gh_mempool_destory(mpool);
    return 0;
}





#endif





