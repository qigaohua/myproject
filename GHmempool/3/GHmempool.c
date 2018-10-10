/**
 * @file GHmempool.c
 * @brief   利用红黑树的内存池 
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


static int gh_mempool_value_cmp(Type *d1, Type *d2)
{
    gh_mempool_node_t *t1 = (gh_mempool_node_t *)(*d1);
    gh_mempool_node_t *t2 = (gh_mempool_node_t *)(*d2);

    if (t1->index > t2->index)
        return 1;
    else if (t1->index < t2->index)
        return -1;
    else 
        return 0;
}


/**
 * @brief gh_mempool_print 打印内存池信息
 *
 * @param p
 */
static void gh_mempool_print (void *p)
{
   rbt_pt node = (rbt_pt)p; 
   gh_mempool_node_t *va =  (gh_mempool_node_t *)node->data;
   
    if (node->parent) {
        gh_mempool_node_t *pa =  (gh_mempool_node_t *)node->parent->data;
        printf("[%s] > key: %ld  used: %d  size: %zu\t[父节点: %s : %ld]\n", 
                node->color == RED ? "red" : "black", va->index, va->is_used, va->blocksize, 
                node->parent->color == RED ? "red" : "black", pa->index);	
    }

    else 
        printf("[%s] > key: %ld  used: %d  size: %zu\t\t[根节点]\n", 
                node->color == RED ? "red" : "black", 
                va->index, va->is_used, va->blocksize);	
} 



/**
 * @brief gh_create_mempool 创建内存池
 *
 * @param size
 *
 * @return 
 */
gh_mempool_t *gh_create_mempool (size_t size)
{
    gh_mempool_t *mp;
    gh_mempool_node_t *node;

    if (size <= 0)
        return NULL;

    mp = (gh_mempool_t *)gh_calloc(sizeof(gh_mempool_t)); 

    mp->d = gh_calloc(size);
    mp->size = size;

    node = (gh_mempool_node_t *)gh_calloc(sizeof(gh_mempool_node_t));
    node->d = mp->d;
    node->index = (unsigned long)(mp->d);  // 使用每段内存的内存头地址当做红黑树的索引
    node->blocksize = size;
    node->is_used = False;

    /* 设置红黑树的比较函数 */
    rbtree_set_cmp (gh_mempool_value_cmp);
    /* 设置红黑树的打印函数 */
    rbtree_set_print(gh_mempool_print);

    // 将申请的内存块添加到红黑树
	rbtree_for_insert(&mp->root, node);  

    return mp;
}


/**
 * @brief gh_mempool_destroy 销毁内存池
 *
 * @param mp
 */
void gh_mempool_destroy(gh_mempool_t *mp)
{
    if (mp != NULL) {
        rbtree_destroy(mp->root);
        if (mp->d) free (mp->d);
    }

    free(mp);
}


// 递归申请内存，被gh_mempool_alloc调用
static void *alloc(gh_mempool_t *mp, rbt_pt root, size_t size)
{
    void *p = NULL;

    if (root != NULL) {
        gh_mempool_node_t *node = (gh_mempool_node_t *)root->data;;

        // 当该节点的内存是空闲状态，且大小大于size+4时，
        // 将该节点分割为两个节点，并将新生产的节点插入红黑树
        if (node->is_used == False && node->blocksize > (size+4)) {
            gh_mempool_node_t *new_node;
            new_node = (gh_mempool_node_t *)gh_calloc(sizeof(gh_mempool_node_t));

            new_node->d = (char*)node->d + size + 4;
            new_node->blocksize = node->blocksize - size - 4;
            new_node->index = (unsigned long)new_node->d;
            new_node->is_used = False;

            node->blocksize = size + 4;
            node->is_used = True;

	        rbtree_for_insert(&mp->root, new_node);  

            unsigned long *v =(unsigned long *)node->d; 
            p = (void*)(v + 1);
            memset(v, 0, 4);
            *v = (unsigned long)&(node->is_used);
        }
        else if (node->is_used == False && node->blocksize == (size+4)) {
            node->is_used = True;
            unsigned long *v =(unsigned long *)node->d; 
            p = (void*)(v + 1);

            memset(v, 0, 4);
            *v = (unsigned long)&(node->is_used);
        }

        if (p != NULL)
            return p;
        else {
            p = alloc(mp, root->lchild, size);
            if (p != NULL)
                return p;
            else 
                p = alloc(mp, root->rchild, size);
        } 
    }

    return p;
}


/**
 * @brief gh_mempool_alloc 向内存池申请内存
 *
 * @param mp    内存池
 * @param size  申请内存大小
 *
 * @return      返回申请的内存头指针 
 */
void *gh_mempool_alloc(gh_mempool_t *mp, size_t size)
{
    void *a;
    a =  alloc(mp, mp->root, size); 
    if (a == NULL) {
        /* 没申请到内存，可能需要整合一下内存池，再申请 */
        fprintf(stdout, "warn: memory alloc failed, should call gh_mempool_integrate\n");
        gh_mempool_integrate(mp);
        a = alloc(mp, mp->root, size); 
    }

#ifdef USE_MALLOC
    // 如果定义了 USE_MALLOC，内存池用完的情况下，直接通过系统函数malloc申请
    // 并且立个标志，以便释放时知道这是malloc申请的
    if (a == NULL) {
        fprintf(stdout, "warn: memory alloc failed, maybe mempool use up\n");
        a = gh_calloc(size + sizeof(unsigned long));
        unsigned long *tags = (unsigned long *)a;
        a = (void *)(tags + 1);
        *tags = 286718345;
    }
#endif

    return a;
}


/**
 * @brief gh_mempool_free 内存释放函数
 *
 * @param f
 */
void gh_mempool_free(void *f)
{

    unsigned int *p;
    p = (unsigned int *)(*(((unsigned long *)f) - 1));


#ifdef USE_MALLOC
    unsigned long va = *((unsigned long *)f - 1);
    /* 条件为真，则是直接通过malloc申请的，直接free */
    if (va == 286718345) {
        f = (void *)((unsigned long *)f - 1);
        free(f);
        return ;
    }
#endif

    *p = False;
}


// 递归整合内存，被gh_mempool_integrate调用
static void integrate(gh_mempool_t *mp, rbt_pt root)
{
    if (root != NULL) {
        gh_mempool_node_t key;
        gh_mempool_node_t *va = (gh_mempool_node_t *)root->data;

        key.index = va->index + va->blocksize;
        rbt_pt next = rbtree_search (&mp->root, &key); 
        if (next == NULL) {
            return ;
        }
        key = *((gh_mempool_node_t *)next->data);
        if (va->is_used == False && key.is_used == False) {
            va->blocksize = va->blocksize + key.blocksize;
            rbtree_for_delete(&mp->root, next->data);
            integrate(mp, root);
        }
        else {
            integrate(mp, next);
        }
    }
}


/**
 * @brief 整合内存池内的空闲内存 
 *
 * @param mp
 */
void gh_mempool_integrate(gh_mempool_t *mp)
{
    // 从做小节点开始整合，先在红黑树中查找最小节点
    rbt_pt min_node =  rbtree_min_node(mp->root);
    if (min_node != NULL) {
        integrate(mp, min_node);
    }
}



/*********************************************************************************/
/*                           Red&Black Mempool Test                             */
/*********************************************************************************/



int main ()
{
    gh_mempool_t *mpool;

    mpool = gh_create_mempool(2 * 1024);

    void *p = gh_mempool_alloc(mpool, 100);
    void *a = gh_mempool_alloc(mpool, 30);
    void *b = gh_mempool_alloc(mpool, 100);
    void *c = gh_mempool_alloc(mpool, 512);
    void *q = gh_mempool_alloc(mpool, 256);
    void *w = gh_mempool_alloc(mpool, 128);
    void *r = gh_mempool_alloc(mpool, 64);
    void *t = gh_mempool_alloc(mpool, 98);
    void *y = gh_mempool_alloc(mpool, 10);
    void *u = gh_mempool_alloc(mpool, 123);
    void *i = gh_mempool_alloc(mpool, 20);
    
    strcpy((char*)p, "mempool test");

    printf("********************测试申请**************************\n");
    rbtree_for_preorder(mpool->root);
    gh_mempool_free(p);
    gh_mempool_free(a);
    void *e = gh_mempool_alloc(mpool, 100);
    void *f = gh_mempool_alloc(mpool, 50);
    void *n = gh_mempool_alloc(mpool, 1024);
    gh_mempool_free(e);
    gh_mempool_free(f);
    gh_mempool_free(i);
    gh_mempool_free(u);
    gh_mempool_free(y);
    gh_mempool_free(t);
    gh_mempool_free(b);
    gh_mempool_free(n);
    printf("********************测试释放**************************\n");
    rbtree_for_preorder(mpool->root);


    printf("********************测试整合**************************\n");
    void *k = gh_mempool_alloc(mpool, 510);
    gh_mempool_free(k);
    rbtree_for_preorder(mpool->root);

    gh_mempool_free(c);
    gh_mempool_free(q);
    gh_mempool_free(w);
    gh_mempool_free(r);
    void *m = gh_mempool_alloc(mpool, 123);
    gh_mempool_free(m);
    gh_mempool_integrate(mpool);
    printf("*****************全部释放，整合测试**************************\n");
    rbtree_for_preorder(mpool->root);

    gh_mempool_destroy(mpool);
    return 0;
}
