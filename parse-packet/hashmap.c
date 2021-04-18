/**
 * @file hashmap.c
 * @brief  hash map
 * @author qigaohua, qigaohua168@163.com
 * @version
 * @date 2018-06-30
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hashmap.h"


static inline int is_power_of_2(uint32_t n)
{
    return n && !(n & (n - 1));
}


static inline uint32_t up_power2_u32(uint32_t c)
{
    c |= c >> 1;
    c |= c >> 2;
    c |= c >> 4;
    c |= c >> 8;
    c |= c >> 16;
    c += 1;

    return c;
}


hashmap_t* hashmap_create(uint32_t bucket, void (*destroy)(void *))
{
    hashmap_t *hm = NULL;
    struct hlist_head *hl = NULL;

    hm = calloc(1, sizeof *hm);
    if ( !hm ) {
        fprintf(stderr, "calloc failed: %m");
        return NULL;
    }

    if (!is_power_of_2(bucket))
        bucket  = up_power2_u32(bucket);
    hl = calloc(bucket - 1, sizeof *hl);
    if ( !hl ) {
        fprintf(stderr, "calloc failed: %m");
        goto ERR;
    }

    for (int i = bucket - 1; i >= 0; i --)
        INIT_HLIST_HEAD(&hl[i]);

    hm->bucket = bucket - 1;
    hm->item_list = hl;
    hm->destroy = destroy;

    return hm;

ERR:
    if (hm) free(hm);
    if (hl) free(hl);
    return NULL;
}


void hashmap_destroy(hashmap_t *hm)
{
    if (!hm)
        return ;

    if (hm->item_list) {
        struct hlist_head *list = hm->item_list;
        struct hlist_node *next;
        item_t *item;
        for (int i = 0; i < hm->bucket; i ++) {
            hlist_for_each_entry_safe(item, next, &list[i], list) {
                hlist_del((struct hlist_node *)item);
                if (item->key) free(item->key);
                if (item->val && hm->destroy)
                    hm->destroy(item->val);
                free(item);
            }
        }
        free(hm->item_list);
    }
    free(hm);
}

// BKDR Hash
static uint32_t BKDRHash(const char *str)
{
    uint32_t seed = 131; // 31 131 1313 13131 131313 etc..
    uint32_t hash = 0;

    while (*str)
    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}


static item_t* hashmap_lookup(hashmap_t *hm, const char *key, uint32_t *hash)
{
    struct hlist_head *hl;
    struct hlist_node *next;
    item_t *item;

    if (!hm || !key)
        return NULL;

    *hash = BKDRHash(key) & hm->bucket;
    hl = &((struct hlist_head *)hm->item_list)[*hash];

    hlist_for_each_entry_safe(item, next, hl, list) {
        if (item->hash == *hash && !strncmp(item->key, key, strlen(item->key)))
            return item;
    }

    return NULL;
}


int hashmap_put(hashmap_t *hm, const char *key, void *val)
{
    uint32_t hash;
    struct hlist_head *hl;

    if (!hm || !key)
        return -1;

    item_t *item = hashmap_lookup(hm, key, &hash);
    if (item) {
        item->val = val;
        return 0;
    }

    item = calloc(1, sizeof *item);
    if ( !item ) {
        fprintf(stderr, "calloc failed: %m");
        return -2;
    }

    item->key = strdup(key);
    item->hash = hash;
    item->val = val;
    INIT_HLIST_NODE(&item->list);
    hl = &((struct hlist_head *)hm->item_list)[hash];
    hlist_add_head(&item->list, hl);

    return 0;
}


void *hashmap_get(hashmap_t *hm, const char *key)
{
    uint32_t hash;

    item_t *item = hashmap_lookup(hm, key, &hash);
    if (item)
        return item->val;

    return NULL;
}


int hashmap_del(hashmap_t *hm, const char *key)
{
    uint32_t hash;

    item_t *item = hashmap_lookup(hm, key, &hash);
    if ( !item )
        return -1;

    if (item->key) free(item->key);
    if (item->val && hm->destroy)
        hm->destroy(item->val);
    hlist_del(&item->list); // hlist_del((struct hlist_head *)item);
    free(item);

    return 0;
}


void *hashmap_get_del(hashmap_t *hm, const char *key)
{
    uint32_t hash;
    void *ret;

    item_t *item = hashmap_lookup(hm, key, &hash);
    if ( !item )
        return NULL;

    ret = item->val;
    if (item->key) free(item->key);
    // if (item->val && hm->destroy)
    //     hm->destroy(item->val);
    hlist_del(&item->list); // hlist_del((struct hlist_head *)item);
    free(item);

    return ret;
}


/******************** test *************************/

#if 0
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#define PALIGN   "%15s: %6.4f sec\n"
#define NKEYS   1024*1024
//#define NKEYS   10240
#define DEBUG 2

static double epoch_double(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec + (t.tv_usec * 1.0) / 1000000.0;
}

int main(int argc, char * argv[])
{
    hashmap_t * d ;
    double t1, t2 ;
    int i ;
    int nkeys ;
    char * buffer ;
    char * val ;

    nkeys = (argc>1) ? (int)atoi(argv[1]) : NKEYS ;
    printf("%15s: %d\n", "values", nkeys);
    buffer = (char *)malloc(9 * nkeys);

    //                10000000
    d = hashmap_create(2097100, NULL);
    printf(">>>>bucket: %u\n", d->bucket);
    t1 = epoch_double();
    for(i = 0; i < nkeys; i++) {
        sprintf(buffer + i * 9, "%08x", i);
    }
    t2 = epoch_double();
    printf(PALIGN, "initialization", t2 - t1);

    t1 = epoch_double();
    for(i = 0; i < nkeys; i++) {
        hashmap_put(d, buffer + i*9, buffer +i*9);
    }
    t2 = epoch_double();
    printf(PALIGN, "adding", t2 - t1);

    t1 = epoch_double();
    int cnt = 20;
    for(i = 0; i < nkeys; i++) {
        val = (char *)hashmap_get(d, buffer + i*9);
        if (cnt > 0) {
        cnt --;
        printf("hash_get: key=%s, val=%s\n", buffer + i*9, val);
        }
#if DEBUG>1
        printf("exp[%s] got[%s]\n", buffer+i*9, val);
        if (val && strcmp(val, buffer+i*9)) {
            printf("-> WRONG got[%s] exp[%s]\n", val, buffer+i*9);
            break;
        }
#endif
    }
    t2 = epoch_double();
    printf(PALIGN, "lookup", t2 - t1);

    t1 = epoch_double();
    for(i = 0; i < nkeys; i++) {
        hashmap_del(d, buffer + i*9);
    }
    t2 = epoch_double();
    printf(PALIGN, "delete", t2 - t1);

    t1 = epoch_double();
    for(i = 0; i < nkeys; i++) {
        hashmap_put(d, buffer + i*9, buffer +i*9);
    }
    t2 = epoch_double();
    printf(PALIGN, "adding", t2 - t1);

    t1 = epoch_double();
    hashmap_destroy(d);
    t2 = epoch_double();
    printf(PALIGN, "free", t2 - t1);

    free(buffer);
    return 0 ;

}
#endif
