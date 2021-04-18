#ifndef __HASH_MAP_H
#define __HASH_MAP_H


#include <stdint.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct _hashmap {
    uint32_t bucket;
    void *item_list;
    void (*destroy)(void *);
} hashmap_t, *hashmap_pt;


typedef struct _item {
    struct hlist_node list;
    char *key;
    void *val;
    uint32_t hash;
} item_t, *item_pt;


hashmap_t* hashmap_create(uint32_t bucket, void (*destroy)(void *));
void hashmap_destroy(hashmap_t *hm);
int hashmap_put(hashmap_t *hm, const char *key, void *val);
void *hashmap_get(hashmap_t *hm, const char *key);
int hashmap_del(hashmap_t *hm, const char *key);
void *hashmap_get_del(hashmap_t *hm, const char *key);

#ifdef __cplusplus
}
#endif


#endif /* ifndef __HASH_MAP_ */
