#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX 26

typedef struct trie {
    struct trie* node[MAX];
    int v;
} Trie;

Trie *root;


Trie *create_node()
{
    Trie *node;

    node = (Trie *)malloc(sizeof(Trie));
    if (node) {
        memset(node, 0, sizeof(Trie));
    } 
    else 
        return NULL;

    return node;
}

int bulid_trie(Trie **root, const char *str)
{
    int slen, i, index;

    if (NULL == str) return -1;
    if (NULL == *root) {
        *root = create_node();
        if (NULL == *root) 
            return -2;
    }

    Trie *p = *root;
    slen = strlen(str);
    for (i = 0; i < slen; i ++) {
        index = str[i] - 'a';
        if (p->node[index] == NULL) {
            p->node[index] = create_node();
        }
        p = p->node[index];
        p->v ++;
    }

    return 0;
}

int find_trie(Trie *root, const char *str)
{
    int slen, i, index;
    Trie *p = root;

    if (NULL == root || NULL == str) 
        return -1;

    slen = strlen(str);
    for (i = 0; i < slen; i ++) {
        index = str[i] - 'a';
        if (p->node[index])
            p = p->node[index];
        else 
            return 0;
    }

    return p->v;
}

int free_trie(Trie *root)
{
    int i;

    if (root) {
        for (i = 0; i < MAX; i ++) {
            if (root->node[i])
                free_trie(root->node[i]);
        }
        free(root);
    }

    return 0;
}


int main()
{
    int i;
    const char *test[] = {
        "abcdef", "abmnb", "abckl", "acdfg", "adert", "abcokjh"
    } ;

    for (i = 0; i < 6; i ++) {
        bulid_trie(&root, test[i]);
    }

    int v = find_trie(root, "abc");
    printf(">>>>v: %d\n", v);

    free(root);
    return 0;
}


