#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// 暴力匹配
int bf(const char *t, const char *p)
{
    int i = 0, j = 0;
    int tlen, plen;

    if (NULL == p || NULL == t)
        return -1;

    tlen = strlen(t); 
    plen = strlen(p);

    while (i < tlen && j < plen) {
        if (t[i] == p[j]) {
            i ++;
            j ++;
        }
        else {
            i = i - j + 1;
            j = 0;
        }
    }

    if (j == plen)
        return i - j;

    return 0;
}


int get_next(const char *p, int *next, int size)
{
    int plen, j = 0, k = -1;
    if (p == NULL || next == NULL ||
            (plen = strlen(p)) > size)
        return -1;

    next[0] = -1;
    while (j < plen-1) {
        if (k == -1 || p[j] == p[k]) {
            next[++j] = ++k;
        }
        else {
            k = next[k];
        }
    }

    return 0;
}

// KMP 算法匹配
int kmp(const char *t, const char *p, int *next)
{
    int i = 0, j = 0;
    int tlen, plen;

    if (NULL == p || NULL == t)
        return -1;

    tlen = strlen(t); 
    plen = strlen(p);

    while (i < tlen && j < plen) {
        if (j == -1 || t[i] == p[j]) {
            i ++;
            j ++;
        }
        else {
            // i = i - j + 1;
            j = next[j];
        }
    }

    if (j == plen)
        return i - j;

    return 0;

}

int main()
{
    const char *t = "abcdefghiqsdcf1abababcabgyfsfbhgdsvbvfbgfdbdvdf";
    const char *p = "abababca";

    int next[64] = {0};
    get_next(p, next, sizeof(next) / sizeof(next[0]));
    unsigned i = 0;
    for (; i < strlen(p); i ++)
        printf("%d\t", next[i]);

    // int offset = bf(t, p);
    int offset = kmp(t, p, next);
    if (offset > 0) 
        printf("match string[%s] at string[%s] offset %d\n", p, t, offset);
    else 
        printf("no match\n");

    return 0;
}



