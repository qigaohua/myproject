#ifndef __GH_RB_TREE__
#define __GH_RB_TREE__


#define False 0
#define True (!(False))
typedef int BOOL;

#define rbnode_is_red(node)    ((node)->color == RED)
#define rbnode_is_black(node)  ((node)->color == BLACK)
#define rbnode_set_black(node) ((node)->color = BLACK)
#define rbnode_set_red(node)   ((node)->color = RED)

#define rbnode_parent(node) ((node)->parent)

#if 0
/* for test */
struct test_s {
    char a;
    short b;
    int c;  // 键值
};
#endif

typedef enum {
    RED   = 0,
    BLACK = 1,
} Color;

// typedef struct test_s Type;
typedef unsigned int Type;
typedef void (*value_handle)(void *);
typedef int (*value_comple)(void *, void*);


typedef struct _red_black_tree rbt_t, *rbt_pt;
struct _red_black_tree {
	Type   data;
    Color  color; 
	rbt_t  *lchild;
    rbt_t  *rchild;
    rbt_t  *parent;
} ;


/* 修正红黑树 */
int rbtree_insert_fixup(rbt_pt *root, rbt_pt node);
int rbtree_delete_fixup(rbt_pt *root, rbt_pt node, rbt_pt parent) ;

/* 默认函数 */
void node_info_print(rbt_pt node);
void default_value_print(void *d);
int default_value_cmp(void *d1, void *d2);
void default_node_free (void *node);





/* API */

rbt_pt rbtree_new_node (Type d, Color color);

/* 打印 */
void rbtree_for_preorder(rbt_pt root);
void rbtree_for_inorder(rbt_pt root);
void rbtree_for_postorder(rbt_pt root);

/* 设置用户自己的打印和比较节点函数 */
void rbtree_set_print (value_handle func);
void rbtree_set_cmp (value_comple func);
void rbtree_set_free (value_handle func);

/* 前驱后继 */
rbt_pt rbtree_predecessor(rbt_pt node); 
rbt_pt rbtree_successor(rbt_pt node);

/* 最大最小 */
rbt_pt rbtree_max_node(rbt_pt node);
rbt_pt rbtree_min_node(rbt_pt node);

/* 查找存在节点 */
rbt_pt rbtree_search (rbt_pt *root, Type data); 

/* 添加删除 */
int rbtree_for_insert(rbt_pt *root, Type data);
int rbtree_for_delete(rbt_pt *root, Type data);

/* 销毁 */
void rbtree_destroy(rbt_pt node);
#endif

