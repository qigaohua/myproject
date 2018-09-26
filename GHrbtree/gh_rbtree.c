/**
 * @file gh_rbtree.c  
 * @brief   实现红黑树 c源文件
 * @author qigaohua, qigaohua168@163.com
 * @version 1.0.0
 * @date 2018-05-10
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "gh_rbtree.h"


#ifdef _DEBUG_
#define rbtree_print(fd, fmt, ...) \
    fprintf(fd, "%s:%d " fmt "\r\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define rbtree_print(fd, fmt, ...) 
#endif

static value_handle value_print = default_value_print;
static value_comple value_cmp = default_value_cmp;
static value_handle node_free = default_node_free;


/*
 * 默认释放节点函数
 */
void default_node_free (void *node)
{
    rbt_pt rbnode = (rbt_pt)node;

    if (node)
        free(rbnode);
}

/*
 * 默认的比较函数，Type类型是unsigned int
 */
int default_value_cmp(void *d1, void *d2)
{
    uint32_t *t1 = (uint32_t *)d1;
    uint32_t *t2 = (uint32_t *)d2;

    if (*t1 < *t2)
        return -1;
    else if (*t1 > *t2)
        return 1;
    else 
        return 0;

}


/*
 * 默认的打印函数，Type类型是unsigned int
 */
void default_value_print(void *d)
{
    rbt_pt t = (rbt_pt)d;

    node_info_print(t);
}


/*
 * 如果用户自定义Type类型，则需要重新设置打印和比较函数
 * 调用下面两个函数重新设置
 */
void rbtree_set_print (value_handle func)
{
    value_print = func;
}


void rbtree_set_cmp (value_comple func)
{
    value_cmp = func;
}


void rbtree_set_free (value_handle func)
{
    node_free = func;
}

/*
 * 如果Type类型不是默认的unsigned int ，则需要用户重新
 * 编写打印,比较和释放函数, 下面三个函数是简单的例子
 */
//#define EXAMPLE
#ifdef EXAMPLE
/**
 * 如果Type类型问struct test_s，成员c为键值
 */
typedef struct test_s {
    char a;
    char *b;
    int c;
} Type;
typedef struct test_s Type;

void example_value_print(void *d)
{

#define node_value(node) ((node)->data.c)

    rbt_pt node = (rbt_pt)d;

    if (node->parent)
        printf("%s : %d\t\t[父节点: %s : %d]\n", node->color == RED ? "red" : "black", node_value(node), 
                node->parent->color == RED ? "red" : "black", node_value(node->parent));	
    else 
        printf("%s : %d\t\t[根节点]\n", node->color == RED ? "red" : "black", node_value(node));	

}

int example_value_cmp(void *d1, void *d2)
{
    Type *t1 = (Type *)d1;
    Type *t2 = (Type *)d2;

    if (t1->c < t2->c)
        return -1;
    else if (t1->c > t2->c)
        return 1;
    else 
        return 0;

}

void example_node_free(void *d)
{
    rbt_pt node = (rbt_pt)d;

    if (node) {
        if (node->data.b)
            free(node->data.b);

        free(node);
    }
}
#endif


#if 0
static rbt_pt rbt_for_search(rbt_pt *root, Type data)
{
	rbt_pt s;

	s = *root;
	while (NULL != s) {
		if (s->data == data)
			return s;
		else 
			s = (s->data > data) ? (s->lchild) : (s-> rchild);
	}
	
	return s;
}
#endif


/**
 * @brief rbtree_for_cmp 添加节点时调用该函数，比较添加的值是否存在
 *
 * @param root   根节点
 * @param data   添加的值
 *
 * @return 若值已经存在，则返回NULL，不存在，则返回添加节点的父节点 
 */
static rbt_pt rbtree_for_cmp(rbt_pt *root, Type data)
{
    int ret;
	rbt_pt s, p;

	if (NULL == *root) {
		rbtree_print(stderr, "Ivalied param.");
		return NULL;
	}
	
	s = *root;
	while (NULL != s) {
		p = s;
        ret = value_cmp(&s->data, &data);
        if (ret == 0) 
            return NULL;
        else if (ret > 0) {
            s = s->lchild;
        } 
        else {
            s = s->rchild;
        }
#if 0
        if (value_cmp) {
            if (value_cmp(&s->data, &data) == 0)
                return NULL;
            else 
                s = (s->data > data) ? (s->lchild) : (s-> rchild);
        }
        else {
            if (s->data == data)
                return NULL;
            else 
                s = (s->data > data) ? (s->lchild) : (s-> rchild);

        }
#endif
	}
	
	return p;
}


/**
 * @brief rbt_new_node 创建一个新的节点
 *
 * @param d      新节点的值
 * @param color  新节点的颜色
 *
 * @return 
 */
rbt_pt rbt_new_node (Type d, Color color)
{
    rbt_pt new_node = (rbt_pt) malloc (sizeof(rbt_t));
    if (NULL == new_node) {
		rbtree_print(stderr, "molloc failed.");
        return NULL;
    }

    new_node->data = d;
    new_node->color = color;
    new_node->lchild = NULL;
    new_node->rchild = NULL;
    new_node->parent = NULL;

    return new_node;
}


/* 
 * 对红黑树的节点(x)进行左旋转
 *
 * 左旋示意图(对节点x进行左旋)：
 *      px                              px
 *     /                               /
 *    x                               y                
 *   /  \      --(左旋)-->           / \                #
 *  lx   y                          x  ry     
 *     /   \                       /  \
 *    ly   ry                     lx  ly  
 *
 *
 */
static void rbtree_left_rotate(rbt_pt *root, rbt_pt x)
{
    // 设置x的右孩子为y
    rbt_pt y = x->rchild;

    // 将 “y的左孩子” 设为 “x的右孩子”；
    // 如果y的左孩子非空，将 “x” 设为 “y的左孩子的父亲”
    x->rchild = y->lchild;
    if (y->lchild != NULL)
        y->lchild->parent = x;

    // 将 “x的父亲” 设为 “y的父亲”
    y->parent = x->parent;

    if (x->parent == NULL)
    {
        //tree = y;            // 如果 “x的父亲” 是空节点，则将y设为根节点
        *root = y;            // 如果 “x的父亲” 是空节点，则将y设为根节点
    }
    else
    {
        if (x->parent->lchild == x)
            x->parent->lchild = y;    // 如果 x是它父节点的左孩子，则将y设为“x的父节点的左孩子”
        else
            x->parent->rchild = y;    // 如果 x是它父节点的左孩子，则将y设为“x的父节点的左孩子”
    }
    
    // 将 “x” 设为 “y的左孩子”
    y->lchild = x;
    // 将 “x的父节点” 设为 “y”
    x->parent = y;
}


/* 
 * 对红黑树的节点(y)进行右旋转
 *
 * 右旋示意图(对节点y进行左旋)：
 *            py                               py
 *           /                                /
 *          y                                x                  
 *         /  \      --(右旋)-->            /  \                     #
 *        x   ry                           lx   y  
 *       / \                                   / \                   #
 *      lx  rx                                rx  ry
 * 
 */
static void rbtree_right_rotate(rbt_pt *root, rbt_pt y)
{
    // 设置x是当前节点的左孩子。
    rbt_pt x = y->lchild;

    // 将 “x的右孩子” 设为 “y的左孩子”；
    // 如果"x的右孩子"不为空的话，将 “y” 设为 “x的右孩子的父亲”
    y->lchild = x->rchild;
    if (x->rchild != NULL)
        x->rchild->parent = y;

    // 将 “y的父亲” 设为 “x的父亲”
    x->parent = y->parent;

    if (y->parent == NULL) 
    {
        //tree = x;            // 如果 “y的父亲” 是空节点，则将x设为根节点
        *root = x;            // 如果 “y的父亲” 是空节点，则将x设为根节点
    }
    else
    {
        if (y == y->parent->rchild)
            y->parent->rchild = x;    // 如果 y是它父节点的右孩子，则将x设为“y的父节点的右孩子”
        else
            y->parent->lchild = x;    // (y是它父节点的左孩子) 将x设为“x的父节点的左孩子”
    }

    // 将 “y” 设为 “x的右孩子”
    x->rchild = y;

    // 将 “y的父节点” 设为 “x”
    y->parent = x;
}


/**
 * @brief rbtree_insert_fixup 添加新节点后 红黑树失去平衡，调用该函数修正红黑树
 *
 * @param root  根节点
 * @param node  添加的新节点
 *
 * @return 
 */
int rbtree_insert_fixup(rbt_pt *root, rbt_pt node)
{
    /* case 1: 插入的节点是根节点 */
    if (*root == node) {
        node->color = BLACK;
        return 0;
    }

    /* case 2: 插入的节点的父节点是黑色 */
    if (rbnode_is_black(node->parent))
        return 0;

    /* case 3: 插入的节点的父节点是红色 */
    rbt_pt parent ;
    while ((parent = rbnode_parent(node)) && rbnode_is_red(parent)) {
        rbt_pt gparent = rbnode_parent(parent);
        rbt_pt uncle;

        /* case 3.1 叔叔节点是祖父节点的右节点 */
        if (gparent->lchild == parent) {
            uncle = gparent->rchild;
            /* case 3.1.1 叔叔节点是红色 */
            if (uncle && rbnode_is_red(uncle)) {
                rbnode_set_black(parent);
                rbnode_set_black(uncle);
                rbnode_set_red(gparent);
                node = gparent;
                continue;
            }
            else {
                /* case 3.1.2 叔叔节点是黑色,且当前节点是其父节点的右孩子 */
                if (parent->rchild == node) {
                    rbt_pt tmp = parent;
                    parent = node;
                    node = tmp;
                    rbtree_left_rotate(root, node);
                }

                /* case 3.1.3 叔叔节点是黑色,且当前节点是其父节点的左孩子 */
                rbnode_set_black(parent);
                rbnode_set_red(gparent);
                rbtree_right_rotate(root, gparent);
            }

        } 
        /* case 3.2 叔叔节点是祖父节点的左节点 */
        else {
            uncle = gparent->lchild;

            /* case 3.2.1 叔叔节点是红色 */
            if (uncle && rbnode_is_red(uncle)) {
                rbnode_set_black(parent);
                rbnode_set_black(uncle);
                rbnode_set_red(gparent);
                node = gparent;
                continue;
            }
            else {
                /* case 3.2.2 叔叔节点是黑色,且当前节点是其父节点的右孩子 */
                if (parent->lchild == node) {
                    rbt_pt tmp = parent;
                    parent = node;
                    node = tmp;
                    rbtree_right_rotate(root, node);
                }

                /* case 3.2.3 叔叔节点是黑色,且当前节点是其父节点的左孩子 */
                rbnode_set_black(parent);
                rbnode_set_red(gparent);
                rbtree_left_rotate(root, gparent);
            }
        }
    }

    rbnode_set_black(*root);

    return 0;
}


/**
 * @brief rbtree_for_insert 调用该函数插入新的节点
 *
 * @param root  根节点
 * @param data  要插入的值
 *
 * @return 
 */
int rbtree_for_insert(rbt_pt *root, Type data)
{
	rbt_pt child, p;


    child = rbt_new_node(data, BLACK);

	if (NULL == *root) 
		*root = child;
    else {
        p = rbtree_for_cmp(root, data);
        if (NULL == p) {
            rbtree_print(stderr, "Node already exist");
            node_free(child);
            return -1;
        }
        child->parent = p;

        if (value_cmp(&data, &p->data) > 0) 
            p->rchild = child;
        else 
            p->lchild = child;

#if 0
		if (data > p->data)
			p->rchild = child;
		else
			p->lchild = child;
#endif

        child->color = RED;
	}

    rbtree_insert_fixup(root, child);

	return 0;
}


/**
 * @brief rbtree_search 根据键值查找节点
 *
 * @param root  根节点
 * @param data  键值
 *
 * @return 
 */
rbt_pt rbtree_search (rbt_pt *root, Type data) 
{
    if (*root == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return NULL;
    }

    int ret = value_cmp(&(*root)->data, &data);
    if (ret == 0)
        return *root;
    else if (ret > 0) 
        return rbtree_search(&(*root)->lchild, data);
    else
        return rbtree_search(&(*root)->rchild, data);

#if 0
    if ((*root)->data == data)
        return *root;
    else if ((*root)->data > data) 
        return rbtree_search(&(*root)->lchild, data);
    else
        return rbtree_search(&(*root)->rchild, data);
#endif
}


/**
 * @brief rbtree_max_node 以某个节点为根，查找最大值(如果以树的根节点，则查找整个树的最大值)
 *
 * @param node  树的某个节点
 *
 * @return 
 */
rbt_pt rbtree_max_node(rbt_pt node)
{
    if (node == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return NULL;
    }

    rbt_pt max_node = node;
    while (max_node->rchild) 
        max_node = max_node->rchild;

    return max_node;
}


/**
 * @brief rbtree_min_node 同上(最小值)
 *
 * @param node
 *
 * @return 
 */
rbt_pt rbtree_min_node(rbt_pt node)
{
    if (node == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return NULL;
    }

    rbt_pt min_node = node;
    while (min_node->lchild) 
        min_node = min_node->lchild;

    return min_node;
}


/*
 * @brief rbtree_successor 查找某个节点的后继节点(即查找"树中数据值大于该结点"的"最小结点")
 *
 * @param node 树中某个节点
 *
 * @return  
 */
rbt_pt rbtree_successor(rbt_pt node)
{
    if (node == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return NULL;
    }

    rbt_pt parent;

    /* case 1: 该节点有右孩子 */
    if (node->rchild)
        return rbtree_min_node(node->rchild);

    parent = node->parent;
    /* case 2: 没有右孩子，且该节点是其父节点的左孩子 */
    if (parent->lchild == node)
        return parent;

    /* case 3: 没有右孩子，且该节点是其父节点的右孩子 */
    while (parent != NULL && node == parent->rchild) {
        node = parent;
        parent = parent->parent;
    }

    return parent;
}


/*
 * @brief rbtree_predecessor 查找某个节点的前驱节点(即查找"树中数据值小于该结点"的"最大结点")
 *
 * @param node 树中某个节点
 *
 * @return  
 */
rbt_pt rbtree_predecessor(rbt_pt node) 
{
    if (node == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return NULL;
    }

    rbt_pt parent;

    /* case 1: 该节点有左孩子 */
    if (node->lchild)
        return rbtree_max_node(node->lchild);

    parent = node->parent;
    /* case 2: 没有左孩子，且该节点是其父节点的右孩子 */
    if (parent->rchild == node)
        return parent;

    /* case 3: 没有左孩子，且该节点是其父节点的左孩子 */
    while (parent != NULL && node == parent->lchild) {
        node = parent;
        parent = parent->parent;
    }

    return parent;

}


/**
 * @brief rbtree_delete_fixup 删除某个节点后，红黑树失去平衡，调用该函数重新修正
 *
 * @param root 根节点
 * @param node 待修正节点
 * @param parent
 *
 * @return 
 */
int rbtree_delete_fixup(rbt_pt *root, rbt_pt node, rbt_pt parent) 
{
    rbt_pt brother = NULL;

    if (*root == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return -1;
    }

    while ((!node || rbnode_is_black(node)) && node != *root) {
        if (parent->lchild == node) {
            brother = parent->rchild;
            /* case 1: 兄弟节点是红色 */
            if (rbnode_is_red(brother)) {
                rbnode_set_black(brother);
                rbnode_set_red(parent);
                rbtree_left_rotate(root, parent);
                brother = parent->rchild;
            }
            /* Case 2: 兄弟是黑色，且俩个孩子也都是黑色的 */
            if ((!brother->lchild || rbnode_is_black(brother->lchild)) && 
                    (!brother->lchild || rbnode_is_black(brother->rchild))) {
                rbnode_set_red(brother);
                node = parent;
                parent = rbnode_parent(node);
            } 
            else {
                /* Case 3: 兄弟是黑色的，并且左孩子是红色，右孩子为黑色  */
                if (!brother->rchild || rbnode_is_black(brother->rchild)) {
                    rbnode_set_black(brother->lchild);
                    rbnode_set_red(brother);
                    rbtree_right_rotate(root, brother);
                    brother = parent->rchild;

                }
                /* Case 4: 兄弟是黑色的；并且右孩子是红色的，左孩子任意颜色 */
                brother->color = parent->color;
                rbnode_set_black(parent);
                rbnode_set_black(brother->rchild);
                rbtree_left_rotate(root, parent);
                node = *root;
                break;
            }
        }
        else {
            brother = parent->lchild;
            /* case 1: 兄弟节点是红色 */
            if (rbnode_is_red(brother)) {
                rbnode_set_black(brother);
                rbnode_set_red(parent);
                rbtree_right_rotate(root, parent);
                brother = parent->lchild;
            }
            /* Case 2: 兄弟是黑色，且俩个孩子也都是黑色的 */
            if ((!brother->lchild || rbnode_is_black(brother->lchild)) && 
                    (!brother->lchild || rbnode_is_black(brother->rchild))) {
                rbnode_set_red(brother);
                node = parent;
                parent = rbnode_parent(node);
            } 
            else {
                /* Case 3: 兄弟是黑色的，并且左孩子是红色，右孩子为黑色  */
                if (!brother->lchild || rbnode_is_black(brother->lchild)) {
                    rbnode_set_black(brother->rchild);
                    rbnode_set_red(brother);
                    rbtree_left_rotate(root, brother);
                    brother = parent->lchild;

                }
                /* Case 4: 兄弟是黑色的；并且右孩子是红色的，左孩子任意颜色 */
                brother->color = parent->color;
                rbnode_set_black(parent);
                rbnode_set_black(brother->lchild);
                rbtree_right_rotate(root, parent);
                node = *root;
                break;
            }
        }
    }

    if (node)
        rbnode_set_black(node);

    return 0;
}


/**
 * @brief rbtree_for_delete 从树中删除某个节点
 *
 * @param root
 * @param data
 *
 * @return 
 */
int rbtree_for_delete(rbt_pt *root, Type data)
{
    rbt_pt d_node = NULL;

    if (*root == NULL) {
        rbtree_print(stderr, "Invalid param.");
        return -1;
    }

    d_node = rbtree_search(root, data);
    if (d_node == NULL) {
        rbtree_print(stdout, "The node not exist.");
        return 0;
    }

    rbt_pt child = NULL, parent = NULL;
    Color color;

    if (d_node->lchild && d_node->rchild) {
        rbt_pt replace = NULL;

        /* 寻找替代删除节点位置的节点replace */
        replace = rbtree_successor(d_node);

        /* 如果删除的节点不是根节点, 即存在父节点 */
        if (rbnode_parent(d_node)) {
            if (rbnode_parent(d_node)->lchild == d_node)
                rbnode_parent(d_node)->lchild = replace;
            else 
                rbnode_parent(d_node)->rchild = replace;
        } 
        else 
            *root = replace;

        color = replace->color;
        child = replace->rchild;

        parent = rbnode_parent(replace);

        /* 如果替代节点就是删除节点的右节点 */
        if (parent == d_node) {
            parent = replace; 
        } 
        else {
            if (child)
                child->parent = parent;
            parent->lchild = child;

            replace->rchild = d_node->rchild;
            d_node->rchild->parent = replace;
        }

        replace->parent = d_node->parent;
        replace->color = d_node->color;
        replace->lchild = d_node->lchild;
        d_node->lchild->parent = replace;

        if (color == BLACK)
            rbtree_delete_fixup(root, child, parent)
            ;
        node_free(d_node);

        return 0;
    }

    child = d_node->lchild ? d_node->lchild : d_node->rchild;
    parent = d_node->parent;

    if (child)
        child->parent = parent;

    color = d_node->color;

    if (parent) {
        if (parent->lchild == d_node)
            parent->lchild = child;
        else 
            parent->rchild = child; 
    }
    else
        *root = child;
        
    if (color == BLACK) 
        rbtree_delete_fixup(root, child, parent)
            ;

    node_free (d_node);
        
	return 0;




#if 0
	rbt_pt p = *root, s, parent;

	if (NULL == p) {
		// printf("bst is null\n");
		return 0;
	}

	if (p->data == data) {
		if ((NULL == p->lchild) && (NULL == p->rchild)) {
			*root = NULL;
		} else if ((NULL != p->lchild) && (NULL == p->rchild)) {
			*root = p->lchild;
		} else if ((NULL == p->lchild) && (NULL != p->rchild)) {
			*root = p->rchild;
		} else {
			s = p->rchild;
			if (NULL == s->lchild)
				s->lchild = p->lchild;
			else {
				while (NULL != s->lchild) {
					parent = s;
					s = s->lchild;
				}
				parent->lchild = s->rchild;
				s->lchild = p->lchild;
				s->rchild = p->rchild;
			}
            *root = s;
        }
        free(p);

    } else if (p->data > data) {
		bst_for_delete(&(p->lchild), data);
	} else {
		bst_for_delete(&(p->rchild), data);
	}

	return 0;
#endif
}


/**
 * @brief node_info_print 打印节点信息
 *
 * @param node
 */
void node_info_print(rbt_pt node)
{
    if (node->parent)
        printf("%s : %02d\t\t[父节点: %s : %d]\n", node->color == RED ? "red" : "black", node->data, 
                node->parent->color == RED ? "red" : "black", node->parent->data);	
    else 
        printf("%s : %d\t\t[根节点]\n", node->color == RED ? "red" : "black", node->data);	

}


/* 先序遍历 */
void rbtree_for_preorder(rbt_pt root)
{
    if (NULL != root) {
        value_print(root);
        rbtree_for_preorder(root->lchild);
		rbtree_for_preorder(root->rchild);
	}
}


/* 中序遍历 */
void rbtree_for_inorder(rbt_pt root)
{
	if (NULL != root) {
        rbtree_for_inorder(root->lchild);
        value_print(root);
        rbtree_for_inorder(root->rchild);
	}
}


/* 后序遍历 */
void rbtree_for_postorder(rbt_pt root)
{
	if (NULL != root) {
		rbtree_for_postorder(root->lchild);
        rbtree_for_postorder(root->rchild);
        value_print(root);
	}
}


/*************************************************************************/
/*                        Red&Black tree test                            */
/*************************************************************************/

#define TEST
#ifdef TEST
#include <time.h>

int main ()
{
    int i;  
	rbt_pt root = NULL;  

    srand((unsigned)time(NULL));

#ifdef EXAMPLE
    rbtree_set_cmp(example_value_cmp);
    rbtree_set_print(example_value_print);
#endif

    Type v;
	for (i = 0; i < 90; i++) {  
        v = rand() % 100; 
		rbtree_for_insert(&root, v);  
	}  

	printf("\ndelete before\n");  
	rbtree_for_preorder(root);  
	printf("\n");  

	for (i = 0; i < 30; i++) {  
        v = rand() % 100; 
	    rbtree_for_delete(&root, v);  
	}  

	printf("delete after\n");  
	rbtree_for_preorder(root);  
	  
	return 0;  
}


#endif


