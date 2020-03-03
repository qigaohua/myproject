/*
 * A generic kernel FIFO implementation
 *
 * Copyright (C) 2009/2010 Stefani Seibold <stefani@seibold.net>
 */

/*
 * 修改内核kfifo用于用户应用程序
 *
 * 只要满足以下要求, kfifo 操作便可以实现不加锁, 从而提高性能
 * 1. 只有一个 reader 和 一个 writer
 * 2. 不调用 kfifo_reset()
 * 3. 如果有调用 kfifo_reset_out(), 只在出队线程中调用
 *
 * 而对于多个 writer 对应一个 reader 的情况, 只需要在 writer (入队线程)加锁即可
 * 而对于多个 reader 对应一个 writer 的情况, 只需要在 reader (出队线程)加锁即可
 */


// #include <linux/kernel.h>
// #include <linux/export.h>
// #include <linux/slab.h>
// #include <linux/err.h>
// #include <linux/log2.h>
// #include <linux/uaccess.h>
// #include <linux/kfifo.h>

#include <stdlib.h>
#include <memory.h>
#include "kfifo.h"


#define min(x,y) ((x)<(y)?(x):(y))

// 判断x是否是2的次方
#define is_power_of_2(x) ((x) != 0 && (((x) & ((x)-1)) == 0))

// return 最接近v且比v大的2的n次幂, 如v=5，6，7，则返回 8
static inline unsigned int roundup_pow_of_two(unsigned int v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

// return 最接近v且比v小的2的n次幂, 如v=5，6，7，则返回 4
static unsigned int rounddown_pow_of_two(unsigned int n) {
    n|=n>>1; n|=n>>2; n|=n>>4; n|=n>>8; n|=n>>16;
    return (n+1) >> 1;
}


/*
 * internal helper to calculate the unused elements in a fifo
 */
static inline unsigned int kfifo_unused(struct __kfifo *fifo)
{
    return (fifo->mask + 1) - (fifo->in - fifo->out);
}

//qgh: fix gfp_t 
int __kfifo_alloc(struct __kfifo *fifo, unsigned int size,
		size_t esize)
{
	/*
	 * round up to the next power of 2, since our 'let the indices
	 * wrap' technique works only in this case.
	 */
	size = roundup_pow_of_two(size);

	fifo->in = 0;
	fifo->out = 0;
	fifo->esize = esize;

	if (size < 2) {
		fifo->data = NULL;
		fifo->mask = 0;
		return -EINVAL;
	}

	// fifo->data = kmalloc_array(esize, size, gfp_mask);
	fifo->data = calloc(size, esize);

	if (!fifo->data) {
		fifo->mask = 0;
		return -ENOMEM;
	}
	fifo->mask = size - 1;

	return 0;
}

//qgh: fix kfree
void __kfifo_free(struct __kfifo *fifo)
{
	// kfree(fifo->data);
	free(fifo->data);
	fifo->in = 0;
	fifo->out = 0;
	fifo->esize = 0;
	fifo->data = NULL;
	fifo->mask = 0;
}

int __kfifo_init(struct __kfifo *fifo, void *buffer,
        unsigned int size, size_t esize)
{
    size /= esize;
    size = rounddown_pow_of_two(size);

    fifo->in = 0;
    fifo->out = 0;
    fifo->esize = esize;
    fifo->data = buffer;

    if (size < 2) {
        fifo->mask = 0;
        return -EINVAL;
    }
    fifo->mask = size - 1;

    return 0;
}

static void kfifo_copy_in(struct __kfifo *fifo, const void *src,
        unsigned int len, unsigned int off)
{
    unsigned int size = fifo->mask + 1;
    unsigned int esize = fifo->esize;
    unsigned int l;

    off &= fifo->mask;
    if (esize != 1) {
        off *= esize;
        size *= esize;
        len *= esize;
    }
    l = min(len, size - off);

    memcpy(fifo->data + off, src, l);
    memcpy(fifo->data, src + l, len - l);
    /*
     * make sure that the data in the fifo is up to date before
     * incrementing the fifo->in index counter
     */
    smp_wmb();
}

unsigned int __kfifo_in(struct __kfifo *fifo,
        const void *buf, unsigned int len)
{
    unsigned int l;

    l = kfifo_unused(fifo);
    if (len > l)
        len = l;

    kfifo_copy_in(fifo, buf, len, fifo->in);
    fifo->in += len;
    return len;
}

static void kfifo_copy_out(struct __kfifo *fifo, void *dst,
        unsigned int len, unsigned int off)
{
    unsigned int size = fifo->mask + 1;
    unsigned int esize = fifo->esize;
    unsigned int l;

    off &= fifo->mask;
    if (esize != 1) {
        off *= esize;
        size *= esize;
        len *= esize;
    }
    l = min(len, size - off);

    memcpy(dst, fifo->data + off, l);
    memcpy(dst + l, fifo->data, len - l);
    /*
     * make sure that the data is copied before
     * incrementing the fifo->out index counter
     */
    smp_wmb();
}

unsigned int __kfifo_out_peek(struct __kfifo *fifo,
        void *buf, unsigned int len)
{
    unsigned int l;

    l = fifo->in - fifo->out;
    if (len > l)
        len = l;

    kfifo_copy_out(fifo, buf, len, fifo->out);
    return len;
}

unsigned int __kfifo_out(struct __kfifo *fifo,
        void *buf, unsigned int len)
{
    len = __kfifo_out_peek(fifo, buf, len);
    fifo->out += len;
    return len;
}

unsigned int __kfifo_max_r(unsigned int len, size_t recsize)
{
    unsigned int max = (1 << (recsize << 3)) - 1;

    if (len > max)
        return max;
    return len;
}


#define	__KFIFO_PEEK(data, out, mask) \
    ((data)[(out) & (mask)])
/*
 * __kfifo_peek_n internal helper function for determinate the length of
 * the next record in the fifo
 */
static unsigned int __kfifo_peek_n(struct __kfifo *fifo, size_t recsize)
{
    unsigned int l;
    unsigned int mask = fifo->mask;
    unsigned char *data = fifo->data;

    l = __KFIFO_PEEK(data, fifo->out, mask);

    if (--recsize)
        l |= __KFIFO_PEEK(data, fifo->out + 1, mask) << 8;

    return l;
}

#define	__KFIFO_POKE(data, in, mask, val) \
    ( \
      (data)[(in) & (mask)] = (unsigned char)(val) \
    )

/*
 * __kfifo_poke_n internal helper function for storeing the length of
 * the record into the fifo
 */
static void __kfifo_poke_n(struct __kfifo *fifo, unsigned int n, size_t recsize)
{
    unsigned int mask = fifo->mask;
    unsigned char *data = fifo->data;

    __KFIFO_POKE(data, fifo->in, mask, n);

    if (recsize > 1)
        __KFIFO_POKE(data, fifo->in + 1, mask, n >> 8);
}

unsigned int __kfifo_len_r(struct __kfifo *fifo, size_t recsize)
{
    return __kfifo_peek_n(fifo, recsize);
}

unsigned int __kfifo_in_r(struct __kfifo *fifo, const void *buf,
        unsigned int len, size_t recsize)
{
    if (len + recsize > kfifo_unused(fifo))
        return 0;

    __kfifo_poke_n(fifo, len, recsize);

    kfifo_copy_in(fifo, buf, len, fifo->in + recsize);
    fifo->in += len + recsize;
    return len;
}

static unsigned int kfifo_out_copy_r(struct __kfifo *fifo,
        void *buf, unsigned int len, size_t recsize, unsigned int *n)
{
    *n = __kfifo_peek_n(fifo, recsize);

    if (len > *n)
        len = *n;

    kfifo_copy_out(fifo, buf, len, fifo->out + recsize);
    return len;
}

unsigned int __kfifo_out_peek_r(struct __kfifo *fifo, void *buf,
        unsigned int len, size_t recsize)
{
    unsigned int n;

    if (fifo->in == fifo->out)
        return 0;

    return kfifo_out_copy_r(fifo, buf, len, recsize, &n);
}

unsigned int __kfifo_out_r(struct __kfifo *fifo, void *buf,
        unsigned int len, size_t recsize)
{
    unsigned int n;

    if (fifo->in == fifo->out)
        return 0;

    len = kfifo_out_copy_r(fifo, buf, len, recsize, &n);
    fifo->out += n + recsize;
    return len;
}

void __kfifo_skip_r(struct __kfifo *fifo, size_t recsize)
{
    unsigned int n;

    n = __kfifo_peek_n(fifo, recsize);
    fifo->out += n + recsize;
}


// 主要是内核从用户空间获取数据和DMA,在用户应用程序用不上，注释
// static unsigned long kfifo_copy_from_user(struct __kfifo *fifo,
// 	const void __user *from, unsigned int len, unsigned int off,
// 	unsigned int *copied)
// {
// 	unsigned int size = fifo->mask + 1;
// 	unsigned int esize = fifo->esize;
// 	unsigned int l;
// 	unsigned long ret;

// 	off &= fifo->mask;
// 	if (esize != 1) {
// 		off *= esize;
// 		size *= esize;
// 		len *= esize;
// 	}
// 	l = min(len, size - off);

// 	ret = copy_from_user(fifo->data + off, from, l);
// 	if (unlikely(ret))
// 		ret = DIV_ROUND_UP(ret + len - l, esize);
// 	else {
// 		ret = copy_from_user(fifo->data, from + l, len - l);
// 		if (unlikely(ret))
// 			ret = DIV_ROUND_UP(ret, esize);
// 	}
// 	/*
// 	 * make sure that the data in the fifo is up to date before
// 	 * incrementing the fifo->in index counter
// 	 */
// 	smp_wmb();
// 	*copied = len - ret * esize;
// 	/* return the number of elements which are not copied */
// 	return ret;
// }

// int __kfifo_from_user(struct __kfifo *fifo, const void __user *from,
// 		unsigned long len, unsigned int *copied)
// {
// 	unsigned int l;
// 	unsigned long ret;
// 	unsigned int esize = fifo->esize;
// 	int err;

// 	if (esize != 1)
// 		len /= esize;

// 	l = kfifo_unused(fifo);
// 	if (len > l)
// 		len = l;

// 	ret = kfifo_copy_from_user(fifo, from, len, fifo->in, copied);
// 	if (unlikely(ret)) {
// 		len -= ret;
// 		err = -EFAULT;
// 	} else
// 		err = 0;
// 	fifo->in += len;
// 	return err;
// }
// // EXPORT_SYMBOL(__kfifo_from_user);

// static unsigned long kfifo_copy_to_user(struct __kfifo *fifo, void __user *to,
// 		unsigned int len, unsigned int off, unsigned int *copied)
// {
// 	unsigned int l;
// 	unsigned long ret;
// 	unsigned int size = fifo->mask + 1;
// 	unsigned int esize = fifo->esize;

// 	off &= fifo->mask;
// 	if (esize != 1) {
// 		off *= esize;
// 		size *= esize;
// 		len *= esize;
// 	}
// 	l = min(len, size - off);

// 	ret = copy_to_user(to, fifo->data + off, l);
// 	if (unlikely(ret))
// 		ret = DIV_ROUND_UP(ret + len - l, esize);
// 	else {
// 		ret = copy_to_user(to + l, fifo->data, len - l);
// 		if (unlikely(ret))
// 			ret = DIV_ROUND_UP(ret, esize);
// 	}
// 	/*
// 	 * make sure that the data is copied before
// 	 * incrementing the fifo->out index counter
// 	 */
// 	smp_wmb();
// 	*copied = len - ret * esize;
// 	/* return the number of elements which are not copied */
// 	return ret;
// }

// int __kfifo_to_user(struct __kfifo *fifo, void __user *to,
// 		unsigned long len, unsigned int *copied)
// {
// 	unsigned int l;
// 	unsigned long ret;
// 	unsigned int esize = fifo->esize;
// 	int err;

// 	if (esize != 1)
// 		len /= esize;

// 	l = fifo->in - fifo->out;
// 	if (len > l)
// 		len = l;
// 	ret = kfifo_copy_to_user(fifo, to, len, fifo->out, copied);
// 	if (unlikely(ret)) {
// 		len -= ret;
// 		err = -EFAULT;
// 	} else
// 		err = 0;
// 	fifo->out += len;
// 	return err;
// }
// EXPORT_SYMBOL(__kfifo_to_user);

// static int setup_sgl_buf(struct scatterlist *sgl, void *buf,
// 		int nents, unsigned int len)
// {
// 	int n;
// 	unsigned int l;
// 	unsigned int off;
// 	struct page *page;

// 	if (!nents)
// 		return 0;

// 	if (!len)
// 		return 0;

// 	n = 0;
// 	page = virt_to_page(buf);
// 	off = offset_in_page(buf);
// 	l = 0;

// 	while (len >= l + PAGE_SIZE - off) {
// 		struct page *npage;

// 		l += PAGE_SIZE;
// 		buf += PAGE_SIZE;
// 		npage = virt_to_page(buf);
// 		if (page_to_phys(page) != page_to_phys(npage) - l) {
// 			sg_set_page(sgl, page, l - off, off);
// 			sgl = sg_next(sgl);
// 			if (++n == nents || sgl == NULL)
// 				return n;
// 			page = npage;
// 			len -= l - off;
// 			l = off = 0;
// 		}
// 	}
// 	sg_set_page(sgl, page, len, off);
// 	return n + 1;
// }

// static unsigned int setup_sgl(struct __kfifo *fifo, struct scatterlist *sgl,
// 		int nents, unsigned int len, unsigned int off)
// {
// 	unsigned int size = fifo->mask + 1;
// 	unsigned int esize = fifo->esize;
// 	unsigned int l;
// 	unsigned int n;

// 	off &= fifo->mask;
// 	if (esize != 1) {
// 		off *= esize;
// 		size *= esize;
// 		len *= esize;
// 	}
// 	l = min(len, size - off);

// 	n = setup_sgl_buf(sgl, fifo->data + off, nents, l);
// 	n += setup_sgl_buf(sgl + n, fifo->data, nents - n, len - l);

// 	return n;
// }

// unsigned int __kfifo_dma_in_prepare(struct __kfifo *fifo,
// 		struct scatterlist *sgl, int nents, unsigned int len)
// {
// 	unsigned int l;

// 	l = kfifo_unused(fifo);
// 	if (len > l)
// 		len = l;

// 	return setup_sgl(fifo, sgl, nents, len, fifo->in);
// }
// // EXPORT_SYMBOL(__kfifo_dma_in_prepare);

// unsigned int __kfifo_dma_out_prepare(struct __kfifo *fifo,
// 		struct scatterlist *sgl, int nents, unsigned int len)
// {
// 	unsigned int l;

// 	l = fifo->in - fifo->out;
// 	if (len > l)
// 		len = l;

// 	return setup_sgl(fifo, sgl, nents, len, fifo->out);
// }
// EXPORT_SYMBOL(__kfifo_dma_out_prepare);

// EXPORT_SYMBOL(__kfifo_skip_r);

// int __kfifo_from_user_r(struct __kfifo *fifo, const void __user *from,
// 	unsigned long len, unsigned int *copied, size_t recsize)
// {
// 	unsigned long ret;

// 	len = __kfifo_max_r(len, recsize);

// 	if (len + recsize > kfifo_unused(fifo)) {
// 		*copied = 0;
// 		return 0;
// 	}

// 	__kfifo_poke_n(fifo, len, recsize);

// 	ret = kfifo_copy_from_user(fifo, from, len, fifo->in + recsize, copied);
// 	if (unlikely(ret)) {
// 		*copied = 0;
// 		return -EFAULT;
// 	}
// 	fifo->in += len + recsize;
// 	return 0;
// }
// EXPORT_SYMBOL(__kfifo_from_user_r);

// int __kfifo_to_user_r(struct __kfifo *fifo, void __user *to,
// 	unsigned long len, unsigned int *copied, size_t recsize)
// {
// 	unsigned long ret;
// 	unsigned int n;

// 	if (fifo->in == fifo->out) {
// 		*copied = 0;
// 		return 0;
// 	}

// 	n = __kfifo_peek_n(fifo, recsize);
// 	if (len > n)
// 		len = n;

// 	ret = kfifo_copy_to_user(fifo, to, len, fifo->out + recsize, copied);
// 	if (unlikely(ret)) {
// 		*copied = 0;
// 		return -EFAULT;
// 	}
// 	fifo->out += n + recsize;
// 	return 0;
// }
// EXPORT_SYMBOL(__kfifo_to_user_r);

// unsigned int __kfifo_dma_in_prepare_r(struct __kfifo *fifo,
// 	struct scatterlist *sgl, int nents, unsigned int len, size_t recsize)
// {
// 	BUG_ON(!nents);

// 	len = __kfifo_max_r(len, recsize);

// 	if (len + recsize > kfifo_unused(fifo))
// 		return 0;

// 	return setup_sgl(fifo, sgl, nents, len, fifo->in + recsize);
// }
// EXPORT_SYMBOL(__kfifo_dma_in_prepare_r);

// void __kfifo_dma_in_finish_r(struct __kfifo *fifo,
// 	unsigned int len, size_t recsize)
// {
// 	len = __kfifo_max_r(len, recsize);
// 	__kfifo_poke_n(fifo, len, recsize);
// 	fifo->in += len + recsize;
// }
// EXPORT_SYMBOL(__kfifo_dma_in_finish_r);

// unsigned int __kfifo_dma_out_prepare_r(struct __kfifo *fifo,
// 	struct scatterlist *sgl, int nents, unsigned int len, size_t recsize)
// {
// 	BUG_ON(!nents);

// 	len = __kfifo_max_r(len, recsize);

// 	if (len + recsize > fifo->in - fifo->out)
// 		return 0;

// 	return setup_sgl(fifo, sgl, nents, len, fifo->out + recsize);
// }
// EXPORT_SYMBOL(__kfifo_dma_out_prepare_r);

// void __kfifo_dma_out_finish_r(struct __kfifo *fifo, size_t recsize)
// {
// 	unsigned int len;

// 	len = __kfifo_peek_n(fifo, recsize);
// 	fifo->out += len + recsize;
// }
// EXPORT_SYMBOL(__kfifo_dma_out_finish_r);
