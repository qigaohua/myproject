#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>


static unsigned int BKDRHash(char *str)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;

    while (*str)
    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}


static uint32_t rpc_generate_uuid(int fd, uint32_t ip, uint16_t port)
{
    char buf[128] = {0};

    snprintf(buf, sizeof buf, "%08x%08x%04x", fd, ip, port);
    return BKDRHash(buf);
}

static uint64_t rpc_get_msec(void)
{
    struct timespec ts;
    uint64_t msec;

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        fprintf(stderr, "%s:%d clock_gettime failed: %m !!!", __FILE__,
                __LINE__);
        return 0;
    }
    msec = ts.tv_sec * 1000 + ts.tv_nsec/1000/1000;

    return msec;
}


/**
 * @brief rio_readn 一次性读n个字节
 *
 * @param fd
 * @param buf
 * @param n
 *
 * @return
 */
static ssize_t rio_readn(int fd, void *buf, size_t n)
{
    size_t nleft = n;
    ssize_t nread;
    char *ptr = (char *)buf;

    while (nleft > 0) {
        if ((nread = read(fd, ptr, nleft)) < 0) {
            if (errno == EINTR)
                nread = 0;
            else
                return (-1);   // error
        }
        else if (nread == 0)   // EOF
            break;

        ptr += nread;
        nleft -= nread;
    }

    return (n - nleft);
}



/**
 * @brief rio_writen 一次性写n个字节
 *
 * @param fd
 * @param buf
 * @param n
 *
 * @return
 */
static ssize_t rio_writen(int fd, void *buf, size_t n)
{
    size_t nleft = n;
    ssize_t nwrite;

    char *ptr = (char *)buf;

    while (nleft > 0) {
        if ((nwrite = write(fd, ptr, nleft)) <= 0) {
            if (errno == EINTR)
                nwrite = 0;
            else
                return (-1); // error
        }

        ptr += nwrite;
        nleft -= nwrite;
    }

    return n;
}

