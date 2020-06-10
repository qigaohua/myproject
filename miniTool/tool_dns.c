#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/**********************************************************
 *int getaddrinfo(const char *node, const char *service,
 *                  const struct addrinfo *hints,
 *                  struct addrinfo **res);
 ********************************************************** */

int check_dns(const char* domain)
{
    // struct addrinfo hints;
    struct addrinfo *res, *rp;
    char buff[128] = {0};
    int error;

    if ((error = getaddrinfo(domain, NULL, NULL, &res)) != 0) {
        fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
        return EXIT_FAILURE;
    }

    printf ("[%s]\n", domain);
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        memset(buff, 0, 128);
        /* tcp == 6 */
        if (rp->ai_family == AF_INET && rp->ai_protocol == 6) {
            inet_ntop(AF_INET, &(((struct sockaddr_in *)rp->ai_addr)->sin_addr),
                    buff, 128);

            printf("\tip: %s\n", buff);
        } else if (rp->ai_family == AF_INET6 && rp->ai_protocol == 6) {
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)rp->ai_addr)->sin6_addr),
                    buff, 128);

            printf("ip: %s\n", buff);
            memset(buff, 0, sizeof(buff));

            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)rp->ai_addr;
            snprintf(buff, sizeof(buff), "%04X%04X%04X%04X%04X%04X%04X%04X",
                    ntohs(addr6->sin6_addr.s6_addr16[0]), ntohs(addr6->sin6_addr.s6_addr16[1]),
                    ntohs(addr6->sin6_addr.s6_addr16[2]), ntohs(addr6->sin6_addr.s6_addr16[3]),
                    ntohs(addr6->sin6_addr.s6_addr16[4]), ntohs(addr6->sin6_addr.s6_addr16[5]),
                    ntohs(addr6->sin6_addr.s6_addr16[6]), ntohs(addr6->sin6_addr.s6_addr16[7]));
            printf("\tip: %s\n", buff);
        } else 
            continue;

    }
    freeaddrinfo(res);

    return 0;
}

#if 0
int main()
{
   const char *domain="ipv6.baidu.com"; 

   check_dns(domain);

   return 0;
}
#endif
