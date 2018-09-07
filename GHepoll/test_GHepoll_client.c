#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


/*测试GHepoll程序中创建了一个socket服务端，这个是客户端，用来测试*/

int tcp_socket(const char *host, uint16_t port)
{
    int sock;
    struct sockaddr_in addr;

    if (-1 == (sock = socket(AF_INET, SOCK_STREAM, 0))) {
        exit(EXIT_FAILURE);
    }


    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* maybe host name */
        struct hostent *hp;
        hp = gethostbyname(host);
        if (NULL == hp) {
            exit(EXIT_FAILURE);
        } 
        
        memcpy(&addr.sin_addr, &hp->h_addr, hp->h_length);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
      return -1;

    return sock;
}


int main ()
{
    int clifd; 
    const char *sbuff = "send msg test GHepoll";
    char rbuff[1024] = {0};

    clifd = tcp_socket("127.0.0.1", 12345); 
    if (clifd < 0) 
        exit(1);

    send(clifd, sbuff, strlen(sbuff) + 1 , 0);
    recv(clifd, rbuff, sizeof(rbuff), 0);

    printf("recv msg from server: %s\n", rbuff);
    sleep(5);

    close(clifd);
    return 0;
}





