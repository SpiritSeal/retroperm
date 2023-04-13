#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define HOST "www.example.com"
#define PORT 80

int main() {
    int sockfd, n;
    struct sockaddr_in servaddr;
    char sendline[1024], recvline[4096];

    // create a socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // set the server address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, HOST, &servaddr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    // connect to the server
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        exit(1);
    }

    // send an HTTP GET request
    sprintf(sendline, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", HOST);
    write(sockfd, sendline, strlen(sendline));

    // read the server response
    while ((n = read(sockfd, recvline, sizeof(recvline)-1)) > 0) {
        recvline[n] = 0;
        printf("%s", recvline);
    }

    // close the socket
    close(sockfd);

    return 0;
}
