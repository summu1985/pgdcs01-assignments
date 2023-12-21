/*
** phonebook_server.c -- a datagram sockets based network phonebook server program
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#define MYPORT "4950"    // the port users will be connecting to

#define MAXBUFLEN 100
#define BUFFER_SIZE 1024

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// Structure to hold client information
typedef struct {
    int socket;
    struct sockaddr_in address;
} client_info;

// Function to handle incoming messages from clients
void *handle_client(void *arg) {
    client_info *client = (client_info *)arg;
    char buffer[BUFFER_SIZE];

    //printf("Accepted connection from %s:%d\n", inet_ntoa(client->address.sin_addr), ntohs(client->address.sin_port));

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t recv_size = recvfrom(client->socket, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&(client->address), sizeof(client->address));

        if (recv_size <= 0) {
            break;
        }

        printf("Received message from %s:%d: %s", inet_ntoa(client->address.sin_addr), ntohs(client->address.sin_port), buffer);

        // Add your processing logic here, if needed
        // For this example, we'll just send the same message back to the client
        sendto(client->socket, buffer, strlen(buffer), 0, (struct sockaddr *)&(client->address), sizeof(client->address));
    }

    printf("Connection from %s:%d closed\n", inet_ntoa(client->address.sin_addr), ntohs(client->address.sin_port));
    close(client->socket);
    free(client);

    return NULL;
}

int main(void)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    int numbytes;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("listener: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("listener: bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "phonebook_server: failed to bind socket\n");
        return 2;
    }

    freeaddrinfo(servinfo);

    printf("phonebook_server: listening for connections ...\n");

	while(1) {
		// Accept a new connection
        struct sockaddr_in client_address;
        socklen_t client_address_len = sizeof(client_address);
        memset(&client_address, 0, sizeof(client_address));

        client_info *client = (client_info *)malloc(sizeof(client_info));
        client->socket = sockfd;
        client->address = client_address;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, (void *)client);
        pthread_detach(thread);
	}


	#if 0
    addr_len = sizeof their_addr;
    if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
        (struct sockaddr *)&their_addr, &addr_len)) == -1) {
        perror("recvfrom");
        exit(1);
    }

    printf("listener: got packet from %s\n",
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s));
    printf("listener: packet is %d bytes long\n", numbytes);
    buf[numbytes] = '\0';
    printf("listener: packet contains \"%s\"\n", buf);
	#endif

    close(sockfd);
    return 0;
}
