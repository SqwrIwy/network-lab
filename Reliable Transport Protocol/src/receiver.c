#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>

#include "util.h"
#include "rtp.h"

#define RECV_BUFFER_SIZE 32768  // 32KB

int receiver(char *receiver_port, int window_size, char* file_name) {

    char buffer[RECV_BUFFER_SIZE];

    // create rtp socket file descriptor
    int receiver_fd = rtp_socket(window_size);
    if (receiver_fd == 0) {
        perror("create rtp socket failed");
        exit(EXIT_FAILURE);
    }

    // create socket address
    // forcefully attach socket to the port
    struct sockaddr_in address;
    memset(&address, 0, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(atoi(receiver_port));

    // bind rtp socket to address
    if (rtp_bind(receiver_fd, (struct sockaddr *)&address, sizeof(struct sockaddr))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    int recv_bytes;
    struct sockaddr_in sender;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    // listen to incoming rtp connection
    if (rtp_listen(receiver_fd, 1) < 0)
    {
        close(receiver_fd);
        myerror("receiver: listen failed");
    }
    // accept the rtp connection
    rtp_accept(receiver_fd, (struct sockaddr*)&sender, &addr_len);

    // receive packet

    int write_fd = open(file_name, O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
    if (write_fd < 0)
    {
        myerror("receiver: open file");
    }

    while (rtp_recvfrom(receiver_fd, (struct sockaddr*)&sender, &addr_len, write_fd) >= 0) ;

    close(write_fd);

    rtp_receiver_close(receiver_fd);

    return 0;
}

/*
 * main():
 * Parse command-line arguments and call receiver function
 */
int main(int argc, char **argv) {
    char *receiver_port;
    int window_size;
    char *file_name;

    if (argc != 4) {
        fprintf(stderr, "Usage: ./receiver [Receiver Port] [Window Size] [File Name]\n");
        exit(EXIT_FAILURE);
    }

    receiver_port = argv[1];
    window_size = atoi(argv[2]);
    file_name = argv[3];
    return receiver(receiver_port, window_size, file_name);
}
