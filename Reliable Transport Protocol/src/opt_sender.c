#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "rtp.h"


int sender(char *receiver_ip, char* receiver_port, int window_size, char* message){

    // create socket
    int sock = 0;
    if ((sock = rtp_socket(window_size)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // create receiver address
    struct sockaddr_in receiver_addr;
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_port = htons(atoi(receiver_port));

    // convert IPv4 or IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, receiver_ip, &receiver_addr.sin_addr)<=0) { perror("address failed");
        exit(EXIT_FAILURE);
    }

    // connect to server
    if (rtp_connect(sock, (struct sockaddr *)&receiver_addr, sizeof(struct sockaddr)) < 0)
    {
        close(sock);
        myerror("sender: connect failed");
    }

    // send data
    // TODO: if message is filename, open the file and send its content

    int read_fd;
    read_fd = open(message, O_RDONLY, 0);
    if (read_fd < 0)
    {
        int tmp_fd = open("tmp.txt", O_WRONLY|O_CREAT|O_TRUNC, DEF_MODE);
        write(tmp_fd, message, strlen(message));
        close(tmp_fd);
        read_fd = open("tmp.txt", O_RDONLY, 0);
    }

    char buf[BUFFER_SIZE];
    int buflen;
    int socklen = sizeof(struct sockaddr);
    struct timeval timeout, now;
    fd_set read_set, ready_set;

    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);
    FD_SET(read_fd, &read_set);

    gettimeofday(&timer, NULL);

    while (1)
    {
        ready_set = read_set;

        timeout.tv_sec = 0;
        gettimeofday(&now, NULL);
        int diff = diff_time(&timer, &now);
        if (diff < 500000)
            timeout.tv_usec = 500000 - diff;
        else
            timeout.tv_usec = 0;

        int ready_num = select(read_fd + 1, &ready_set, NULL, NULL, &timeout);

        if (!FD_ISSET(read_fd, &ready_set) && rcb->n == rcb->m+1)
            break;

        if (ready_num == 0 || timeout.tv_usec == 0)
        {
            rtp_resend();
        } else
            if (ready_num > 0)
            {
                if (FD_ISSET(sock, &ready_set))
                {
                    buflen = Recvfrom(sock, buf, BUFFER_SIZE, 0, (struct sockaddr *)&receiver_addr, &socklen);
                    if (check_checksum(buf, buflen))
                        rtp_sender_update_opt(SEQ(buf));
                } else
                    if (FD_ISSET(read_fd, &ready_set))
                    {
                        if (rcb->m+1 < rcb->n+rcb->window_size)
                        {
                            buflen = read(read_fd, buf, MESSAGE_SIZE);
                            if (buflen > 0)
                            {
                                rtp_sendto(sock, buf, buflen, 0, (struct sockaddr*)&receiver_addr, socklen);
                            } else
                            {
                                FD_CLR(read_fd, &read_set);
                            }
                        }
                    } else
                        myerror("sender: select ready_set");
            } else
                myerror("sender: select");
    }

    close(read_fd);

    // close rtp socket
    rtp_sender_close(sock);

    return 0;
}



/*
 * main()
 * Parse command-line arguments and call sender function
 */
int main(int argc, char **argv) {
    char *receiver_ip;
    char *receiver_port;
    int window_size;
    char *message;

    if (argc != 5) {
        fprintf(stderr, "Usage: ./sender [Receiver IP] [Receiver Port] [Window Size] [message]");
        exit(EXIT_FAILURE);
    }

    receiver_ip = argv[1];
    receiver_port = argv[2];
    window_size = atoi(argv[3]);
    message = argv[4];
    return sender(receiver_ip, receiver_port, window_size, message);
}
