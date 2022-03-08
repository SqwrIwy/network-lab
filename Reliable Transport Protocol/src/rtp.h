#ifndef RTP_H
#define RTP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#define RTP_START 0
#define RTP_END   1
#define RTP_DATA  2
#define RTP_ACK   3

#define BUFFER_SIZE 2048
#define MESSAGE_SIZE 1024
#define BUFFER_NUM 256

#define TYPE(msg) (((rtp_header_t *)(msg))->type)
#define LENGTH(msg) (((rtp_header_t *)(msg))->length)
#define SEQ(msg) (((rtp_header_t *)(msg))->seq_num)
#define CHECKSUM(msg) (((rtp_header_t *)(msg))->checksum)

#define DEF_MODE S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH

typedef struct __attribute__ ((__packed__)) RTP_header {
    uint8_t type;       // 0: START; 1: END; 2: DATA; 3: ACK
    uint16_t length;    // Length of data; 0 for ACK, START and END packets
    uint32_t seq_num;
    uint32_t checksum;  // 32-bit CRC
} rtp_header_t;


typedef struct RTP_control_block {
    uint32_t window_size;
    // TODO: you can add your RTP-related fields here

    int sockfd;
    struct sockaddr to, from;
    socklen_t tolen, fromlen;
    int n, m;
    char *buf[BUFFER_NUM];
    int buflen[BUFFER_NUM];
    int acked[BUFFER_NUM];
    int bufed[BUFFER_NUM];
} rcb_t;

extern rcb_t* rcb;

extern struct timeval timer;

// different from the POSIX

int Sendto(int sockfd, const void *msg, int len, int flags, const struct sockaddr *to, socklen_t tolen);

int Recvfrom(int sockfd, void *buf, int len, int flags,  struct sockaddr *from, socklen_t *fromlen);

void rcb_init(uint32_t window_size);

int rtp_socket(uint32_t window_size);

int rtp_listen(int sockfd, int backlog);

int rtp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int rtp_bind(int sockfd, struct sockaddr *addr, socklen_t addrlen);

int rtp_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int rtp_sender_close(int sockfd);

int rtp_receiver_close(int sockfd);

void send_seq(int seq);

int rtp_sendto(int sockfd, const void *msg, int len, int flags, const struct sockaddr *to, socklen_t tolen);

// int rtp_recvfrom(int sockfd, void *buf, int len, int flags, struct sockaddr *from, socklen_t *fromlen);
int rtp_recvfrom(int sockfd, struct sockaddr *from, socklen_t *fromlen, int write_fd);

int rtp_recvfrom_opt(int sockfd, struct sockaddr *from, socklen_t *fromlen, int write_fd);

void rtp_sender_update(int seq);

void rtp_sender_update_opt(int seq);

void rtp_resend();

void rtp_receiver_update(int seq, void *buf, int buflen, int write_fd);

void rtp_sendack(int seq);

#endif //RTP_H
