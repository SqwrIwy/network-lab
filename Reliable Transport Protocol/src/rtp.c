#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>

#include "rtp.h"
#include "util.h"

rcb_t *rcb = NULL;

struct timeval timer;

int Sendto(int sockfd, const void *msg, int len, int flags, const struct sockaddr *to, socklen_t tolen)
{
    int sent_bytes = sendto(sockfd, msg, len, flags, to, tolen);
    if (sent_bytes != len)
    {
        myerror("send error");
    }
    return sent_bytes;
}

int Recvfrom(int sockfd, void *buf, int len, int flags,  struct sockaddr *from, socklen_t *fromlen)
{
    int recv_bytes = recvfrom(sockfd, buf, len, flags, from, fromlen);
    if (recv_bytes < 0)
    {
        myerror("receive error");
    }
    ((char *)buf)[recv_bytes] = '\0';
    return recv_bytes;
}

void rcb_init(uint32_t window_size) {
    if (rcb == NULL) {
        rcb = (rcb_t *) calloc(1, sizeof(rcb_t));
    } else {
        myerror("The current version of the rtp protocol only supports a single connection");
    }
    rcb->window_size = window_size;
    // TODO: you can initialize your RTP-related fields here

    rcb->n = 0;
    rcb->m = -1;
    memset(rcb->acked, 0, sizeof(rcb->acked));
    memset(rcb->bufed, 0, sizeof(rcb->bufed));
}


/*********************** Note ************************/
/* RTP in Assignment 2 only supports single connection.
/* Therefore, we can initialize the related fields of RTP when creating the socket.
/* rcb is a global varialble, you can directly use it in your implementatyion.
/*****************************************************/
int rtp_socket(uint32_t window_size) {
    rcb_init(window_size); 
    // create UDP socket
    return socket(AF_INET, SOCK_DGRAM, 0);  
}


int rtp_bind(int sockfd, struct sockaddr *addr, socklen_t addrlen) {
    return bind(sockfd, addr, addrlen);
}


int rtp_listen(int sockfd, int backlog) {
    // TODO: listen for the START message from sender and send back ACK
    // In standard POSIX API, backlog is the number of connections allowed on the incoming queue.
    // For RTP, backlog is always 1

    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    struct sockaddr sender;
    socklen_t socklen;
    int buflen, pktlen;

    socklen = sizeof(sender);

    while (1)
    {
        buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, &sender, &socklen);
        if (TYPE(buf) == RTP_START)
        {
            if (check_checksum(buf, buflen))
            {
                make_packet(pkt, &pktlen, RTP_ACK, SEQ(buf), NULL, 0);
                Sendto(sockfd, pkt, pktlen, 0, &sender, socklen);

                rcb->sockfd = sockfd;
                rcb->from = sender;
                rcb->fromlen = sizeof(struct sockaddr);

                return 1;
            } else
            {
                return -1;
            }
        }
    }

    return 1;
}


int rtp_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    // Since RTP in Assignment 2 only supports one connection,
    // there is no need to implement accpet function.
    // You don’t need to make any changes to this function.
    return 1;
}

int rtp_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    // TODO: send START message and wait for its ACK

    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    struct sockaddr receiver, from;
    socklen_t socklen;
    fd_set read_set, ready_set;
    uint32_t rand_seq;
    int buflen, pktlen, ready_num;
    struct timeval timeout;

    receiver = *addr;
    socklen = addrlen;

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);

    rand_seq = (uint32_t)rand();

    make_packet(pkt, &pktlen, RTP_START, rand_seq, NULL, 0);
    Sendto(sockfd, pkt, pktlen, 0, &receiver, socklen);

    ready_set = read_set;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    ready_num = select(sockfd+1, &ready_set, NULL, NULL, &timeout);
    if (ready_num > 0)
    {
        buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, &from, &socklen);
        if (check_checksum(buf, buflen) && TYPE(buf) == RTP_ACK && SEQ(buf) == rand_seq)
        {
            rcb->sockfd = sockfd;
            rcb->to = receiver;
            rcb->tolen = sizeof(struct sockaddr);
            return 1;
        } else
        {
            goto error;
        }
    } else
    {
        goto error;
    }

    return 1;

error:

    make_packet(pkt, &pktlen, RTP_END, 0, NULL, 0);
    Sendto(sockfd, pkt, pktlen, 0, &receiver, socklen);

    ready_set = read_set;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    ready_num = select(sockfd+1, &ready_set, NULL, NULL, &timeout);
    if (ready_num > 0)
    {
        buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, &from, &socklen);
        return -1;
    } else
        return -1;
    return -1;
}


int rtp_sender_close(int sockfd)
{
    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    struct sockaddr receiver, from;
    socklen_t socklen;
    fd_set read_set, ready_set;
    uint32_t rand_seq;
    int buflen, pktlen, ready_num;
    struct timeval timeout;

    receiver = rcb->to;
    socklen = rcb->tolen;

    FD_ZERO(&read_set);
    FD_SET(sockfd, &read_set);

    make_packet(pkt, &pktlen, RTP_END, rcb->n, NULL, 0);
    Sendto(sockfd, pkt, pktlen, 0, &receiver, socklen);

    ready_set = read_set;
    timeout.tv_sec = 0;
    timeout.tv_usec = 500000;
    ready_num = select(sockfd+1, &ready_set, NULL, NULL, &timeout);
    if (ready_num > 0)
    {
        buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, &from, &socklen);
        return close(sockfd);
    } else
        return close(sockfd);

    return close(sockfd);
}


int rtp_receiver_close(int sockfd)
{
    return close(sockfd);
}


void send_seq(int seq)
{
    char pkt[BUFFER_SIZE];
    int pktlen;

    make_packet(pkt, &pktlen, RTP_DATA, seq, rcb->buf[seq%BUFFER_NUM], rcb->buflen[seq%BUFFER_NUM]);
    Sendto(rcb->sockfd, pkt, pktlen, 0, &rcb->to, rcb->tolen);
}


int rtp_sendto(int sockfd, const void *msg, int len, int flags, const struct sockaddr *to, socklen_t tolen) {
    // TODO: send message

    rcb->m ++;
    rcb->buf[rcb->m%BUFFER_NUM] = malloc(len);
    memcpy(rcb->buf[rcb->m%BUFFER_NUM], msg, len);
    rcb->buflen[rcb->m%BUFFER_NUM] = len;
    rcb->acked[rcb->m%BUFFER_NUM] = 0;

    if (rcb->m < rcb->n+rcb->window_size)
    {
        send_seq(rcb->m);
    } else
    {
        myerror("rtp_sendto: out of range");
    }

    return 1;
}


int rtp_recvfrom(int sockfd, struct sockaddr *from, socklen_t *fromlen, int write_fd) {
    // TODO: recv message

    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    int buflen, pktlen;

    buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, from, fromlen);

    if (check_checksum(buf, buflen))
    {
        if (TYPE(buf) == RTP_DATA)
        {
            rtp_receiver_update(SEQ(buf), buf+sizeof(rtp_header_t), LENGTH(buf), write_fd);
        } else
            if (TYPE(buf) == RTP_END)
            {
                make_packet(pkt, &pktlen, RTP_ACK, SEQ(buf), NULL, 0);
                Sendto(sockfd, pkt, pktlen, 0, &rcb->from, rcb->fromlen);
                return -1;
            } else
                myerror("rtp_recvfrom: type");
    }

    rtp_sendack(rcb->n);

    return 0;
}


int rtp_recvfrom_opt(int sockfd, struct sockaddr *from, socklen_t *fromlen, int write_fd) {
    // TODO: recv message

    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    int buflen, pktlen;

    buflen = Recvfrom(sockfd, buf, BUFFER_SIZE, 0, from, fromlen);

    if (check_checksum(buf, buflen))
    {
        if (TYPE(buf) == RTP_DATA)
        {
            rtp_receiver_update(SEQ(buf), buf+sizeof(rtp_header_t), LENGTH(buf), write_fd);
            rtp_sendack(SEQ(buf));
        } else
            if (TYPE(buf) == RTP_END)
            {
                make_packet(pkt, &pktlen, RTP_ACK, SEQ(buf), NULL, 0);
                Sendto(sockfd, pkt, pktlen, 0, &rcb->from, rcb->fromlen);
                return -1;
            } else
                myerror("rtp_recvfrom: type");
    }

    return 0;
}


void rtp_sender_update(int seq)
{
    if (rcb->n < seq && seq <= rcb->n+rcb->window_size)
    {
        for (int i = rcb->n; i < seq; i++)
            free(rcb->buf[i%BUFFER_NUM]);
        for (int i = rcb->n+rcb->window_size; i < seq+rcb->window_size; i++)
            rcb->acked[i%BUFFER_NUM] = 0;
        rcb->n = seq;
        gettimeofday(&timer, NULL);
    }
}


void rtp_sender_update_opt(int seq)
{
    if (rcb->n <= seq && seq < rcb->n+rcb->window_size && !rcb->acked[seq%BUFFER_NUM])
    {
        free(rcb->buf[seq%BUFFER_NUM]);
        rcb->acked[seq%BUFFER_NUM] = 1;
        if (rcb->acked[rcb->n%BUFFER_NUM])
        {
            while (rcb->acked[rcb->n%BUFFER_NUM])
            {
                rcb->acked[(rcb->n+rcb->window_size)%BUFFER_NUM] = 0;
                rcb->n ++;
            }
            gettimeofday(&timer, NULL);
        }
    }
}

void rtp_resend()
{
    for (int i = rcb->n; i < rcb->n+rcb->window_size && i < rcb->m; i++)
        if (!rcb->acked[i%BUFFER_NUM])
            send_seq(i);
    gettimeofday(&timer, NULL);
}

void rtp_receiver_update(int seq, void *buf, int buflen, int write_fd)
{
    if (rcb->n <= seq && seq < rcb->n+rcb->window_size && !rcb->bufed[seq%BUFFER_NUM])
    {
        rcb->buf[seq%BUFFER_NUM] = malloc(buflen);
        memcpy(rcb->buf[seq%BUFFER_NUM], buf, buflen);
        rcb->buflen[seq%BUFFER_NUM] = buflen;
        rcb->bufed[seq%BUFFER_NUM] = 1;
    }
    while (rcb->bufed[rcb->n%BUFFER_NUM])
    {
        rcb->bufed[(rcb->n+rcb->window_size)%BUFFER_NUM] = 0;
        write(write_fd, rcb->buf[rcb->n%BUFFER_NUM], rcb->buflen[rcb->n%BUFFER_NUM]);
        free(rcb->buf[rcb->n%BUFFER_NUM]);
        rcb->n ++;
    }
}

void rtp_sendack(int seq)
{
    char pkt[BUFFER_SIZE];
    int pktlen;
    make_packet(pkt, &pktlen, RTP_ACK, seq, NULL, 0);
    Sendto(rcb->sockfd, pkt, pktlen, 0, &rcb->from, rcb->fromlen);
}
