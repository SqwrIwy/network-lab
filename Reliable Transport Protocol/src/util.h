#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>

uint32_t compute_checksum(const void* pkt, size_t n_bytes);

void myerror(char *str);

int diff_time(struct timeval *t1, struct timeval *t2);

int check_checksum(void *pkt, int pktlen);

int cmp_sockaddr(struct sockaddr *addr1, struct sockaddr *addr2);

void make_packet(void *pkt, int *pktlen, uint8_t type, uint32_t seq_num, void *buf, int buflen);

void debug(int n);

#endif
