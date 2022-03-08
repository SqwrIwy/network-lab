#include "rtp.h"
#include "util.h"

uint32_t crc32_for_byte(uint32_t r) {
    for(int j = 0; j < 8; ++j)
        r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}

void crc32(const void *data, size_t n_bytes, uint32_t* crc) {
    static uint32_t table[0x100];
    if(!*table)
        for(size_t i = 0; i < 0x100; ++i)
            table[i] = crc32_for_byte(i);
    for(size_t i = 0; i < n_bytes; ++i)
        *crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

uint32_t compute_checksum(const void* pkt, size_t n_bytes) {
    uint32_t crc = 0;
    crc32(pkt, n_bytes, &crc);
    return crc;
}

void myerror(char *str)
{
    perror(str);
    exit(EXIT_FAILURE);
}

int diff_time(struct timeval *t1, struct timeval *t2)
{
    return (t2->tv_sec - t1->tv_sec) * 1000000 + (t2->tv_usec - t1->tv_usec);
}

int check_checksum(void *pkt, int pktlen)
{
    uint32_t checksum;

    checksum = CHECKSUM(pkt);
    CHECKSUM(pkt) = 0;

    if (compute_checksum(pkt, pktlen) == checksum)
        return 1;
    return 0;
}

int cmp_sockaddr(struct sockaddr *addr1, struct sockaddr *addr2)
{
    if (memcmp((void *)addr1, (void *)addr2, sizeof(struct sockaddr)) == 0)
        return 1;
    return 0;
}

void make_packet(void *pkt, int *pktlen, uint8_t type, uint32_t seq_num, void *buf, int buflen)
{
    *pktlen = buflen+sizeof(rtp_header_t);
    TYPE(pkt) = type;
    LENGTH(pkt) = (uint16_t)buflen;
    SEQ(pkt) = seq_num;
    CHECKSUM(pkt) = 0;
    memcpy(pkt+sizeof(rtp_header_t), buf, buflen);
    CHECKSUM(pkt) = compute_checksum(pkt, *pktlen);
}

void debug(int n)
{
    printf("%d\n", n);
}
