#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>

#define BUFFER_SIZE 2048
#define MAX_WEIGHT 1000
#define ROUTER_NUM 11
#define MAX_COMMAND_LENGTH 100
#define LISTENQ 1024

#define RSP_DV 0
#define RSP_UPDATE 1
#define RSP_SHOW 2
#define RSP_RESET 3
#define RSP_REPLY 4
#define RSP_EXCHANGE 5

#define TYPE(pkt) (((rsp_header_t *)(pkt))->type)
#define LEN(pkt) (((rsp_header_t *)(pkt))->len)

// rsp = routing simulation protocol
typedef struct __attribute__ ((__packed__)) RSP_header
{
    uint8_t type;
    uint16_t len;
} rsp_header_t;

typedef struct Router
{
    struct sockaddr addr;
    int id;
} router_t;

int err(char *msg);

int find_router_id(int id, router_t *routers, int router_num);

int parse_router_location_file(char *router_location_file, router_t *routers, int *router_num);

int parse_topology_conf_file(char *topology_conf_file, int router_id, int *cost_table, router_t *routers, int router_num);

ssize_t readn(int fd, void *usrbuf, size_t n);

ssize_t writen(int fd, void *usrbuf, size_t n);

int Socket(int domain, int type, int protocol);

int Connect(int clientfd, const struct sockaddr *addr, socklen_t addrlen);

int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int Listen(int sockfd, int backlog);

int Accept(int listenfd, struct sockaddr *addr, int *addrlen);
