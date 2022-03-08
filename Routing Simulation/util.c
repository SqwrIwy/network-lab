#include "common.h"

int err(char *msg)
{
    fprintf(stderr, "%s\n", msg);
}

int find_router_id(int id, router_t *routers, int router_num)
{
    for (int i = 1; i <= router_num; i++)
        if (routers[i].id == id)
            return i;
    return -1;
}

int parse_router_location_file(char *router_location_file, router_t *routers, int *router_num)
{
    uint8_t ip0, ip1, ip2, ip3;
    uint32_t ip;
    uint16_t port;
    int id;
    struct sockaddr_in addr;

    FILE *fp = fopen(router_location_file, "r");

    fscanf(fp, "%d", router_num);
    for (int i = 1; i <= *router_num; i++)
    {
        fscanf(fp, "%hhu.%hhu.%hhu.%hhu,%hu,%d", &ip0, &ip1, &ip2, &ip3, &port, &id);
        ip = (ip0 << 24) + (ip1 << 16) + (ip2 << 8) + (ip3);
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(ip);
        memcpy(&routers[i].addr, &addr, sizeof(struct sockaddr));
        routers[i].id = id;
    }

    fclose(fp);

    return 0;
}

int parse_topology_conf_file(char *topology_conf_file, int router_id, int *cost_table, router_t *routers, int router_num)
{
    int edge_num, routerid1, routerid2, weight;

    FILE *fp = fopen(topology_conf_file, "r");

    fscanf(fp, "%d", &edge_num);
    for (int i = 1; i <= edge_num; i++)
    {
        fscanf(fp, "%d,%d,%d", &routerid1, &routerid2, &weight);
        routerid1 = find_router_id(routerid1, routers, router_num);
        routerid2 = find_router_id(routerid2, routers, router_num);
        if (weight == -1)
            weight = MAX_WEIGHT + 1;
        if (routerid1 == router_id)
            cost_table[routerid2] = weight;
    }

    fclose(fp);

    return 0;
}

ssize_t readn(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n;
    ssize_t nread;
    char *buf = usrbuf;

    while (nleft > 0)
    {
        nread = read(fd, buf, nleft);
        if (nread < 0)
            nread = 0;
        nleft -= nread;
        buf += nread;
    }

    return n;
}

ssize_t writen(int fd, void *usrbuf, size_t n)
{
    size_t nleft = n;
    ssize_t nwritten;
    char *buf = usrbuf;

    while (nleft > 0)
    {
        nwritten = write(fd, buf, nleft);
        if (nwritten < 0)
            nwritten = 0;
        nleft -= nwritten;
        buf += nwritten;
    }

    return n;
}

int Socket(int domain, int type, int protocol)
{
    int ret;
    while ((ret = socket(domain, type, protocol)) < 0) ;
    return ret;
}

int Connect(int clientfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret;
    while ((ret = connect(clientfd, addr, addrlen)) < 0) ;
    return ret;
}

int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret;
    while ((ret = bind(sockfd, addr, addrlen)) < 0) ;
    return ret;
}

int Listen(int sockfd, int backlog)
{
    int ret;
    while ((ret = listen(sockfd, backlog)) < 0) ;
    return ret;
}

int Accept(int listenfd, struct sockaddr *addr, int *addrlen)
{
    int ret;
    while ((ret = accept(listenfd, addr, addrlen)) < 0) ;
    return ret;
}
