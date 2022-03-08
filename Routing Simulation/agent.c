#include "common.h"

int router_num;
int connfd[ROUTER_NUM];
router_t routers[ROUTER_NUM];

void signal_handler(int sig)
{
    for (int i = 1; i <= router_num; i++)
        close(connfd[i]);
    exit(0);
}

int init()
{
    if (signal(SIGINT, signal_handler) == SIG_ERR)
    {
        err("signal handler error");
        return -1;
    }
    if (signal(SIGTERM, signal_handler) == SIG_ERR)
    {
        err("signal handler error");
        return -1;
    }

    return 0;
}

int establish_connections()
{
    int agent_id = 0;

    for (int i = 1; i <= router_num; i++)
    {
        connfd[i] = Socket(AF_INET, SOCK_STREAM, 0);
        Connect(connfd[i], &routers[i].addr, sizeof(routers[i].addr));
        writen(connfd[i], &agent_id, sizeof(int));
    }

    return 0;
}

int agent(char *router_location_file)
{
    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    int buflen, pktlen;
    char cmd[MAX_COMMAND_LENGTH];
    int routerid1, routerid2;
    int weight;

    init();

    if (parse_router_location_file(router_location_file, routers, &router_num) < 0)
        return -1;
    if (establish_connections() < 0)
        return -1;

    while (1)
    {
        scanf("%s", cmd);
        if (memcmp(cmd, "dv", 2) == 0)
        {
            TYPE(pkt) = RSP_DV;
            LEN(pkt) = 0;
            pktlen = sizeof(rsp_header_t)+LEN(pkt);
            for (int i = 1; i <= router_num; i++)
            {
                writen(connfd[i], pkt, pktlen);
            }
        } else
            if (memcmp(cmd, "update", 6) == 0)
            {
                sscanf(cmd+7, "%d,%d,%d", &routerid1, &routerid2, &weight);
                routerid1 = find_router_id(routerid1, routers, router_num);
                routerid2 = find_router_id(routerid2, routers, router_num);
                TYPE(pkt) = RSP_UPDATE;
                LEN(pkt) = sizeof(int)*2;
                pktlen = sizeof(rsp_header_t)+LEN(pkt);
                int *msg = (int *)(pkt+sizeof(rsp_header_t));
                msg[0] = routerid2;
                msg[1] = weight;
                writen(connfd[routerid1], pkt, pktlen);
            } else
                if (memcmp(cmd, "show", 4) == 0)
                {
                    sscanf(cmd+5, "%d", &routerid1);
                    routerid1 = find_router_id(routerid1, routers, router_num);
                    TYPE(pkt) = RSP_SHOW;
                    LEN(pkt) = 0;
                    pktlen = sizeof(rsp_header_t)+LEN(pkt);
                    writen(connfd[routerid1], pkt, pktlen);

                    readn(connfd[routerid1], buf, sizeof(rsp_header_t));
                    readn(connfd[routerid1], buf+sizeof(rsp_header_t), LEN(buf));
                    if (TYPE(buf) == RSP_REPLY)
                    {
                        int *msg = (int *)(buf+sizeof(rsp_header_t));
                        for (int i = 1; i <= router_num; i++)
                        {
                            int dest = i;
                            int next = msg[i-1];
                            int cost = msg[i-1+router_num];
                            if (next > 0)
                            {
                                printf("dest: %d, next: %d, cost: %d\n", routers[dest].id, routers[next].id, cost);
                            }
                        }
                    } else
                    {
                        err("agent show reply error");
                        return -1;
                    }
                } else
                    if (memcmp(cmd, "reset", 5) == 0)
                    {
                        sscanf(cmd+6, "%d", &routerid1);
                        routerid1 = find_router_id(routerid1, routers, router_num);
                        TYPE(pkt) = RSP_RESET;
                        LEN(pkt) = 0;
                        pktlen = sizeof(rsp_header_t)+LEN(pkt);
                        writen(connfd[routerid1], pkt, pktlen);
                    } else
                    {
                        err("command not found");
                        return -1;
                    }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char *router_location_file;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc != 2)
    {
        err("Usage: ./agent [router location file]");
        exit(EXIT_FAILURE);
    }

    router_location_file = argv[1];

    agent(router_location_file);
}
