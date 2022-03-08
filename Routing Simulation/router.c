#include "common.h"

int router_id;
int router_num;
router_t routers[ROUTER_NUM];
int connfd[ROUTER_NUM];

int cost_table[ROUTER_NUM];
int distance_vectors[ROUTER_NUM][ROUTER_NUM];
int routing_table[ROUTER_NUM][2];
int counter_received_dv;
int waiting_to_propagate;

int listenfd;

void signal_handler(int sig)
{
    close(listenfd);
    for (int i = 0; i <= router_num; i++)
        if (i != router_id)
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

    for (int i = 0; i < ROUTER_NUM; i++)
        cost_table[i] = MAX_WEIGHT+1;
    for (int i = 0; i < ROUTER_NUM; i++)
        for (int j = 0; j < ROUTER_NUM; j++)
            if (i == j)
                distance_vectors[i][j] = 0;
            else
                distance_vectors[i][j] = MAX_WEIGHT+1;
    for (int i = 0; i < ROUTER_NUM; i++)
    {
        if (i == router_id)
        {
            routing_table[i][0] = i;
            routing_table[i][1] = 0;
        } else
        {
            routing_table[i][0] = -1;
            routing_table[i][1] = MAX_WEIGHT+1;
        }
    }
    counter_received_dv = 0;
    waiting_to_propagate = 0;

    return 0;
}

int establish_connections()
{
    struct sockaddr cliaddr;
    socklen_t clilen;

    for (int i = 1; i < router_id; i++)
    {
        connfd[i] = Socket(AF_INET, SOCK_STREAM, 0);
        Connect(connfd[i], &routers[i].addr, sizeof(routers[i].addr));
        writen(connfd[i], &router_id, sizeof(int));
    }

    listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    Bind(listenfd, &routers[router_id].addr, sizeof(routers[router_id].addr));
    Listen(listenfd, LISTENQ);
    for (int j = router_id; j <= router_num; j++)
    {
        int tmp = Accept(listenfd, &cliaddr, &clilen), i;
        readn(tmp, &i, sizeof(int));
        connfd[i] = tmp;
    }
    close(listenfd);

    return 0;
}

void calc_routing_table()
{
    int tmp[ROUTER_NUM][2];

    for (int i = 1; i <= router_num; i++)
    {
        tmp[i][0] = routing_table[i][0];
        tmp[i][1] = routing_table[i][1];
    }

    for (int i = 1; i <= router_num; i++)
    {
        if (i == router_id)
        {
            routing_table[i][0] = i;
            routing_table[i][1] = 0;
        } else
        {
            routing_table[i][0] = -1;
            routing_table[i][1] = MAX_WEIGHT+1;
        }
    }

    for (int i = 1; i <= router_num; i++)
        if (i != router_id && cost_table[i] <= MAX_WEIGHT)
        {
            for (int j = 1; j <= router_num; j++)
                if (distance_vectors[i][j] + cost_table[i] < routing_table[j][1] ||
                    distance_vectors[i][j] + cost_table[i] == routing_table[j][1] && i < routing_table[j][0] )
                {
                    routing_table[j][0] = i;
                    routing_table[j][1] = distance_vectors[i][j] + cost_table[i];
                }
        }

    for (int i = 1; i <= router_num; i++)
        if (routing_table[i][0] != tmp[i][0] || routing_table[i][1] != tmp[i][1])
        {
            waiting_to_propagate = 1;
            break;
        }
}

int propagate()
{
    char pkt[BUFFER_SIZE];
    int pktlen;

    if (waiting_to_propagate != 0)
    {
        for (int i = 1; i <= router_num; i++)
            if (i != router_id && cost_table[i] <= MAX_WEIGHT)
            {
                TYPE(pkt) = RSP_EXCHANGE;
                LEN(pkt) = sizeof(int)*router_num;
                pktlen = sizeof(rsp_header_t)+LEN(pkt);
                int *msg = (int *)(pkt+sizeof(rsp_header_t));
                for (int j = 0; j < router_num; j++)
                    msg[j] = routing_table[j+1][1];
                writen(connfd[i], pkt, pktlen);
            }
        waiting_to_propagate = 0;
    }

    return 0;
}

int router(char *router_location_file, char *topology_conf_file)
{
    char buf[BUFFER_SIZE], pkt[BUFFER_SIZE];
    int buflen, pktlen;

    init();

    if (parse_router_location_file(router_location_file, routers, &router_num) < 0)
        return -1;
    router_id = find_router_id(router_id, routers, router_num);
    if (parse_topology_conf_file(topology_conf_file, router_id, cost_table, routers, router_num) < 0)
        return -1;
    if (establish_connections() < 0)
        return -1;

    calc_routing_table();

    int max_fd = 0;
    fd_set read_set, ready_set;
    FD_ZERO(&read_set);
    for (int i = 0; i <= router_num; i++)
        if (i != router_id)
        {
            FD_SET(connfd[i], &read_set);
            if (connfd[i] > max_fd)
                max_fd = connfd[i];
        }

    while (1)
    {
        ready_set = read_set;
        select(max_fd+1, &ready_set, NULL, NULL, NULL);

        int from_id;
        for (int i = 0; i <= router_num; i++)
            if (i != router_id)
            {
                if (FD_ISSET(connfd[i], &ready_set))
                {
                    from_id = i;
                    break;
                }
            }
        readn(connfd[from_id], buf, sizeof(rsp_header_t));
        readn(connfd[from_id], buf+sizeof(rsp_header_t), LEN(buf));
        if (from_id == 0)
        {
            if (TYPE(buf) == RSP_DV)
            {
                propagate();
            } else
                if (TYPE(buf) == RSP_UPDATE)
                {
                    int *msg = (int *)(buf+sizeof(rsp_header_t));
                    int weight = msg[1];
                    if (weight == -1)
                        weight = MAX_WEIGHT + 1;
                    cost_table[msg[0]] = weight;
                    calc_routing_table();
                } else
                    if (TYPE(buf) == RSP_SHOW)
                    {
                        TYPE(pkt) = RSP_REPLY;
                        LEN(pkt) = sizeof(int)*router_num*2;
                        pktlen = sizeof(rsp_header_t)+LEN(pkt);
                        int *msg = (int *)(pkt+sizeof(rsp_header_t));
                        for (int i = 1; i <= router_num; i++)
                        {
                            msg[i-1] = routing_table[i][0];
                            msg[i-1+router_num] = routing_table[i][1];
                        }
                        writen(connfd[0], pkt, pktlen);
                    } else
                        if (TYPE(buf) == RSP_RESET)
                        {
                            counter_received_dv = 0;
                        } else
                        {
                            err("packet type error");
                            return -1;
                        }
        } else
        {
            if (TYPE(buf) == RSP_EXCHANGE)
            {
                int *msg = (int *)(buf+sizeof(rsp_header_t));
                for (int i = 1; i <= router_num; i++)
                    distance_vectors[from_id][i] = msg[i-1];
                counter_received_dv ++;
                calc_routing_table();
                propagate();
            } else
            {
                err("packet type error");
                return -1;
            }
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char *router_location_file, *topology_conf_file;

    if (argc != 4)
    {
        err("Usage: ./router [router location file] [topology conf file] [router id]");
        exit(EXIT_FAILURE);
    }

    router_location_file = argv[1];
    topology_conf_file = argv[2];
    router_id = atoi(argv[3]);

    router(router_location_file, topology_conf_file);
}
