#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "traceroute.h"
#include "cJSON.h"

/**
 * \brief Calculate the checksum for ICMP (Internet Control Message Protocol) packets.
 * \param buffer : pointer to the icmp packet
 * \param length : total length of the icmp packet
 * \return checksum value
 */
uint16_t check_sum(const void *buffer, size_t length)
{
    const uint16_t *buf = (const uint16_t *)buffer;
    uint32_t sum = 0;

    while (length > 1) {
        sum += *buf++;
        length -= sizeof(uint16_t);
    }

    if (length) {
        sum += *(const uint8_t *)buf;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

/**
 * \brief Send ICMP packets.
 * \param param : pointer to the icmp_param structure
 */
void send_icmp_packet(struct icmp_param *param)
{
    int nbs;
    unsigned int i;
    unsigned char packet[PACKET_LEN];
    unsigned char *data = &packet[8];  // data start at 8th byte, icmp header is 8 bytes
    struct icmp *icmp_packet = (struct icmp*) packet;

    memset(packet, 0, PACKET_LEN);
    icmp_packet->icmp_type = ICMP_ECHO;
    icmp_packet->icmp_code = 0;
    icmp_packet->icmp_cksum = 0;
    icmp_packet->icmp_seq = htons(++param->seq);
    icmp_packet->icmp_id = htons(param->pid);
    // fill the data
    for(i = 0; i < *param->size_data; i++) {
        *data++ = i;
    }
    // calculate the checksum
    icmp_packet->icmp_cksum = check_sum(icmp_packet, 8 + *param->size_data);
    clock_gettime(CLOCK_REALTIME, param->send_time);    // save the send time
    nbs = sendto(*param->sockfd, packet, 8 + *param->size_data, 0,
                 (struct sockaddr*)param->destination, sizeof(struct sockaddr));
    if(nbs < 0 || nbs < 8 + *param->size_data) {
        if(nbs < 0) {
            printf("sendto : %s\n", strerror(errno));
        }
        printf("sendto %s %d chars, achieve %d\n",
               inet_ntoa((*param->destination).sin_addr),
               8 + *param->size_data, nbs);
    }
}

/** 
 * \brief Check if the received ICMP packet is valid.
 * \param recv_buffer : pointer to the buffer where the received packet
 * \param param : pointer to the icmp_param structure
 * \return 0 if the packet is valid, -1 otherwise
 */
int check_recv_packet(const void *recv_buffer, struct icmp_param *param)
{
    struct ip *reply = (struct ip *)recv_buffer;
    // check packet's protocol
	if(reply->ip_p != IPPROTO_ICMP) {
        return -1;
	}
    // extract the ICMP header from the IP packet
	struct icmp *icmp_header = (struct icmp *)((unsigned char *)recv_buffer + reply->ip_hl*4);
    // check the ICMP type and code
	if(icmp_header->icmp_type != ICMP_ECHOREPLY &&
	  !(icmp_header->icmp_type == ICMP_TIME_EXCEEDED && icmp_header->icmp_code == ICMP_EXC_TTL)) {
        return -1;
	}
    // if ICMP type is ICMP_TIME_EXCEEDED, extract the nested ICMP packet
	if(icmp_header->icmp_type == ICMP_TIME_EXCEEDED) {
	    icmp_header = (struct icmp *)(icmp_header->icmp_data + ((struct ip *)(icmp_header->icmp_data))->ip_hl*4);
	}
    // check the identification
    if(ntohs(icmp_header->icmp_id) != param->pid) {
        return -1;
    }
    // check the sequence number
    if( ntohs(icmp_header->icmp_seq) != param->seq) {
        return -1;
    }

    return 0;
}

/**
 * \brief Check if an IP address exists in an array of IP addresses.
 * \param ip  : the ip address of the host
 * \param tab  : the array of ip addresses
 * \return 1 if the host has arrived, 0 otherwise
 */
int host_has_arrived(uint32_t ip, uint32_t *tab)
{
    int i;
    int visited = 0;
    for(i = 0; i < MAX_HOPS && !visited; i++) {
        visited = visited || tab[i] == ip;
    }

    return visited;
}

/**
 * \brief Calculate the time difference between two timespec structures.
 * \param send : a pointer to the timespec structure representing the time before sending the packet
 * \param recv : a pointer to the timespec structure representing the time after receiving the packet
 * \return a pointer to the timespec structure representing the time difference
 */
struct timespec time_diff(struct timespec *send, struct timespec *recv)
{
    struct timespec diff;

    diff.tv_sec = recv->tv_sec - send->tv_sec;
    diff.tv_nsec = recv->tv_nsec - send->tv_nsec;
    if(diff.tv_nsec < 0) {
        diff.tv_sec -= 1;
        diff.tv_nsec += 1000000000;
    }

    return diff;
}

/**
 * \brief Analyze the packets returned from the network.
 * \param buffer : buffer containing the packet
 * \param size : size of the buffer
 * \param from : address of the sender
 * \param ttl : time to live
 * \param tbef : time before sending
 * \param print_obj : pointer to the print control structure
 */
void analyze_icmp(const void *buffer, unsigned int size, struct sockaddr_in *from, int ttl, struct timespec *tbef, print_ctrl_t *print_obj)
{
    int ret = 0;
    struct timespec tnow;
    struct timespec diff;
    struct ip *ip;
    unsigned int ip_header_len;
    double time_ms;
    char host[48];

    clock_gettime(CLOCK_REALTIME, &tnow);
    ip = (struct ip*)buffer;
    ip_header_len = ip->ip_hl << 2;
    if(size < ip_header_len + ICMP_MINLEN) {
        printf("Packet too small\n");
        return;
    }

    diff = time_diff(tbef, &tnow);
    time_ms = diff.tv_sec * 1000 + (diff.tv_nsec / 1000000.0);

    if((ret = getnameinfo((struct sockaddr*)from, sizeof(struct sockaddr_in), host, 48, NULL, 0, 0)) != 0 ) {
        printf("genameinfo: %s\n", gai_strerror(ret));
    }

    print_node_t *print_node = (print_node_t *)malloc(sizeof(print_node_t));
    snprintf(print_node->ttl, sizeof(print_node->ttl), "%d", ttl);
    snprintf(print_node->ip, sizeof(print_node->ip), "%s", inet_ntoa(from->sin_addr));
    snprintf(print_node->rrt, sizeof(print_node->rrt), "%.3f ms", time_ms);
    print_node->next = NULL;

    if(print_obj->head == NULL) {
        print_obj->head = print_node;
        print_obj->current_node = print_node;
        print_obj->size = 1;
    } else {
        print_obj->current_node->next = print_node;
        print_obj->current_node = print_node;
        print_obj->size++;
    }

    printf("%d %s (%s) %.3fms\n", ttl, host, inet_ntoa(from->sin_addr), time_ms);
}

/**
 * \brief Print an asterisk for each hop.
 * \param hop : the number of the hop
 * \param print_obj : pointer to the print control structure
 */
void show_asterisk(int hop, print_ctrl_t *print_obj)
{
    print_node_t *print_node = (print_node_t *)malloc(sizeof(print_node_t));
    snprintf(print_node->ttl, sizeof(print_node->ttl), "%d", hop);
    snprintf(print_node->ip, sizeof(print_node->ip), "%s", "*");
    snprintf(print_node->rrt, sizeof(print_node->rrt), "%s", "*");
    print_node->next = NULL;

    if(print_obj->head == NULL) {
        print_obj->head = print_node;
        print_obj->current_node = print_node;
        print_obj->size = 1;
    } else {
        print_obj->current_node->next = print_node;
        print_obj->current_node = print_node;
        print_obj->size++;
    }

    printf("%d * * * \n", hop);
}

void free_print_list(print_ctrl_t *print_obj)
{
    print_node_t *print_node_temp = print_obj->head;

    while(print_node_temp != NULL) {
        print_node_t *print_node_next = print_node_temp->next;
        free(print_node_temp);
        print_node_temp = print_node_next;
    }

    free(print_obj);
}

/**
 * \brief Create a json string of the traceroute.
 * \param list : pointer to the print control structure
 * \return the json string of the traceroute
 */
char* create_json_string_of_traceroute(print_ctrl_t *list)
{
    cJSON *root;
    cJSON *json_array, *json_obj;
    char  *out = NULL;
    print_node_t *ptmp = NULL;

    if (NULL == list) {
        return NULL;
    }

    root = cJSON_CreateObject();
    if(root) {
        struct timeval curr_time;
        gettimeofday(&curr_time, NULL );
        cJSON_AddNumberToObject(root, "timestamp", curr_time.tv_sec);

        json_array = cJSON_CreateArray();
        cJSON_AddItemToObject(root, "ip_traceroute", json_array);
        for(ptmp = list->head; NULL != ptmp; ptmp = ptmp->next) {
            json_obj = cJSON_CreateObject();
            cJSON_AddItemToArray(json_array, json_obj);
            cJSON_AddStringToObject(json_obj, "ip", ptmp->ip);
            cJSON_AddStringToObject(json_obj, "rrt", ptmp->rrt);
            cJSON_AddNumberToObject(json_obj, "ttl", atoi(ptmp->ttl));
        }

        out = cJSON_PrintUnformatted(root);
        if(out) {
            printf("traceroute report: %s\n", out);
        }
        cJSON_Delete(root);
    }

    return out;
}

char* traceroute_report(const char *host)
{
    char *traceroute_out = NULL;
    int sockfd = -1;
    int ttl = 1;
    int ret = -1;
    unsigned int size_data = 64;
    struct sockaddr_in from;
    struct sockaddr_in destination;
    struct addrinfo hints;
    struct addrinfo *addr_info_list = NULL;
    struct addrinfo *addr_info = NULL;
    struct icmp_param ping_param;
    struct timespec send_time;
    struct timespec recv_time;
    char dest_ip[INET6_ADDRSTRLEN];
    unsigned char buffer[PACKET_LEN];
    uint32_t addresses[MAX_HOPS];

    if (NULL == host || strlen(host) == 0) {
        return traceroute_out;
    }

    print_ctrl_t *print_obj = (print_ctrl_t *)malloc(sizeof(print_ctrl_t));
    print_obj->head = NULL;
    print_obj->current_node = NULL;
    print_obj->size = 0;

    ping_param.destination = &destination;
    ping_param.send_time = &send_time;
    ping_param.sockfd = &sockfd;
    ping_param.size_data = &size_data;
    ping_param.pid = getpid();
    ping_param.seq = 0;

    memset(&addresses, 0, MAX_HOPS * sizeof(*addresses));
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    if((ret = getaddrinfo(host, NULL, &hints, &addr_info_list)) != 0) {
        printf("getaddrinfo error: %s\n", gai_strerror(ret));
        return traceroute_out;
    }

    for(addr_info = addr_info_list; addr_info != NULL; addr_info = addr_info->ai_next) {
        sockfd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);
        if(sockfd > 0) {
            memcpy(&destination, addr_info->ai_addr, sizeof(struct sockaddr_in));
            break;
        } else {
            printf("create socket error: %s\n", strerror(errno));
            goto EXIT_TRACEROUTE;
        }
    }
    if(NULL == addr_info) {
        printf("unknown host: %s\n", host);
        goto EXIT_TRACEROUTE;
    }
    inet_ntop(destination.sin_family, &destination.sin_addr, dest_ip, INET6_ADDRSTRLEN);    // convert ip to string
    printf("traceroute to %s (%s)\n", host, dest_ip);

    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));    // set ttl to 1

    struct timeval timeout;
    socklen_t from_len = sizeof(from);
    int try_cnt = 0;
    int maxfds = sockfd + 1;
    fd_set rfds;

    while(ttl <= MAX_HOPS) {
        int len;
        FD_ZERO(&rfds);           // clear the set
        FD_SET(sockfd, &rfds);    // add sockfd to the set
        timeout.tv_sec  = 1;
        timeout.tv_usec = 0;
        from_len = sizeof(from);

        send_icmp_packet(&ping_param);

        int res = select(maxfds, &rfds, NULL, NULL, &timeout);    // the return value is the number of ready file descriptors
        if(res < 0) {
            printf("select error: %s\n", strerror(errno));
            goto EXIT_TRACEROUTE;
        } else if(res == 0) {    // timeout
            if(try_cnt == MAX_TRY) {
                show_asterisk(ttl, print_obj);
                ttl++;
                try_cnt = 0;
                setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                continue;
            }
            try_cnt++;
            continue;
        } else {
            if (FD_ISSET(sockfd, &rfds)) {    // sockfd is ready
                if((len = recvfrom(sockfd, buffer, PACKET_LEN, 0, (struct sockaddr*) &from, &from_len)) <= 0) {
                    printf("recvfrom error: %s\n", strerror(errno));
                    goto EXIT_TRACEROUTE;
                }
                clock_gettime(CLOCK_REALTIME, &recv_time);

                if(check_recv_packet(buffer, &ping_param) == 0) {
                    // destination host has arrived
                    if(from.sin_addr.s_addr == destination.sin_addr.s_addr) {
                        analyze_icmp(buffer, (unsigned int)len, &from, ttl, ping_param.send_time, print_obj);
                        printf("traceroute completed\n");
                        break;
                    }
                    // the host has not arrived
                    if(0 == host_has_arrived(from.sin_addr.s_addr, addresses)) {
                        addresses[ttl - 1] = from.sin_addr.s_addr;
                        analyze_icmp(buffer, (unsigned int)len, &from, ttl, ping_param.send_time, print_obj);
                        ttl++;
                        try_cnt = 0;
                        setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                        continue;
                    }
                } else {  // not icmp packet
                    if(try_cnt == MAX_TRY) {
                        show_asterisk(ttl, print_obj);
                        ttl++;
                        try_cnt = 0;
                        setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof(ttl));
                        continue;
                    }
                    try_cnt++;
                }
            }
        }
    }
    traceroute_out = create_json_string_of_traceroute(print_obj);

EXIT_TRACEROUTE:
    if (NULL != addr_info_list) {
        freeaddrinfo(addr_info_list);
    }
    if (sockfd > 0) {
        close(sockfd);
    }
    if (NULL != print_obj) {
        free_print_list(print_obj);
    }

    return traceroute_out;
}
