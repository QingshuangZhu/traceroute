#ifndef __TRACEROUTE_H
#define __TRACEROUTE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <netinet/in.h>

#define MAX_HOPS 30      /* the number of hops */ 
#define MAX_TRY 3        /* the number of probes per each hop */
#define PACKET_LEN 80    /* The full packet length (default is the length of an IP header plus 40) */

struct icmp_param
{
    struct sockaddr_in *destination;    /* IPv4 destination address */
    struct timespec *send_time;         /* send time */
    int *sockfd;                        /* socket descriptor */
    unsigned int *size_data;            /* size of data */
    int pid;                            /* process id */
    int seq;                            /* sequence number */
};

typedef struct json_node_t
{
    char ip[48];                 /* ip address */
    char rrt[16];                /* round-trip time */
    char ttl[8];                 /* time to live */
    struct json_node_t *next;    /* next node */
} print_node_t;

typedef struct print_ctrl_tag
{
    print_node_t *head;            /* head of the list */
    print_node_t *current_node;    /* current node */
    int size;
} print_ctrl_t;

/**
 * \brief Calculate the checksum for ICMP (Internet Control Message Protocol) packets.
 * \param buffer : pointer to the icmp packet
 * \param length : total length of the icmp packet
 * \return checksum value
 */
uint16_t check_sum(const void *buffer, size_t length);

/**
 * \brief Send ICMP packets.
 * \param param : pointer to the icmp_param structure
 */
void send_icmp_packet(struct icmp_param *param);

/** 
 * \brief Check if the received ICMP packet is valid.
 * \param recv_buffer : pointer to the buffer where the received packet
 * \param param : pointer to the icmp_param structure
 * \return 0 if the packet is valid, -1 otherwise
 */
int check_recv_packet(const void *recv_buffer, struct icmp_param *param);

/**
 * \brief Check if an IP address exists in an array of IP addresses.
 * \param ip  : the ip address of the host
 * \param tab  : the array of ip addresses
 * \return 1 if the host has arrived, 0 otherwise
 */
int host_has_arrived(uint32_t ip, uint32_t *tab);

/**
 * \brief Calculate the time difference between two timespec structures.
 * \param send : a pointer to the timespec structure representing the time before sending the packet
 * \param recv : a pointer to the timespec structure representing the time after receiving the packet
 * \return a pointer to the timespec structure representing the time difference
 */
struct timespec time_diff(struct timespec *send, struct timespec *recv);

/**
 * \brief Analyze the packets returned from the network.
 * \param buffer : buffer containing the packet
 * \param size : size of the buffer
 * \param from : address of the sender
 * \param ttl : time to live
 * \param tbef : time before sending
 * \param print_obj : pointer to the print control structure
 */
void analyze_icmp(const void *buffer, unsigned int size, struct sockaddr_in *from, int ttl, struct timespec *tbef, print_ctrl_t *print_obj);

/**
 * \brief Print an asterisk for each hop.
 * \param hop : the number of the hop
 * \param print_obj : pointer to the print control structure
 */
void show_asterisk(int hop, print_ctrl_t *print_obj);

/**
 * \brief Create a json string of the traceroute.
 * \param list : pointer to the print control structure
 * \return the json string of the traceroute
 */
char* create_json_string_of_traceroute(print_ctrl_t *list);

/**
 * \brief Trace route the host.
 * \host : the host to trace route
 * \return the json string of the traceroute
 */
char* traceroute_report(const char *host);

#ifdef __cplusplus
}
#endif

#endif // __TRACEROUTE_H
