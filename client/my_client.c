#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>

#define SERVER_IP "192.168.31.250"
#define SERVER_PORT 5353

unsigned short calculate_checksum(void *b, int len) {    
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void fill_icmp_packet(struct icmphdr *icmp_hdr, int packet_size) {
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = getpid();
    icmp_hdr->un.echo.sequence = 1;
    memset(icmp_hdr + 1, 0xA5, packet_size - sizeof(*icmp_hdr)); // 填充数据部分
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = calculate_checksum(icmp_hdr, packet_size);
}

void receive_icmp_echo_reply(int sockfd) {
    char buffer[1024]; // 接收缓冲区
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&from, &from_len) < 0) {
        perror("Recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // 解析接收到的包
    struct iphdr *ip_hdr = (struct iphdr *)buffer;
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + (ip_hdr->ihl * 4)); // IP header length field * 4

    // 检查ICMP类型和代码
    if (icmp_hdr->type == ICMP_ECHOREPLY) {
        printf("ICMP echo reply received from %s\n", inet_ntoa(from.sin_addr));
        if (icmp_hdr->un.echo.id == getpid()) { // 确认响应是针对我们发出的请求
            printf("ICMP echo reply matches our echo request\n");
        } else {
            printf("Received ICMP echo reply does not match our echo request\n");
        }
    } else {
        printf("Received ICMP type %d code %d\n", icmp_hdr->type, icmp_hdr->code);
    }
}


void send_icmp_echo(const char *target_ip) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip, &dest_addr.sin_addr);

    const int packet_size = sizeof(struct icmphdr) + 32;
    char packet[packet_size];
    memset(packet, 0, packet_size);

    fill_icmp_packet((struct icmphdr *)packet, 32);

    if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    receive_icmp_echo_reply(sockfd);
    printf("ICMP echo request sent to %s\n", target_ip);
    close(sockfd);
}

typedef struct {
    uint16_t id;
    uint8_t flags[2];
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
} __attribute__((packed)) dns_header_t;

typedef struct{
    uint16_t QTYPE;
    uint16_t QCLASS;
} __attribute__((packed)) query_t;

void domain_to_dns_format(const char *domain, unsigned char *dns_format)
{
    int lock = 0;
    int i;
    int domain_length = strlen(domain);
    char domain_copy[256];

    strcpy(domain_copy, domain);
    strcat(domain_copy, ".");

    for (i = 0; i < strlen(domain_copy); i++) {
        if (domain_copy[i] == '.') {
            *dns_format++ = i - lock;
            for (; lock < i; lock++) {
                *dns_format++ = domain_copy[lock];
            }
            lock++;
        }
    }

    *dns_format++ = '\0';
}

void initial_dns_header(dns_header_t *dns_header)
{
    dns_header->id = htons(getpid());
    dns_header->flags[0] = 0x01;
    dns_header->flags[1] = 0x00;
    dns_header->q_count = htons(1);
    dns_header->ans_count = 0;
    dns_header->auth_count = 0;
    dns_header->add_count = 0;
}

/*****************************************************************
* Function: build_dns_request
* Description: build dns request messege
* Input:
*    buffer: a buffer for saving DNS request messege
*    domain: request domain
* Return: size of messege
*****************************************************************/
int build_dns_request(unsigned char *buffer, const char* domain)
{
    dns_header_t *dns_header = (dns_header_t *)buffer;
    initial_dns_header(dns_header);

    unsigned char *qname = buffer + sizeof(dns_header_t);
    domain_to_dns_format(domain, qname);

    query_t *query_info = (query_t *)(qname + strlen((char *)qname) + 1);//add one to miss /0
    query_info->QTYPE = htons(1);
    query_info->QCLASS = htons(1);

    // 返回完整的请求大小
    return sizeof(dns_header_t) + strlen((char *)qname) + 1 + sizeof(query_t);
}

void parse_dns_response(unsigned char *buffer)
{
    dns_header_t *dns_header = (dns_header_t *) buffer;
    unsigned char *reader = buffer + sizeof(dns_header_t);

    // 跳过问题部分
    for (int i = 0; i < ntohs(dns_header->q_count); i++) {
        while (*reader != 0) {
            reader++;
        }
        reader += 5; // 跳过末尾的 null 字节和 QTYPE + QCLASS（2 + 2）
    }

    printf("Answer RRs: %d\n", ntohs(dns_header->ans_count));

    for (int i = 0; i < ntohs(dns_header->ans_count); i++) {
        // 跳过名字部分
        if (*reader == 0xc0) {
            reader += 2;
        } else {
            while (*reader != 0) {
                reader++;
            }
            reader++;
        }

        // 读取类型、类、TTL 和数据长度
        uint16_t type = ntohs(*(uint16_t *)reader);
        printf("Raw Type: %02x %02x\n", reader[0], reader[1]); // 调试打印
        reader += 2;
        uint16_t class = ntohs(*(uint16_t *)reader);
        printf("Raw Class: %02x %02x\n", reader[0], reader[1]); // 调试打印
        reader += 2;
        uint32_t ttl = ntohl(*(uint32_t *)reader);
        reader += 4;
        uint16_t data_len = ntohs(*(uint16_t *)reader);
        reader += 2;

        // 打印调试信息
        printf("Resource Record %d:\n", i + 1);
        printf("\tType: %u\n", type);
        printf("\tClass: %u\n", class);
        printf("\tTTL: %u\n", ttl);
        printf("\tData Length: %u\n", data_len);

        // 读取数据部分
        if (type == 1 && class == 1) { // A 记录
            struct in_addr addr;
            memcpy(&addr, reader, data_len);
            printf("\tIP Address: %s\n", inet_ntoa(addr));
        }
        reader += data_len;
    }
}




/*****************************************************************
* Function: send_dns_request
* Description: build dns request messege
* Input:
*    dns_server: IP of dns server
*    domain: request domain
* Return:
*****************************************************************/
void send_dns_request(const char *dns_server, const char *domain)
{
    int sockfd;
    struct sockaddr_in dest;
    unsigned char buffer[512];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, dns_server, &dest.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    int query_size = build_dns_request(buffer, domain);
    if (sendto(sockfd, buffer, query_size, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS request sent for %s to %s\n", domain, dns_server);
    int len = sizeof(dest);
    if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&dest, &len) < 0) {
        perror("recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    parse_dns_response(buffer);
    close(sockfd);
}


int main()
{
    char server_ip[16];
    char type_of_protocol[100];
    char dns_server[30];
    char domain_name[100];

    while (1)
    {
        printf("send icmp or dns\n");
        fgets(type_of_protocol, sizeof(type_of_protocol), stdin);
        type_of_protocol[strcspn(type_of_protocol, "\n")] = 0;

        if (strcmp(type_of_protocol, "send icmp") == 0)
        {
            printf("Enter server IP:\n");
            scanf("%15s", server_ip);
            send_icmp_echo(server_ip);
            while (getchar() != '\n');
        }
        else if (strcmp(type_of_protocol, "send dns") == 0)
        {
                printf("Enter DNS server IP: ");
                scanf("%29s", dns_server);
                printf("Enter domain name to query: ");
                scanf("%99s", domain_name);

                send_dns_request(dns_server, domain_name);
        }
    }
    return 0;
}
