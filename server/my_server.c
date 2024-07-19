#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#define BUFFER_SIZE 512
#define PORT 9876

typedef struct {
    uint16_t id;
    uint8_t flags[2];
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
} __attribute__((packed)) dns_header_t;

typedef struct {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata; // For A record
} __attribute__((packed)) dns_response_t;

void get_dns_query_domain(const unsigned char *buffer, int msg_len ,unsigned char* DNS_name) {
    dns_header_t *dns_hdr = (dns_header_t *)buffer;
    int query_offset = sizeof(dns_header_t); // 跳过DNS头部
    int index = 0;

    printf("Extracted Domain Name: ");
    while (buffer[query_offset] != 0 && query_offset < msg_len) {
        if (query_offset > sizeof(dns_header_t) && index > 0) {
            DNS_name[index++] = '.';
        }

        int label_length = buffer[query_offset++];
        for (int i = 0; i < label_length; ++i) {
            DNS_name[index++] = buffer[query_offset++];
        }
    }
    DNS_name[index] = '\0';
    // this is a test for git
    printf("%s\n",DNS_name);
}

int get_ip(char *hostname, unsigned char *ip_buffer) {
    struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        return 1; // 错误发生
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (int i = 0; addr_list[i] != NULL; i++) {
        // 将第一个找到的地址复制到 ip_buffer，假设空间已经足够
        memcpy(ip_buffer, addr_list[i], sizeof(struct in_addr));
        printf("ip is: %s\n", inet_ntoa(*(struct in_addr*)ip_buffer));
        return 0; // 成功
    }

    return 2; // 未找到有效的 IP 地址
}

void send_dns_response(int sockfd, struct sockaddr_in client_addr, unsigned char *request, int request_len ,unsigned char* IP_BUFFER, unsigned char* DNS_name) {
    unsigned char response[BUFFER_SIZE];
    memset(response, 0, BUFFER_SIZE);

    int header_size = sizeof(dns_header_t);
    int query_size = header_size;
    while (request[query_size] != 0) {
        query_size++;
    }
    query_size += 5;

    memcpy(response, request, query_size);

    dns_header_t *dns_header = (dns_header_t *)response;
    dns_header->flags[0] = 0x81;
    dns_header->flags[1] = 0x80;
    dns_header->ans_count = htons(1);
    dns_header->auth_count = 0;
    dns_header->add_count = 0;

    int answer_start = query_size;
    response[answer_start] = 0xC0;
    response[answer_start + 1] = header_size;

    dns_response_t *response_record = (dns_response_t *)(response + answer_start + 2);
    response_record->type = htons(1);
    response_record->class = htons(1);
    response_record->ttl = htonl(300);
    response_record->rdlength = htons(4);

    // Directly set the IP address in the rdata field
    get_dns_query_domain(request, request_len, DNS_name);
    get_ip(DNS_name, IP_BUFFER);
    
    memcpy(&response_record->rdata, IP_BUFFER, sizeof(uint32_t));
    //*(uint32_t *)&response_record->rdata = inet_addr(IP_BUFFER);

    int total_length = answer_start + 2 + sizeof(dns_response_t) + 4;
    sendto(sockfd, response, total_length, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}



void run_dns_server(unsigned char* DNS_name, unsigned char* IP_BUFFER) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DNS Server is running on port %d\n", PORT);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        int msg_len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len);
        if (msg_len < 0) {
            perror("recvfrom failed");
            continue;
        }
        send_dns_response(sockfd, client_addr, buffer, msg_len, IP_BUFFER, DNS_name);
    }

    close(sockfd);
}

int main() {
    unsigned char DNS_name[255];
    unsigned char IP_BUFFER[16];
    run_dns_server(DNS_name, IP_BUFFER);
    return 0;
}
