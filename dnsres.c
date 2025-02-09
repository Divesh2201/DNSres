#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct dns_header {
    uint16_t tx_id;
    uint16_t flags;
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authorities;
    uint16_t num_additional;
}; // 12 byte header

struct root_server {
    char hostname[48];
    char ipv4[16];
};

struct root_server root_servers[13] = {
    {"a.root-servers.net", "198.41.0.4"},	// Verisign, Inc.
    {"b.root-servers.net", "170.247.170.2"}, //	University of Southern California, Information Sciences Institute
    {"c.root-servers.net", "192.33.4.12"}, // Cogent Communications
    {"d.root-servers.net", "199.7.91.13"}, // University of Maryland
    {"e.root-servers.net", "192.203.230.10"}, // NASA (Ames Research Center)
    {"f.root-servers.net", "192.5.5.241"}, // Internet Systems Consortium, Inc.
    {"g.root-servers.net", "192.112.36.4"}, // US Department of Defense (NIC)
    {"h.root-servers.net", "198.97.190.53"}, // US Army (Research Lab)
    {"i.root-servers.net", "192.36.148.17"}, // Netnod
    {"j.root-servers.net", "192.58.128.30"}, // Verisign, Inc.
    {"k.root-servers.net", "193.0.14.129"}, // RIPE NCC
    {"l.root-servers.net", "199.7.83.42"}, // ICANN
    {"m.root-servers.net", "202.12.27.33"}, // WIDE Project
};

// dns_query_header (12) - encoded domain name (variable bytes) - QTYPE (2) - QCLASS (2)


void dns_encode_domain(char *domain_name, char *encoded_domain) {
    // separate domain based on delimiter '.'
    // prefix using one byte, the byte length of each part
    // end with 0, since the last part has 0 bytes
    // eg: www.apple.com is \x03www\x05apple\x03com\x00
    int part_len = 0;
    // leave first byte empty for following part byte length, eg; \x03 for www
    encoded_domain++;
    while(*domain_name != '\0') {
        if(*domain_name == '.') {
            *(encoded_domain-part_len-1) = part_len+'0';
            part_len = 0;
        } else {
            part_len++;
            *encoded_domain = *domain_name;
        }
        encoded_domain++;
        domain_name++;
    }
    *(encoded_domain-part_len-1) = part_len;
}

void print_encoded_domain(char *encoded_domain, int len) {
    printf("Calculated encoded domain with length %d is \n", len);
    for(int i = 0; i <= len; i++) {
        printf("for i %d, we have %d\n", i, encoded_domain[i]);
    }
    printf("\n");
}

bool is_type(char *argv) {
    if(!strcmp(argv, "A") || !strcmp(argv, "NS") || !strcmp(argv, "MX")) return true;
    return false;
}

int main(int argc, char *argv[]) {
    printf("Hello from DNSres\n");
    int total_possible_servers = argc-1;
    // List of DNS Resolvers the user wants to query
    char **dnsres_servers = (char **) malloc(sizeof(char *) * total_possible_servers);
    // dummy variable to iterate over SERVERS array
    char **dnsres_server_i = dnsres_servers;
    // Domain name user wants to query
    char *domain_name = NULL;
    // DNS query type
    char *qtype = "A";
    for(int i = 1; i < argc; i++) {
        if (argv[i][0] == '@') {
            *dnsres_server_i = argv[i];
            dnsres_server_i++;
        } else if(is_type(argv[i])) {
            qtype = argv[i];
        } else {
            domain_name = argv[i]; 
        }
    }
    printf("The domain name is %s\n", domain_name);
    printf("The type is %s\n", qtype);

    // DNSres communication endpoint
    int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    // create the DNS query
    int domain_name_len = strlen(domain_name);
    // NOTE: this length does NOT include a null terminator for this string 
    int encoded_domain_len = domain_name_len+2;
    char *encoded_domain = (char*) calloc(encoded_domain_len+1, sizeof(char));
    dns_encode_domain(domain_name, encoded_domain);
    // print_encoded_domain(encoded_domain, encoded_domain_len);
    char dns_query[512];
    memset(dns_query, 0, sizeof(dns_query));
    int dns_query_len = 0;

    struct dns_header *dns_query_header = (struct dns_header*) malloc(sizeof(struct dns_header));
    dns_query_header->tx_id = htons(0x1234);
    dns_query_header->flags = htons(0x0100);
    dns_query_header->num_questions = htons(1);
    dns_query_header->num_answers = htons(0);
    dns_query_header->num_additional = htons(0);
    dns_query_header->num_authorities = htons(0);
    memcpy(dns_query, dns_query_header, sizeof(*dns_query_header));
    dns_query_len += sizeof(dns_query_header);

    memcpy(dns_query + dns_query_len, encoded_domain, encoded_domain_len);
    dns_query_len += encoded_domain_len;
    uint16_t encoded_qtype = htons(1); // A record
    uint16_t encoded_qclass = htons(1); // Internet

    memcpy(dns_query + dns_query_len, &encoded_qtype, sizeof(encoded_qtype));
    dns_query_len += sizeof(encoded_qtype);

    memcpy(dns_query + dns_query_len, &encoded_qclass, sizeof(encoded_qclass));
    dns_query_len += sizeof(encoded_qclass);

    struct sockaddr_in dns_server_addr_in;
    dns_server_addr_in.sin_family = AF_INET;
    dns_server_addr_in.sin_port = htons(53);
    int num_root_servers = sizeof root_servers / sizeof *root_servers;
    for(int i = 0; i < num_root_servers; i++) {
        inet_aton(root_servers[i].ipv4, &dns_server_addr_in.sin_addr);
        // sendto does NOT establish connection (suitable for UDP)
        // if it were TCP we REQUIRE already established connection
        if (sendto(udp_socket_fd, dns_query, dns_query_len, 0, (struct sockaddr *)&dns_server_addr_in, sizeof(dns_server_addr_in)) < 0) {
            continue;
        }
    }
    free(dnsres_servers);
    free(dns_query_header);
    return 0;
}