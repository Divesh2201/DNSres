#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

bool is_type(char *argv) {
    if(!strcmp(argv, "A") || !strcmp(argv, "NS") || !strcmp(argv, "MX")) return true;
    return false;
}

int main(int argc, char *argv[]) {
    printf("Hello from DNSres\n");
    int total_possible_servers = argc-1;
    char **SERVERS = (char **) malloc(sizeof(char *) * total_possible_servers);
    char **SERVER_i = SERVERS;
    char *NAME = NULL;
    char *TYPE = "A";
    for(int i = 1; i < argc; i++) {
        if (argv[i][0] == '@') {
            *SERVER_i = argv[i];
            SERVER_i++;
        } else if(is_type(argv[i])) {
            TYPE = argv[i];
        } else {
            NAME = argv[i]; 
        }
    }
    SERVER_i = SERVERS;
    while(*SERVER_i != NULL) {
        printf("Lookup DNS Resolver %s\n", *SERVER_i);
        SERVER_i++;
    }
    printf("The domain name is %s\n", NAME);
    printf("The type is %s\n", TYPE);
    return 0;
}