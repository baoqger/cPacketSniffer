#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "udpsegment.h"
#include "utils.h"

// Returns the UDP segment header length in bytes
static unsigned int header_length(udpsegment *u) {
    return 8;
} 

// Returns source port
static unsigned int source_port(udpsegment *u) {
    return char2word(u->p_data);
}

// Return destination port
static unsigned int destination_port(udpsegment *u) {
    return char2word(u->p_data + 2);
}

// Return the length field
static unsigned int len(udpsegment *u) {
    return char2word(u->p_data + 4);
}

// Returns the checksum field
static unsigned int checksum(udpsegment *u) {
    return char2word(u->p_data + 6);
}

// Returns a string textually identifying most popular standard ports
static char* port_name(unsigned int num) {
    switch(num) {
        case 20:
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67:
        case 68: return "DHCP";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 137:
        case 150: return "NetBIOS";
        case 389: return "LDAP";
        case 546:
        case 547: return "DHCP";
    }
    // Distinguish assigned ports from ephemerals
    if (num < 1024) {
        return "unknown";
    } else {
        return "ephemeral";
    }
}

// Returns a string textually identifying some common standard ports
void print_udpsegment(udpsegment *u) {
    if (u->p_data) {
        char outstr[8];
        printf("source port = %d", u->source_port(u));
        printf(" [%s]\n", u->port_name(u->source_port(u)));

        printf("destination port = %d", u->destination_port(u));
        printf("[%s]\n", u->port_name(u->destination_port(u)));
        
        printf("length = %d\n", u->len(u));
        sprintf(outstr, "0x%.4x", u->checksum(u)); 
        printf("checksum = %s\n", outstr);
        
    }
}


// create a new udpsegment instance
udpsegment* new_udpsegment(bool owned, unsigned char *p_data, unsigned int p_len) {
    udpsegment *u = malloc(sizeof(udpsegment));
    u->p_len = p_len;
    u->owned = owned;
    u->header_length = header_length;
    u->source_port = source_port;
    u->destination_port = destination_port;
    u->len = len;
    u->checksum = checksum;
    u->port_name = port_name;
    u->print_udpsegment = print_udpsegment;
    if (u->owned) { // copy the data into a new block
        memcpy(u->p_data, p_data, p_len);
    } else {
        u->p_data = p_data;
    }
    return u; 
}
