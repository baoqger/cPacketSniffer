#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include "utils.h"
#include "icmppacket.h"
#include "ipaddress.h"

jmp_buf env;


// Try-Catch-Throw macro
#define TRY if(set_jmp(env) == 0)
#define CATCH else 
#define THROW longjmp(env, 1)

// Returns the ICMP header length bytes
unsigned int header_length(icmppacket *i) {
    if(!i->p_data) {
        return 0;
    } else {
        return 8;
    }
}

// Returns a textual description of the packet according to its type and code fields
char* description(icmppacket *i) {
    unsigned int msg_id = (i->type(i) << 8) + i->code(i);
    switch(msg_id) {
        case 0x0000: return "echo reply";
        case 0x0300: return "network unreachable";
        case 0x0301: return "host unreachable";
        
    }
}

// Returns content of type header field
unsigned int type(icmppacket *i) {
    return i->p_data[0];
}

// Returns content of code header field
unsigned int code(icmppacket *i) {
    return i->p_data[1];
}

// Returns content of checksum header field
unsigned int checksum(icmppacket *i) {
    return char2word(i->p_data + 2);
}

// Returns content of identifier header field for type 13, 14, 17 or 18 ICMP packets
unsigned int identifier(icmppacket *i) {
    if (i->code(i) == 0 || (i->type(i) == 13 || i->type(i) == 14 || i->type(i) == 17 || i->type(i) == 18)) {
        return char2word(i->p_data + 4);
    } else {
        fprintf(stderr, "ICMP packet does not hold identifier field\n");
        // exit(EXIT_FAILURE);
        THROW;
    }
}

// Returns content of sequence number header field for 13, 14, 17 or 18 ICMP packets
unsigned int sequence_number(icmppacket *i) {
    if(i->code(i) == 0 || (i->type(i) == 13 || i->type(i) == 14 || i->type(i) == 17 || i->type(i) == 18)) {
        return char2word(i->p_data + 6);
    } else {
        fprintf(stderr, "ICMP packet does not hold sequence number field.\n");
        //exit(EXIT_FAILURE);
        THROW;
    }
}

// Returns content of next-hop MTU header field for type 3 ICMP packets
unsigned int next_hop_MTU(icmppacket *i) {
    if (i->type(i) == 3) {
        return char2word(i->p_data + 6);
    } else {
        fprintf(stderr, "ICMP packet does not hold next-hop MTU field.\n");
        //exit(EXIT_FAILURE);
        THROW;
    }
}

// Return content of originate timestamp header field for type 13 or 14 ICMP packets
unsigned int originate_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && (i->type(i) == 13 || i->type(i) == 14)) {
        return char4word(i->p_data + 8);
    } else {
        fprintf(stderr, "ICMP packet does not hold originate timestamp field.\n");
        // exit(EXIT_FAILURE);
        THROW;
    }
}   

// Returns content of receive timestamp header field for type 14 ICMP packets
unsigned int receive_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && i->type(i) == 14) {
        return char4word(i->p_data + 12);
    } else {
        fprintf(stderr, "ICMP packet does not hold receive timestamp field.\n");
        THROW;
    }
} 

// Returns content of transmit timestamp header field for type 14 ICMP packets 
unsigned int transmit_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && i->type(i) == 14){
        return char4word(i->p_data + 16);
    } else {
        fprintf(stderr, "ICMP packet does not hold transmit timestamp field.\n");
        THROW;
    }
}

// Returns content of IP address header field for type 5 ICMP packets
ipaddress* ip_address(icmppacket *i) {
    if(i->type(i) == 5) {
        return new_ipaddress(false, i->p_data + 4);
    } else {
        fprintf(stderr, "ICMP packet does not hold IP address field.\n");
        THROW;
    }
} 

// Returns content of address mask header field for type 17 or 18 ICMP packets
ipaddress* address_mask(icmppacket *i) {
    if(i->code(i) == 0 && (i->type(i) == 17 || i->type(i) == 18)) {
        return new_ipaddress(false, i->p_data + 8);
    } else {
        fprintf(stderr, "ICMP packet does not hold address mask field.\n");
        THROW;
    }
}

icmppacket* new_icmppacket(bool owned, unsigned char *p_data, unsigned int p_len) {
    icmppacket *i = malloc(sizeof(icmppacket));
    i->p_len = p_len;
    i->owned = owned;
    i->header_length = header_length;
    i->type = type;
    i->checksum = checksum;
    i->identifier = identifier;
    i->sequence_number = sequence_number;
    i->next_hop_MTU = next_hop_MTU;
    i->originate_timestamp = originate_timestamp;
    i->receive_timestamp = receive_timestamp;
    i->transmit_timestamp = transmit_timestamp;
    i->ip_address = ip_address;
    if(i->owned) { // copy data into a new block
        memcpy(i->p_data, p_data, p_len);
    } else {
        i->p_data = p_data;
    }
    return i;
}
