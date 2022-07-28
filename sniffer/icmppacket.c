#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "icmppacket.h"

// Returns the ICMP header length bytes
unsigned int header_length(icmppacket *i) {
    if(!i->p_data) {
        return 0;
    } else {
        return 8;
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
        exit(EXIT_FAILURE); 
    }
}

// Returns content of sequence number header field for 13, 14, 17 or 18 ICMP packets
unsigned int sequence_number(icmppacket *i) {
    if(i->code(i) == 0 || (i->type(i) == 13 || i->type(i) == 14 || i->type(i) == 17 || i->type(i) == 18)) {
        return char2word(i->p_data + 6);
    } else {
        fprintf(stderr, "ICMP packet does not hold sequence number field.\n");
        exit(EXIT_FAILURE);
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
    if(i->owned) { // copy data into a new block
        memcpy(i->p_data, p_data, p_len);
    } else {
        i->p_data = p_data;
    }
    return i;
}
