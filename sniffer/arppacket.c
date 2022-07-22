#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "arppacket.h"
#include "utils.h"

// Indicates what ARP operation the packet transport
unsigned int operation_code(arppacket *a) {
    if (a->p_data) {
        return char2word(a->p_data + 6); // operation code stored in two bytes
    } else {
        return 0;
    }
}

// Indicate what ARP operation the packet transport
ARPPacketType operation(arppacket *a) {
    switch(a->operation_code(a)) {
        case 0x0001: return akt_ArpRequest;
        case 0x0002: return akt_ArpReply;
        case 0x0003: return akt_RarpRequest;
        case 0x0004: return akt_RarpReply;
        default    : return akt_unknown;
    }
}


// Display the ARP packet header fields in human readable format
void print_arppacket(arppacket *a) {
    if (a->p_data) {
        char outstr[7];

        // Get operation code
        sprintf(outstr, "0x%.4x", a->operation_code(a));

        // Display operation textually along its corresponding code
        printf("packet type = ");
        switch(a->operation(a)) {
            case akt_ArpRequest:  printf("ARP request [%s]\n", outstr); 
            case akt_ArpReply:    printf("ARP reply [%s]\n", outstr);
            case akt_RarpRequest: printf("RARP requesst [%s]\n", outstr);
            case akt_RarpReply:   printf("RARP reply [%s]\n", outstr);
            default:              printf("unknown [%s]",outstr);
        }
    }
}

arppacket* new_arppacket(bool owned, unsigned char *p_data, unsigned int p_len) {
    arppacket *a = malloc(sizeof(arppacket));
    a->p_len = p_len;
    a->owned = owned;
    a->print_arppacket = print_arppacket;
    a->operation_code = operation_code;
    a->operation = operation;
    if(a->owned) { // copy data into a new block
        memcpy(a->p_data, p_data, p_len);
    } else {
        a->p_data = p_data;
    }
    return a;
}

