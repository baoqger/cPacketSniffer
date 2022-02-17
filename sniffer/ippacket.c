#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ippacket.h"
#include "utils.h"

// Version: The first header field is the four-bit version field. 
// For IPv4, this has a value of 4.
unsigned int version(ippacket *i) {
    return i->p_data[0] >> 4;
}

// Internet Header Length (IHL): The 4-bit field indicates the number of 32-bit(or 4 bytes) words in the header.
// stored in the low 4 bits of the first byte of ip packet
unsigned int ihl(ippacket *i) {
    return i->p_data[0] & 0x0F;
}

// Based on the above definition of IHL, the header length in bytes can be computed as ihl() * 4
unsigned int ip_header_length(ippacket *i) {
    if (!i->p_data) {
        return 0;
    } else {
        return 4 * i->ihl(i);
    }
}

// Type Of Service (TOS): The TOS field specifies a packet's priority and 
// requests a route for low-delay, high-throughput, or highly-reliable service.
// store in the second byte of ip packet
unsigned int tos(ippacket *i) {
    return i->p_data[1];
}

// Total Length: This 16-bit field defines the entire packet (fragment) size, 
// including header and data, in bytes.
unsigned int totol_length(ippacket *i) {
    return char2word(i->p_data + 2);
}

// Identification: This field is an identification field and is primarily 
// used for uniquely identifying fragments of an original IP datagram.
unsigned int fragment_id(ippacket *i) {
    return char2word(i->p_data + 4);
}

// Flags: A three-bit field follows and is used to control or identify fragments. They are (in order, from high order to low order):
    // bit 0: Reserved; must be zero.
    // bit 1: Don't Fragment (DF)
    // bit 2: More Fragments (MF)
unsigned int fragment_flags(ippacket *i) {
    return i->p_data[6] >> 5;
}

unsigned int fragment_pos(ippacket *i) {
    unsigned int d = i->p_data[6] & 0x1F;
    return d << 8 | i->p_data[7];
}

// Protocol: This field defines the protocol transported in the data portion of the IP datagram.
// store 9th bytes of ip packet
unsigned int protocol_id(ippacket *i) {
    return i->p_data[9];
}

// Indicates which protocol is encapsulated within the packet's payload
ipprotocol protocol(ippacket *i) {
    switch(i->protocol_id(i)) {
        case 1: return ipp_icmp;
        case 2: return ipp_igmp;
        case 6: return ipp_tcp;
        case 17: return ipp_udp;
        default: return ipp_other; 
    }
}

// Time To Live (TTL): This eight-bit field helps prevent datagrams from circulating forever on an Internet. 
// store in the 8th byte of ip packet 
unsigned int ttl(ippacket *i) {
    return i->p_data[8];
}

// Checksum: The 16-bit checksum field is used for error-checking of the header.
unsigned int checksum(ippacket *i) {
    return char2word(i->p_data + 10);
}

void print_ippacket(ippacket *i) {
    if (i->p_data) {
        char outstr[8];
        printf("version = ");
        switch(i->version(i)) {
            case 4: printf("IPv4\n"); break;
            case 6: printf("IPv6\n"); break;
            default: printf("unknown [%d]\n", i->version(i));
        }
        printf("header length = %d (IHL = %d) \n", i->ip_header_length(i), i->ihl(i));
        printf("type of service = %d:\n", i->tos(i));
        if (i->tos(i) > 0) {
            switch(i->tos(i) >> 5) {
                case 0: printf(" precedence = routine\n"); break;
                case 1: printf(" precedence = priority\n"); break;
                case 2: printf(" precedence = immediate\n"); break;
                case 3: printf(" precedence = flash\n"); break;
                case 4: printf(" precedence = flash override\n"); break;
                case 5: printf(" precedence = critical\n"); break;
                case 6: printf(" precedence = internetwork control\n"); break;
                case 7: printf(" precedence = network control\n"); break;
            }
            // type of service in textual form
            if (i->tos(i) & 0x10) // 0x10: 00010000
                printf(" delay = low\n");
            else
                printf(" delay = normal\n");
            
            if (i->tos(i) & 0x08) // 0x08: 00001000
                printf(" throughtput = high\n");
            else 
                printf(" throughtput = normal\n");

            if (i->tos(i) & 0x04) // 0x04: 00000100
                printf(" reliability = high \n");
            else 
                printf(" reliability = normal \n ");

            if (i->tos(i) & 0x02) // 0x02: 00000010
                printf(" cost = low \n");
            else 
                printf(" cost = normal \n");
        }

        printf("total length = %d\n", i->total_length(i));

        printf("fragment ID = 0x%.4x\n", i->fragment_id(i));
        printf(" don't fragment = %d\n", i->fragment_flags(i) & 0x2);
        printf(" more fragments = %d\n", i->fragment_flags(i) & 0x1);
        printf(" fragment position = %d\n", i->fragment_pos(i));

        printf("protocol = ");
        switch(i->protocol(i)) {
            case ipp_icmp: printf("ICMP ["); break;
            case ipp_igmp: printf("IGMP ["); break;
            case ipp_tcp: printf("TCP ["); break;
            case ipp_udp: printf("UDP ["); break;
            default: printf("unknown ["); break;
        }
        printf("0x%.2x]\n", i->protocol_id(i));

        printf("time to live = %d\n", i->ttl(i));

        printf("checksum = 0x%.4x \n", i->checksum(i));
    }
}

ippacket* new_ippacket(bool owned, unsigned char *p_data, unsigned int p_len) {
    ippacket *i = malloc(sizeof(ippacket));
    i->p_len = p_len;
    i->owned = owned;
    i->print_ippacket = print_ippacket;
    i->version = version;
    i->ihl = ihl;
    i->ip_header_length = ip_header_length;
    i->tos = tos;
    i->total_length = totol_length;
    i->fragment_id = fragment_id;
    i->fragment_flags = fragment_flags;
    i->fragment_pos = fragment_pos;
    i->protocol_id = protocol_id;
    i->protocol = protocol;
    i->ttl = ttl;
    i->checksum = checksum;
    if (i->owned) { // copy data into a new block
        memcpy(i->p_data, p_data, p_len); 
    } else {
        i->p_data = p_data;
    }
    return i;
}

