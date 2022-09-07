#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "ethernetframe.h"
#include "utils.h"

macaddress* destination_mac(ethernetframe *e) {
    return new_macaddress(false, e->p_data);
}

macaddress* source_mac(ethernetframe *e) {
    return new_macaddress(false, (e->p_data + 6)); // replace 6 with MAC_LEN macro;
}

// Extracts from Ethernet header what protocol this transports in its data
unsigned int ether_code(ethernetframe *e) {
    if (e->p_data) {
        return char2word(e->p_data + 12); // after destination and source mac address, each is 6 bytes 
    } else {
        return 0;
    }
}

// Returns an enum value corresponding to what this transports. Only the most frequent 
// layer two protocols arew listed - there are more than one hundred of them in reality!
etherType ether_type(ethernetframe *e) {
    // values of 1500 (0x05DC) and below indicate that it is used as the size of the payload in bytes
    if(e->ether_code(e) <= 0x05DC) {
        return et_Length;
    // values of 1536 (0x0600) and above indicate that it is used to represent EtherType.
    } else {
        switch(e->ether_code(e)) {
            case 0x6000 : return et_DEC;
            case 0x0609 : return et_DEC;
            case 0x0600 : return et_XNS;
            case 0x0800 : return et_IPv4;
            case 0x0806 : return et_ARP;
            case 0x8019 : return et_Domain;
            case 0x8035 : return et_RARP;
            case 0x8037 : return et_IPX;
            case 0x809B : return et_AppleTalk;
            case 0x8100 : return et_802_1Q; 
            case 0x86DD : return et_IPv6;
            case 0x9000 : return et_loopback;
            default     : return et_other;
        }
    } 
}

// Returns the Ethernet header length, which depends on the type of frame
unsigned int header_length(ethernetframe *e) {
    if(!e->p_data) {
        return 0;
    } else if (e->ether_type(e) == et_802_1Q) {
        return 18;
    } else {
        return 14;
    }
}

// Returns number of bytes in ethernetframe
unsigned int length(ethernetframe *e) {
    return e->p_len;
}

// Returns a pointer to beginning of transported data (passed the header)
unsigned char* data(ethernetframe *e) {
    if (e->header_length(e) < e->length(e)) {
        return e->p_data + e->header_length(e);
    } else {
        return NULL;
    }
}

// Priority Code Point (PCP): a 3-bit field which refers to the IEEE 802.1Q frame priority level. 
// Values range from 0 (best effort) to 7 (highest), 1 representing the lowest priority.
// This code is stored in the 3 most significant bits of the header's 14th byte
unsigned int pcp_8021q(ethernetframe *e) {
    if(e->ether_type(e) != et_802_1Q) {
        exit(EXIT_FAILURE);
    }
    return e->p_data[14] >> 5; // right shift 5 bits to get the 3-bit field
}

// Drop Eligible Indicator (DEI): a 1-bit field that may be used separately or 
// in conjunction with PCP to indicate frames eligible to be dropped in times of congestion.
// This code is stored in the 4th most significant bit of the header's  14th byte
unsigned int dei_8021q(ethernetframe *e) {
    if(e->ether_type(e) != et_802_1Q) {
        exit(EXIT_FAILURE);
    }
    return (e->p_data[14] >> 4) & 0x01; // right shift 4 bits then AND with 0001
}

// VLAN Identifier (VID): a 12-bit field specifying the VLAN to which the frame belongs. 
// The values 0x000 and 0xFFF are reserved, but all other values may be used as VLAN identifiers, 
// allowing up to 4,094 VLANs.
// This code is stored in the 12 least significant bits of the header's 14th and 15th bytes
unsigned int vid_8021q(ethernetframe *e) {
    if(e->ether_type(e) != et_802_1Q) {
        exit(EXIT_FAILURE);
    }
    return (char2word(e->p_data + 14)) & 0x0FFF;
}

void print_ethernetframe(ethernetframe *e) {
    if (e->p_data) {
        // Display Mac addresses
        macaddress *d = e->destination_mac(e),
                   *s = e->source_mac(e);
        printf("destination MAC address: ");
        d->print_macaddress(d);
        printf("source MAC address: ");
        s->print_macaddress(s);

        // Display the hexadecimal value of the Ethernet code field (i.e. what the frame transports)
        char outstr[8];
        sprintf(outstr, "0x%.4x", e->ether_code(e));

        // Display the Ethernet code field in textual form. If it's 802.1Q type, the code identifier is dsiplayed later on
        printf("ether type = ");

        switch(e->ether_type(e)) {
            case et_Length:     printf("Length field [%s]\n", outstr); break;
            case et_DEC:        printf("DEC [%s]\n", outstr);          break;
            case et_XNS:        printf("XNS [%s]\n", outstr);          break;
            case et_IPv4:       printf("IPv4 [%s]\n", outstr);         break;
            case et_ARP:        printf("ARP [%s]\n", outstr);          break;
            case et_Domain:     printf("Domain [%s]\n", outstr);       break;
            case et_RARP:       printf("RARP [%s]\n", outstr);         break;
            case et_IPX:        printf("IPX [%s]\n", outstr);          break;
            case et_AppleTalk:  printf("AppleTalk [%s]\n", outstr);    break;
            case et_IPv6:       printf("IPv6 [%s]\n", outstr);         break;
            case et_loopback:   printf("loopback [%s]\n", outstr);     break;
            default:            printf("unknown [%s]\n", outstr);      break;
        }
        // If the frame is 802.1Q, the header contains 4 more bytes.
        // Destination MAC(6 bytes) + Source MAC(6 bytes) + 802.1Q headr(4 bytes) + Frame Type(2 bytes) 
        if (e->ether_type(e) == et_802_1Q) {
            sprintf(outstr, "0x%.4x", char2word(e->p_data + 12));
            printf("ether type = 802.1Q [%s]\n", outstr);
            printf("802.1Q priority code point (PCP) = %d \n", e->pcp_8021q(e));
            printf("802.1Q drop eligible indicator (DEI) = %d \n", e->dei_8021q(e));
            printf("802.1Q vlan identifier (VID) = %d \n", e->vid_8021q(e));
        } 
        
        // Release allocated memory
        free(d);
        free(s);
    }
}

// Returns an instance of the IPv4 datagram transported as payload
ippacket* create_ippacket(ethernetframe *e) {
    if (e->ether_type(e) != et_IPv4) {
        exit(EXIT_FAILURE);
    }
    // ip packet bytes start after the ethernetframe header
    return new_ippacket(false, e->data(e), e->length(e) - e->header_length(e));
}

// Returna an instance of APR packet 
arppacket* create_arppacket(ethernetframe *e) {
    if (e->ether_type(e) != et_ARP) { // make sure it transport ARP protocol 
        exit(EXIT_FAILURE);
    }
    return new_arppacket(false, e->data(e), e->length(e) - e->header_length(e));
}

ethernetframe* new_ethernetframe(bool owned, unsigned char *p_data, unsigned int p_len) {
    ethernetframe *e = malloc(sizeof(ethernetframe));
    e->p_len = p_len;
    e->owned = owned;
    e->print_ethernetframe = print_ethernetframe;
    e->destination_mac = destination_mac;
    e->source_mac = source_mac;
    e->ether_code = ether_code;
    e->ether_type = ether_type;
    e->length = length;
    e->header_length = header_length;
    e->data = data;
    e->pcp_8021q = pcp_8021q;
    e->dei_8021q = dei_8021q;
    e->vid_8021q = vid_8021q;
    e->create_ippacket = create_ippacket;
    e->create_arppacket = create_arppacket;
    if (e->owned) { // copy data into a new block
        memcpy(e->p_data, p_data, p_len);
    } else {
        e->p_data = p_data;
    }
    return e;
}

