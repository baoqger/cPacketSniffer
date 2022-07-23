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

// Indicates the hardware layer type
ARPHardwareType hardware_type(arppacket *a) {   
    switch(a->hardware_type_code(a)) {
        case 0x0001: return aht_Ethernet;
        case 0x000F: return aht_FrameRelay;
        case 0x0010:
        case 0x0013:
        case 0x0015: return aht_ATM;
        case 0x001F: return aht_IPSec;
        default    : return aht_unknown;
    }
}

// Indicates the hardware layer type code
unsigned int hardware_type_code(arppacket *a) {
    if(a->p_data) {
        return char2word(a->p_data + 0); // hardware layer type stored in two bytes
    } else {
        return 0;
    }
}

// Return hardware address length in bytes
unsigned int hardware_adr_length(arppacket *a) {
    if (a->p_data) {
        return a->p_data[4];
    } else {
        return 0;
    }
}

// Return protocol addresses length in bytes 
unsigned int protocol_adr_length(arppacket *a) {
    if (a->p_data) {
        return a->p_data[5];
    } else {
        return 0;
    }
}

// Returns the destination hardware address field's content
static macaddress* destination_mac(arppacket *a) {
    if(a->hardware_type(a) == aht_Ethernet) {
        return new_macaddress(false, a->p_data + 8 + a->hardware_adr_length(a) + a->protocol_adr_length(a)); 
    } else {
       fprintf(stderr, "Hardware layer is not Ethernet based.");
       exit(EXIT_FAILURE);
    }
}

// Returns the source hardware address field's content
static macaddress* source_mac(arppacket *a) {
    if(a->hardware_type(a) == aht_Ethernet) {
        return new_macaddress(false, a->p_data + 8);
    } else {
        fprintf(stderr, "Hardware layer is not Ethernet based.");
        exit(EXIT_FAILURE);
    }
}

// Return the destination protocol address field's content
static ipaddress* destination_ip(arppacket *a) {
    if(a->protocol_type(a) == apt_IPv4) {
        return new_ipaddress(false, a->p_data + 8 + a->hardware_adr_length(a) * 2 + a->protocol_adr_length(a));
    } else {
        fprintf(stderr, "Protocol layer is not IPv4 bsaed.");
        exit(EXIT_FAILURE);
    }
} 


// Return the source protocol address field's content
static ipaddress* source_ip(arppacket *a) {
    if(a->protocol_type(a) == apt_IPv4) {
        return new_ipaddress(false, a->p_data + 8 + a->hardware_adr_length(a));
    } else {
        fprintf(stderr, "Protocol layer is not IPv4 based.");
        exit(EXIT_FAILURE);
    }
}
// Indicates the protocol layer type
ARPProtocolType protocol_type(arppacket *a) {
    switch(a->protocol_type_code(a)) {
        case 0x0800: return apt_IPv4;
        case 0x8037: return apt_IPX;
        case 0x8100: return apt_802_1Q;
        case 0x86DD: return apt_IPv6;
        default    : return apt_unknown;
    }
}

// Indicates the protocol layer type
unsigned int protocol_type_code(arppacket *a) {
    if(a->p_data) {
        return char2word(a->p_data + 2);
    } else {
        return 0;
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
        // Display hardware address
        macaddress *d = a->destination_mac(a),
                   *s = a->source_mac(a);
        printf("Destination MAC address: ");
        d->print_macaddress(d);
        printf("Source MAC address: ");
        s->print_macaddress(s);

        // Display protocol addresses
        ipaddress *di = a->destination_ip(a),
                  *si = a->source_ip(a);
        printf("Destination IP address: ");
        di->print_ipaddress(di);
        printf("Source IP address: ");
        si->print_ipaddress(si);
        
        // Get hardware type
        sprintf(outstr, "0x%.4x", a->hardware_type_code(a));
        
        // Display hardware type textually along its corresponding code

        printf("hardware type = ");
        switch(a->hardware_type(a)) {
            case aht_Ethernet:   printf("Ethernet [%s]\n", outstr);
            case aht_FrameRelay: printf("Frame Relay [%s]\n", outstr);
            case aht_ATM       : printf("Asynchronous Transmission Mode {ATM} [%s]\n", outstr);
            case aht_IPSec     : printf("IPSec tunnel [%s]\n", outstr);
            default            : printf("unknown [%s]\n", outstr);  
        }

        // Get protocol type
        sprintf(outstr, "0x%.4x", a->protocol_type_code(a));
        
        // Display protocol type textually along its corresponding code
        printf("protocol type = ");

        switch(a->protocol_type(a)) {
            case apt_IPv4:   printf("IPv4 [%s]\n", outstr);
            case apt_IPX:    printf("IPX [%s]\n", outstr);
            case apt_802_1Q: printf("IEEE 802.1Q [%s]\n", outstr);
            case apt_IPv6:   printf("IPv6 [%s]\n", outstr);
            default:         printf("unknown [%s]\n", outstr);
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
    a->protocol_type = protocol_type;
    a->protocol_type_code = protocol_type_code;
    a->hardware_type = hardware_type;
    a->hardware_type_code = hardware_type_code;
    a->destination_mac = destination_mac;
    a->source_mac = source_mac;
    a->destination_ip = destination_ip;
    a->source_ip = source_ip;
    a->hardware_adr_length = hardware_adr_length;
    a->protocol_adr_length = protocol_adr_length;
    if(a->owned) { // copy data into a new block
        memcpy(a->p_data, p_data, p_len);
    } else {
        a->p_data = p_data;
    }
    return a;
}

