#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ethernetframe.h"
#include "utils.h"

macaddress* destination_mac(ethernetframe* e) {
    return new_macaddress(false, e->p_data);
}

macaddress* source_mac(ethernetframe* e) {
    return new_macaddress(false, (e->p_data + 6)); // replace 6 with MAC_LEN macro;
}

// Extracts from Ethernet header what protocol this transports in its data
unsigned int ether_code(ethernetframe* e) {
    if (e->p_data) {
        return char2word(e->p_data + 12);
    } else {
        return 0;
    }
}

// Returns an enum value corresponding to what this transports. Only the most frequent 
// layer two protocols arew listed - there are more than one hundred of them in reality!
etherType ether_type(ethernetframe* e) {
    if(e->ether_code(e) <= 0x05DC) {
        return et_Length;
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

void print_ethernetframe(ethernetframe* e) {
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

    }
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
    if (e->owned) { // copy data into a new block
        memcpy(e->p_data, p_data, p_len);
    } else {
        e->p_data = p_data;
    }
    return e;
}