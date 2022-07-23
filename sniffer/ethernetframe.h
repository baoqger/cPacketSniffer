#ifndef _ETHERNET_FRAME_H
#define _ETHERNET_FRAME_H

#include <stdbool.h>
#include "macaddress.h"
#include "ippacket.h"
#include "arppacket.h"

typedef struct ethernetframe_ ethernetframe;

typedef enum etherType_ {
    et_Length, et_DEC, et_XNS, et_IPv4, et_ARP, et_Domain, et_RARP, et_IPX, 
    et_AppleTalk, et_802_1Q, et_IPv6, et_loopback, et_other, et_none
} etherType;

struct ethernetframe_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    void (*print_ethernetframe)(ethernetframe *self);
    macaddress* (*destination_mac)(ethernetframe *self);
    macaddress* (*source_mac)(ethernetframe *self);
    unsigned int (*ether_code)(ethernetframe *self);
    etherType (*ether_type)(ethernetframe *self);
    unsigned int (*header_length)(ethernetframe *self);
    unsigned int (*length)(ethernetframe *self);
    unsigned char* (*data)(ethernetframe *self);
    unsigned int (*pcp_8021q)(ethernetframe *self);
    unsigned int (*dei_8021q)(ethernetframe *self); 
    unsigned int (*vid_8021q)(ethernetframe *self); 
    ippacket* (*create_ippacket)(ethernetframe *self);
    arppacket* (*create_arppacket)(ethernetframe *self);    
};

ethernetframe* new_ethernetframe(bool owned, unsigned char *p_data, unsigned int p_len);

#endif
