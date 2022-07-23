#ifndef _ARPPACKET_H
#define _ARPPACKET_H

#include <stdbool.h>
#include "macaddress.h"
#include "ipaddress.h"

typedef struct arppacket_ arppacket;

// Enumeration of hardware address types
typedef enum ARPHardwareType_ {
    aht_Ethernet, aht_FrameRelay, aht_ATM, aht_IPSec, aht_unknown 
} ARPHardwareType;

// Enumeration of protocol address types
typedef enum ARPProtocolType_ {
    apt_IPv4, apt_IPX, apt_802_1Q, apt_IPv6, apt_unknown 
} ARPProtocolType;

// Enumeration of ARP operations
typedef enum ARPPacketType_ {
    akt_ArpRequest, akt_ArpReply, akt_RarpRequest, akt_RarpReply, akt_unknown
} ARPPacketType;


struct arppacket_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    ARPPacketType (*operation)(arppacket *self);
    unsigned int (*operation_code)(arppacket *self);
    ARPProtocolType (*protocol_type)(arppacket *self);
    unsigned int (*protocol_type_code)(arppacket *self);
    ARPHardwareType (*hardware_type)(arppacket *self);
    unsigned int (*hardware_type_code)(arppacket *self);
    macaddress* (*destination_mac)(arppacket *self);
    macaddress* (*source_mac)(arppacket *self);
    ipaddress* (*destination_ip)(arppacket *self);
    ipaddress* (*source_ip)(arppacket *self);
    unsigned int (*hardware_adr_length)(arppacket *self);
    unsigned int (*protocol_adr_length)(arppacket *self);
    void (*print_arppacket)(arppacket *self);
};


arppacket* new_arppacket(bool owned, unsigned char *p_data, unsigned int p_len); 

#endif 
