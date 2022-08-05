#ifndef _ICMPPACKET_H 
#define _ICMPPACKET_H 

#include <stdbool.h>
#include "ipaddress.h"

typedef struct icmppacket_ icmppacket; 

struct icmppacket_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    unsigned int (*header_length)(icmppacket*);
    char* (*description)(icmppacket*);
    unsigned int (*type)(icmppacket*);
    unsigned int (*code)(icmppacket*);
    unsigned int (*checksum)(icmppacket*);
    unsigned int (*identifier)(icmppacket*);
    unsigned int (*sequence_number)(icmppacket*);
    unsigned int (*next_hop_MTU)(icmppacket*);
    unsigned int (*originate_timestamp)(icmppacket*);
    unsigned int (*receive_timestamp)(icmppacket*);
    unsigned int (*transmit_timestamp)(icmppacket*);
    ipaddress* (*ip_address)(icmppacket*);
    ipaddress* (*address_mask)(icmppacket*);
    void (*print_icmppacket)(icmppacket*);
}; 

icmppacket* new_icmppacket(bool owned, unsigned char *p_data, unsigned int p_len);

#endif 
