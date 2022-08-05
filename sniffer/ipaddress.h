#ifndef _IPADDRESS_H
#define _IPADDRESS_H

#include <stdbool.h>
// #include "icmppacket.h"

#define IPADR_LEN 4;

typedef struct ipaddress_ ipaddress;

struct ipaddress_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_int;
    void (*print_ipaddress)(ipaddress *i);
    // icmppacket* (*create_icmppacket)(ipaddress *i);
    };

ipaddress* new_ipaddress(bool owned, unsigned char *p_data);
char* get_ipaddress(ipaddress *i);

#endif
