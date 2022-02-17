#ifndef _IPADDRESS_H
#define _IPADDRESS_H

#include <stdbool.h>

#define IPADR_LEN 4;

typedef struct ipaddress_ ipaddress;

struct ipaddress_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_int;
    void (*print_ipaddress)(ipaddress *i);
};

ipaddress* new_ipaddress(bool owned, unsigned char *p_data);

#endif