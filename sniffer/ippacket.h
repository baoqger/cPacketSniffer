#ifndef _IPPACKET_H
#define _IPPACKET_H

#include <stdbool.h>

typedef struct ippacket_ ippacket;

struct ippacket_ {
    bool owned;
    unsigned char* p_data;
    unsigned int p_len;
};

ippacket* new_ippacket(bool owned, unsigned char *p_data, unsigned int p_len);

#endif