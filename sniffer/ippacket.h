#ifndef _IPPACKET_H
#define _IPPACKET_H

#include <stdbool.h>

typedef struct ippacket_ ippacket;

struct ippacket_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    void (*print_ippacket)(ippacket *self);
    unsigned int(*version)(ippacket *self);
    unsigned int(*ip_header_length)(ippacket *self);
    unsigned int(*ihl)(ippacket *self);
    unsigned int(*tos)(ippacket *self);
    unsigned int(*total_length)(ippacket *self);
    unsigned int(*fragment_id)(ippacket *self);
    unsigned int(*fragment_flags)(ippacket *self);
    unsigned int(*fragment_pos)(ippacket *self);
};

ippacket* new_ippacket(bool owned, unsigned char *p_data, unsigned int p_len);

#endif