#ifndef _UDP_SEGMENT_H
#define _UDP_SEGMENT_H 

#include <stdbool.h>

typedef struct udpsegment_ udpsegment;

struct udpsegment_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    unsigned int (*header_length)(udpsegment *self);
    unsigned int (*source_port)(udpsegment *self);
    unsigned int (*destination_port)(udpsegment *self);
    unsigned int (*len)(udpsegment *self);
    unsigned int (*checksum)(udpsegment *self);
    char* (*port_name)(unsigned int);
    void (*print_udpsegment)(udpsegment *self);
};


udpsegment* new_udpsegment(bool owned, unsigned char *p_data, unsigned int p_len);

#endif 
