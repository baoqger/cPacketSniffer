#ifndef _TCP_SEGMENT_H
#define _TCP_SEGMENT_H 

#include <stdbool.h>

typedef struct tcpsegment_ tcpsegment;

struct tcpsegment_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    unsigned int (*header_length)(tcpsegment *self);
    unsigned int (*source_port)(tcpsegment *self);
    unsigned int (*destination_port)(tcpsegment *self);
    unsigned int (*sequence_nb)(tcpsegment *self);
    unsigned int (*ack_nb)(tcpsegment *self);
    unsigned int (*offset)(tcpsegment *self);
    unsigned int (*reserved)(tcpsegment *self);
    bool (*flag_ns)(tcpsegment *self);
    bool (*flag_cwr)(tcpsegment *self);
    bool (*flag_ece)(tcpsegment *self);
    bool (*flag_urg)(tcpsegment *self);
    bool (*flag_ack)(tcpsegment *self);
    bool (*flag_psh)(tcpsegment *self);
    bool (*flag_rst)(tcpsegment *slef);
    bool (*flag_syn)(tcpsegment *self);
    bool (*flag_fin)(tcpsegment *self);
    unsigned int (*window_size)(tcpsegment *self);
    unsigned int (*checksum)(tcpsegment *self);
    unsigned int (*pointer_urg)(tcpsegment *self);
    char* (*port_name)(unsigned int);
    void (*print_tcpsegment)(tcpsegment *self);
};

tcpsegment* new_tcpsegment(bool owned, unsigned char *p_data, unsigned int p_len);

#endif 
