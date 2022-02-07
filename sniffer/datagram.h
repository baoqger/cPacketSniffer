#ifndef _DATAGRAM_H
#define _DATAGRAM_H

#include "ethernetframe.h"

typedef struct datagram_ datagram;

struct datagram_ {
    unsigned char *p_data;
    unsigned int p_len;
    void (*print_datagram)(datagram *self);
    void (*free_datagram)(datagram *self);
    ethernetframe* (*create_ethernetframe)(datagram *self);
};

datagram* new_datagram(unsigned char *p_data, unsigned int p_len);


#endif