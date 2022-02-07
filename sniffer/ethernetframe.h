#ifndef _ETHERNET_FRAME_H
#define _ETHERNET_FRAME_H

#include <stdbool.h>
#include "macaddress.h"

typedef struct ethernetframe_ ethernetframe;

struct ethernetframe_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    void (*print_ethernetframe)(ethernetframe *self);
    macaddress* (*destination_mac)(ethernetframe *self);
    macaddress* (*source_mac)(ethernetframe *self);
};

ethernetframe* new_ethernetframe(bool owned, unsigned char *p_data, unsigned int p_len);

#endif