#ifndef _MACADDRESS_H
#define _MACADDRESS_H

#include <stdbool.h>
#include "macaddress.h"

#define MAC_LEN 6;  // length of MAC address in bytes

typedef struct macaddress_ macaddress;

struct macaddress_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    unsigned char* (*print_macaddress)(macaddress *self);
    unsigned int (*length)(macaddress *self);
};

macaddress* new_macaddress(bool owned, unsigned char *p_data); // macaddress length is fixed to 6 bytes

#endif