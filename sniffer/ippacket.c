#include <stdlib.h>
#include <string.h>
#include "ippacket.h"

ippacket* new_ippacket(bool owned, unsigned char *p_data, unsigned int p_len) {
    ippacket *i = malloc(sizeof(ippacket));
    i->p_len = p_len;
    i->owned = owned;
    if (i->owned) { // copy data into a new block
        memcpy(i->p_data, p_data, p_len); 
    } else {
        i->p_data = p_data;
    }
    return i;
}