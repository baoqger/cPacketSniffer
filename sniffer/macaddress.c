#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "macaddress.h"



unsigned int length(macaddress *m) {
    return m->p_len;
}

// Output operator displaying the MAC address in dot form (XX.XX.XX.XX.XX.XX)
unsigned char* print_macaddress(macaddress *m) {
    unsigned char macaddress[18];
    for (unsigned int i = 0; i < m->length(m); i++) {
        sprintf(macaddress + strlen(macaddress), "%.2x", m->p_data[i]);
        if (i < m->length(m) - 1) {
            sprintf(macaddress + strlen(macaddress), ".");
        }
    }
    return macaddress; 
}




macaddress* new_macaddress(bool owned, unsigned char *p_data) {
    macaddress *m = malloc(sizeof(macaddress));
    m->owned = owned;
    m->p_len = MAC_LEN;
    m->print_macaddress = print_macaddress;
    m->length = length;
    if (m->owned) { // copy data into a new block
        memcpy(m->p_data, p_data, m->p_len);
    } else {
        m->p_data = p_data;
    }
    return m;
}