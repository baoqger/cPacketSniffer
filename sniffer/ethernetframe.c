#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ethernetframe.h"

macaddress* destination_mac(ethernetframe* e) {
    return new_macaddress(false, e->p_data);
}

macaddress* source_mac(ethernetframe* e) {
    return new_macaddress(false, (e->p_data + 6)); // replace 6 with MAC_LEN macro;
}

void print_ethernetframe(ethernetframe* e) {
    if (e->p_data) {
        macaddress *d = e->destination_mac(e),
                   *s = e->source_mac(e);
        printf("destination MAC address = %s\n", d->print_macaddress(d));
        printf("source MAC address = %s\n", s->print_macaddress(s));
    }
}

ethernetframe* new_ethernetframe(bool owned, unsigned char *p_data, unsigned int p_len) {
    ethernetframe *e = malloc(sizeof(ethernetframe));
    e->p_len = p_len;
    e->owned = owned;
    e->print_ethernetframe = print_ethernetframe;
    e->destination_mac = destination_mac;
    e->source_mac = source_mac;
    if (e->owned) { // copy data into a new block
        memcpy(e->p_data, p_data, p_len);
    } else {
        e->p_data = p_data;
    }
    return e;
}