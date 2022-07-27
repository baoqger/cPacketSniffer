#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "macaddress.h"



unsigned int macaddress_length(macaddress *m) {
    return m->p_len;
}

void print_macaddress(macaddress *m) {
    for (unsigned int i = 0; i < m->macaddress_length(m); i++) {
        printf("%.2x", m->p_data[i]);
        if (i < m->macaddress_length(m) - 1) {
            printf(".");
        }
    }
    printf("\n");
}

char* get_macaddress(macaddress *m) {
    char *mac = malloc(sizeof(char)*20);
    mac[0] = 0; // malloc doesn't initialize the memory. mac[0] = '\0' also works
    for (unsigned int n = 0; n < m->p_len; n++) {
        char s[3];
        sprintf(s, "%.2x", m->p_data[n]);
        strcat(mac, s);
        if (n < m->p_len - 1) {
            strcat(mac, ".");
        }
    }
    return mac;
}


macaddress* new_macaddress(bool owned, unsigned char *p_data) {
    macaddress *m = malloc(sizeof(macaddress));
    m->owned = owned;
    m->p_len = MAC_LEN;
    m->print_macaddress = print_macaddress;
    m->macaddress_length = macaddress_length;
    if (m->owned) { // copy data into a new block
        memcpy(m->p_data, p_data, m->p_len);
    } else {
        m->p_data = p_data;
    }
    return m;
}
