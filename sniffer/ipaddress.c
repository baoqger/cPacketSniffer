#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ipaddress.h"

// print operator displaying the IP address in dot form  (X.X.X.X)
void print_ipaddress(ipaddress *i) {
    for (unsigned int n = 0; n < i->p_int; n++) {
        printf("%d", i->p_data[n]);
        if (n < i->p_int - 1) printf(".");
    }
    printf("\n"); 
}

ipaddress* new_ipaddress(bool owned, unsigned char *p_data) {
    ipaddress *i = malloc(sizeof(ipaddress));
    i->p_int = IPADR_LEN;
    i->owned = owned;
    i->print_ipaddress = print_ipaddress;
    if (i->owned) {
        memcpy(i->p_data, p_data, i->p_int);
    } else {
        i->p_data = p_data;
    }
    return i;
}