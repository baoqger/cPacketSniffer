#include <stdio.h>
#include <stdlib.h>
#include "datagram.h"


void print_datagram(datagram *d) {
    int LEN = 16; // number of bytes to display er line
    char outstr[8],     // for output formatting purposes
         ascii[LEN];    // holds textual bytes for a line

    // display all bytes in hexadecimal and textual forms
    for (unsigned int i = 0; i < d->p_len; i++) {
        if (i%LEN == 0) {
            // before moving to the next line, display accumulated bytes in character form
            if (i > 0) {
                printf("    ");
                for (int j = 0; j < LEN; j++) {
                    printf("%c", ascii[j]);
                }
            }
            // change line and display memory position of next byte in datagram
            printf("\n%.4d", i);
        }

        // display byte in hexadecimal
        printf("%.2x ", (unsigned char)d->p_data[i]);

        // format byte for textual form
        ascii[i%LEN] = ((d->p_data[i] >= 32 && d->p_data[i] <= 126) ? d->p_data[i] : '.');
    }

    // Display last line of bytes in textual form
    for (int i = LEN - d->p_len % LEN; i > 0; i--) {
        printf("   "); // print three spaces
    }
    printf("    "); // print a tab
    for (unsigned int j = 0; j < d->p_len % LEN; j++) {
        printf("%c", ascii[j]);
    }
    printf("\n");
}

void free_datagram(datagram *d) {
    free(d);
}


ethernetframe* create_ethernetframe(datagram *d) {
    return new_ethernetframe(false, d->p_data, d->p_len);
}


datagram* new_datagram(unsigned char *p_data, unsigned int p_len) {
    datagram *d = malloc(sizeof(datagram));
    d->p_data = p_data;
    d->p_len = p_len;
    d->print_datagram = print_datagram;
    d->free_datagram = free_datagram;
    d->create_ethernetframe = create_ethernetframe;
    return d;
}

