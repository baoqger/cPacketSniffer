#ifndef _DATAGRAM_H
#define _DATAGRAM_H

// the benifit of declaring a new type using typedef?
struct datagram {
    unsigned char *p_data;
    unsigned int p_len;
};

void print_datagram(const struct datagram *d);

#endif