#ifndef _DATAGRAM_H
#define _DATAGRAM_H

typedef struct datagram_ datagram;

struct datagram_ {
    unsigned char *p_data;
    unsigned int p_len;
    void (*print_datagram)(datagram *self);
};

datagram* new_datagram(unsigned char *p_data, unsigned int p_len);

#endif