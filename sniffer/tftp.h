#ifndef _TFTP_H
#define _TFTP_H 

#include <stdbool.h>

typedef struct tftpmessage_ tftpmessage;

typedef enum tftpoperation_ {
    tftp_wrq, tftp_rrq, tftp_data, tftp_ack, tftp_error, tftp_none
} tftpoperation;

struct tftpmessage_ {
    bool owned;
    unsigned char *p_data;
    unsigned int p_len;
    unsigned int (*header_length)(tftpmessage *self);  // length of TFTP message header in bytes
    tftpoperation (*operation)(tftpmessage *self);     // operation code
    char* (*filename)(tftpmessage *self);              // filename field in RRQ and WRQ datagrams
    char* (*mode)(tftpmessage *self);                  // mode field in RRQ and WRQ message
    unsigned int (*error_code)(tftpmessage *self);     // error code in ERROR message
    char* (*error_msg)(tftpmessage *self);             // error message in ERROR message
    unsigned int (*block)(tftpmessage *self);          // block number in DATA message
    unsigned int (*data_length)(tftpmessage *self);    // bytes of data in DATA message
    void (*print_tftpmessage)(tftpmessage *self);      // print the TFTP message
};

tftpmessage* new_tftpmessage(bool owned, unsigned char *p_data,  unsigned int p_len); 

#endif 
