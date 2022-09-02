#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tftp.h" 
#include "utils.h"

// Returns the TFTP message header length in bytes
// TFTP message has 5 types, and the header length are various
// Only the first two bytes(opcode) is common
static unsigned int header_length(tftpmessage *t) {
        return 2;
}


// Returns TFTP message type according to the opcode field
tftpoperation operation(tftpmessage *t) {
    switch(char2word(t->p_data)) {
        case 1: return tftp_rrq;
        case 2: return tftp_wrq;
        case 3: return tftp_data;   
        case 4: return tftp_ack;
        case 5: return tftp_error;
        default: return tftp_none;
    }
}   


// Returns the ASCII mode transported by RRQ and WRQ message
char* mode(tftpmessage *t) {
    if(t->operation(t) == tftp_rrq || t->operation(t) == tftp_wrq) {
        return (char*)t->p_data + t->header_length(t) + strlen(t->filename(t)) + 1; // plus 1 byte for the delimitor
    } else {
        fprintf(stderr, "TFTP message does not contain mode field\n");
        exit(EXIT_FAILURE);
    }
} 


// Returns the filename transported by PRQ and WRQ message
char* filename(tftpmessage *t) {
    if(t->operation(t) == tftp_rrq || t->operation(t) == tftp_wrq) {
        return (char*)t->p_data + t->header_length(t);
    } else {
        fprintf(stderr, "TFTP message  does not contain file field\n");
        exit(EXIT_FAILURE);
    }
}

// Returns the error code contained in ERROR message
unsigned int error_code(tftpmessage *t) {
    if(t->operation(t) == tftp_error) {
        return char2word(t->p_data + t->header_length(t));
    } else {
        fprintf(stderr, "TFTP message does not contain error code field\n");
        exit(EXIT_FAILURE);
    } 
}

// Returns the error message contained in  ERROR message
char* error_msg(tftpmessage *t) {
    if(t->operation(t) == tftp_error) {
        return (char*)t->p_data + t->header_length(t) + 2; // plus 2 for the error number two bytes
    } else {
        fprintf(stderr, "TFTP message does not contain error code field\n");
        exit(EXIT_FAILURE);
    }
        
}

// Returns the block number transported in TFTP DATA and ACK message
unsigned int block(tftpmessage *t) {
    if(t->operation(t) == tftp_data || t->operation(t) == tftp_ack) {
        return char2word(t->p_data + t->header_length(t));
    } else {
        fprintf(stderr, "TFTP message does not contain block field\n");
        exit(EXIT_FAILURE);
    }
}

// Returns the size (in bytes) of data transported by TFTP  DATA message
unsigned int data_length(tftpmessage *t) {
    if (t->operation(t) == tftp_data) {
        return t->p_len - 4;
    } else {
        fprintf(stderr, "TFTP message does not contain data");
        exit(EXIT_FAILURE);
    }
}

void print_tftpmessage(tftpmessage *t) {
    if (t->p_data) {
        printf("operation = ");
        switch(t->operation(t)) {
            case tftp_rrq:   printf("READ \n");    break;
            case tftp_wrq:   printf("WRITE \n");   break;
            case tftp_data:  printf("DATA\n");     break;
            case tftp_ack:   printf("ACK \n");     break;
            case tftp_error: printf("ERROR \n");   break;
            default:         printf("Unknown \n"); break; 
        }
        // display the filename and mode field for READ and WRITE TFTP message
        if (t->operation(t) == tftp_rrq || t->operation(t) == tftp_wrq) {
            printf("filename = %s\n", t->filename(t));
            printf("mode = %s\n", t->mode(t));
        }
        // display the block number field for DATA and ACK TFTP message
        if (t->operation(t) == tftp_data || t->operation(t) == tftp_ack) {
            printf("block number = %d\n", t->block(t));
        }
        // display the data size for DATA TFTP message
        if (t->operation(t) == tftp_data) {
            printf("data size = %d\n", t->data_length(t));
        }
        // display the error info for ERROR TFTP message
        if (t->operation(t) == tftp_error) {
            printf("error code = %d\n", t->error_code(t));
            printf("error message = %s\n", t->error_msg(t));
        }
    }
   
}

// create a new tftp message instance
tftpmessage* new_tftpmessage(bool owned, unsigned char *p_data, unsigned int p_len) {
    tftpmessage *t = malloc(sizeof(tftpmessage));
    t->p_len = p_len;
    t->owned = owned;
    t->header_length = header_length;
    t->operation = operation;
    t->filename = filename;
    t->mode = mode;
    t->error_code = error_code;
    t->error_msg = error_msg;
    t->block = block;
    t->data_length = data_length;
    t->print_tftpmessage = print_tftpmessage;
    if(t->owned) { // copy the data into a new  block
        memcpy(t->p_data, p_data, p_len);
    } else {
        t->p_data = p_data;
    }
    return t;
}
