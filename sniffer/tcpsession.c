#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include "tcpsession.h" 
#include "tcpsegment.h"

struct tcpsession_ {
    char sourceId[25];      // key identifying source host: source ip address + source port
    char destinationId[25]; // key identifying destination host: destination ip address + destination port
    unsigned int state;  // current session state
    unsigned int bytes;  // count of data bytes exchanged in session
    unsigned int (*trackState)(tcpsegment*, char*, char*, bool, tcpsession);  // TCP session manager
    unsigned int (*getState)(tcpsession);  // access to state attribute
    unsigned int (*getBytes)(tcpsession);  // access to bytes attribute
    bool (*terminated)(tcpsession);        // tells if session terminated
};


// Returns value of attribute state
unsigned int getState(tcpsession t) {
    return t->state;
}

// Returns value of attribute bytes
unsigned int getBytes(tcpsession t) {
    return t->bytes;
}


// Returns true if state machine has reached final state 
bool terminated(tcpsession t) {
    return t->getState(t) == 10;
}

// Machine state processing: transit from one state to next according to given IP packet (which must have a TCP segment as payload)
unsigned int trackState(tcpsegment *tcp, char* source_id, char* destination_id, bool debug, tcpsession t) {
    // Make sure the datagram is part of the session
    bool considerDatagram = ((strcmp(t->sourceId, source_id) == 0) && (strcmp(t->destinationId, destination_id) == 0)) ||
        ((strcmp(t->sourceId, destination_id) == 0) && (strcmp(t->destinationId, destination_id) == 0));
    if (!considerDatagram) return false;
    
    // Determine segment direction according to the host that initiated the connection
    bool forward = (strcmp(t->sourceId, source_id) == 0);
    bool backward = !forward;

 
    // Apply state machine according to segment
    switch(t->getState(t)) {
        case 0:  // session closed
            // The segment must be SYN from source
            if (tcp->flag_syn(tcp) && !tcp->flag_ack(tcp) && forward) {
                t->bytes = 0;  // reset data bytes count 
                t->state = 1;  // waiting for syn+ack destination

                if (debug) {   // display debug info on transition
                    printf("%s >>>>> SYN >>>>> %s (open request)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 1:  // source transmitted a SYN asking to connect
            // The segment must be SYN+ACK from destination
            if (tcp->flag_syn(tcp) && tcp->flag_ack(tcp) && backward) {
                t->state = 2;  // waiting for ACK from source to complete connection
                if (debug) {
                    printf("%s <<<<< SYN+ACK <<<<< %s (half opened)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 2:  // destination sent SYN+ACK accepting connection
            // The segment must be ACK from source
            if (!tcp->flag_syn(tcp) && tcp->flag_ack(tcp) && forward) {
                t->state = 3;  // waiting for FIN from source or destination
                if (debug) {
                    printf("%s >>>>> ACK >>>>> %s (opened)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 3: // connetion established
            // The segment must be FIN in either direction
            if(tcp->flag_fin(tcp)) {
                if(forward) { // source initiates termination
                    t->state = 4; // waiting an ACK or FIN+ACK from destination
                    if (debug) {
                        printf("%s >>>>> FIN >>>>> %s (close request)\n", t->sourceId, t->destinationId);
                    }
                } else { // destination initiate termination
                    t->state = 7; // waiting an ACK or FIN+ACK from source
                    if (debug) {
                        printf("%s <<<<< FIN <<<<< %s (close request)\n", t->sourceId, t->destinationId);
                    }
                }
            }
            break;
        case 4: // destination having received FIN from source
            // The segment should be ACK or FIN+ACK from destination
            if (!tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && backward) {
                t->state = 5; // waiting for FIN from destination
                if (debug) {  // display debug info transition
                    printf("%s <<<<< ACK <<<<< %s (half closed)\n", t->sourceId, t->destinationId);
                }
            } else if(tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && backward) {
                t->state = 6; // waiting for ACK from source
                if(debug) {
                    printf("%s <<<<< FIN+ACK <<<<< %s (half closed)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 5: // source having received ACK in response to its FIN
            // The segment must be FIN from destination
            if(tcp->flag_fin(tcp) && backward) {
                t->state = 6; // waiting for ACK from source to complete termination
                if (debug) {
                    printf("%s <<<<< FIN <<<<< %s (reverse close request)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 6: // soruce having received FIN or FIN+ACK from destination
            // The segment must be ACK from soruce
            if (!tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && forward) {
                t->state = 10; // session closed
                if (debug) {
                    printf("%s >>>>> ACK >>>>> %s (closed)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 7: // source having received FIN from destination
            // The segment should be ACK or FIN+ACK from source
            if (!tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && forward) {
                t->state = 8; // waiting for FIN from source
                if (debug) {
                    printf("%s >>>>> ACK >>>>> %s (half closed)\n", t->sourceId, t->destinationId);
                }
            } else if(tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && forward) {
                t->state = 9; // waiting for ACK from destination
                if (debug) {
                    printf("%s >>>>> FIN+ACK >>>>> %s (half closed)\n", t->sourceId, t->destinationId);
                }
            }
            break;

        case 8: // destination having received ACK in response to its FIN
            // The segment must be FIN from source
            if (tcp->flag_fin(tcp) && forward) {
                t->state = 9; // waiting for ACK from destination to complete termination
                if (debug) {
                    printf("%s >>>>> FIN >>>>> %s (reverse close request)\n", t->sourceId, t->destinationId);
                }
            }
            break;
        case 9: // destination having received FIN or FIN+ACK from source
            // The segment must be ACK from destination
            if (!tcp->flag_fin(tcp) && tcp->flag_ack(tcp) && backward) {
                t->state = 10; // session closed
                if(debug) {
                    printf("%s <<<<< ACK <<<<< %s (closed)\n", t->sourceId, t->destinationId);
                } 
            }
            break;

    }
    // if connection established, update data bytes counter
    if (t->getState(t) == 3) {
        t->bytes += tcp->length(tcp) - tcp->header_length(tcp);
    }
    return 0;
}

tcpsession new_tcpsession(char *source_id, char *destination_id) {
    tcpsession t = malloc(sizeof(struct tcpsession_));
    t->bytes = 0;    // no data exchanged yet
    t->state = 0;    // initial state
    strcpy(t->sourceId, source_id);
    strcpy(t->destinationId, destination_id);
    t->getState = getState;
    t->getBytes = getBytes;
    t->terminated = terminated;
    t->trackState = trackState;
    return t;
}

