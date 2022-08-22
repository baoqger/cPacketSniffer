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

