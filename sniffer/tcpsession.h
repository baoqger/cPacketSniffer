#ifndef _TCP_SESSION_H
#define _TCP_SESSION_H 
#include "tcpsegment.h"

typedef struct tcpsession_ *tcpsession;

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



tcpsession new_tcpsession(char*, char*);

#endif 
