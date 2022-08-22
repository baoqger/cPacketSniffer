#ifndef _TCP_SESSION_DETECTOR_H
#define _TCP_SESSION_DETECTOR_H 

#include "generic-dict.h"

typedef struct tcpsessiondetector_ *tcpsessiondetector;


struct tcpsessiondetector_ {
    HashTable tcpSessions;
    void (*process_tcpsegment)();
};

void newTCPSessionDetector(tcpsessiondetector*);
tcpsessiondetector new_tcpsessiondetector();

#endif 
