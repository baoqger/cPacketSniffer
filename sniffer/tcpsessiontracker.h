#ifndef _TCP_SESSION_TRACKER_H
#define _TCP_SESSION_TRACKER_H 

#include "ippacket.h"
#include "generic-dict.h"

typedef struct tcpsessiontracker_ *tcpsessiontracker;


struct tcpsessiontracker_ {
    HashTable tcpSessions;
    void (*process_tcpsegment)(ippacket*, tcpsessiontracker);
};

void newTCPSessionTracker(tcpsessiontracker*);
tcpsessiontracker new_tcpsessiontracker();
void destroy_tcpsessiontracker(tcpsessiontracker);

char* source_ip_port(ippacket*);
char* destination_ip_port(ippacket*);

#endif 
