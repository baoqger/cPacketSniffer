#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tcpsessiontracker.h"
#include "tcpsegment.h"
#include "tcpsession.h"
#include "ipaddress.h"

// get source id(ip:port)
char* source_ip_port(ippacket *i) {
    char *source_id = malloc(sizeof(char) * 25);
    tcpsegment *tcp = i->create_tcpsegment(i);
    sprintf(source_id, "%s:%d", get_ipaddress(i->source_ip(i)), tcp->source_port(tcp));
    return source_id;
}

// get destination id(ip:port)
char* destination_id_port(ippacket *i) {
    char *destination_id = malloc(sizeof(char) * 25);
    tcpsegment *tcp = i->create_tcpsegment(i);
    sprintf(destination_id, "%s:%d", get_ipaddress(i->destination_ip(i)), tcp->destination_port(tcp));
    return destination_id;
}

// process tcp segment, update the tcpsession state
void process_tcpsegment(ippacket *i, tcpsessiontracker tracker) {
    tcpsession t; 
    tcpsegment *tcp = i->create_tcpsegment(i);
    // compute keys to uniquely identify the session
    char *src = source_ip_port(i);
    char *dst = destination_id_port(i);

    // Is the segment part of a tracked session or not? We need to search
    // for two keys since segments within a TCP session travel in both directions
    char id_forward[50];
    id_forward[0] = 0;
    strcat(id_forward, src);
    strcat(id_forward, dst);
    char id_backward[50];
    id_backward[0] = 0;
    strcat(id_backward, dst);
    strcat(id_backward, src);
    char *session_id = NULL;

    if(keyExist(id_forward, tracker->tcpSessions)) {
        t = retrieve(id_forward, tracker->tcpSessions);  // retrieve session by id
        session_id = id_forward;
    } else if(keyExist(id_backward, tracker->tcpSessions)) {
        t = retrieve(id_backward, tracker->tcpSessions); // retrieve session by id
        session_id = id_backward;
    } else if(tcp->flag_syn(tcp) && !tcp->flag_ack(tcp)){ // start a new session
        t = new_tcpsession(src, dst); // create a new tcp session with source id and destination id
        put(id_forward, (void*)t, tracker->tcpSessions); // add the tcp session into the hashtable
        session_id = id_forward;
    }
    // Now we track the session to which is associated with the TCP segment
    if (t->getState(t) != t->trackState(tcp, src, dst, true ,t)) {
        // If the session has just been closed, display total number of bytes exchanged since we started tracking it and destroy it
        if (t->terminated(t)) {
            printf("Total data exchanged between %s and %s = %d bytes.\n", src, dst, t->getBytes(t));
            // Destroy TCP session tracker
            removeKey(session_id, tracker->tcpSessions);
        }
    }
}


// create a new tcpsessiontracker instance
tcpsessiontracker new_tcpsessiontracker() {
    tcpsessiontracker tracker = malloc(sizeof(struct tcpsessiontracker_));
    tracker->tcpSessions = initializeTable(10);
    tracker->process_tcpsegment = process_tcpsegment;
    return tracker;
}

void newTCPSessionTracker(tcpsessiontracker *tracker) {
    if(*tracker == NULL) {
        *tracker = new_tcpsessiontracker();
    }
} 

