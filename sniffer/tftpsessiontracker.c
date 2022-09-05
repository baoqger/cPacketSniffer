#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "tftpsessiontracker.h"
#include "ipaddress.h"
#include "udpsegment.h"
#include "tcpsessiontracker.h"
#include "tftp.h"

// process udp segment, update the tftp session transported payload size
void process_tftpmessage(ippacket *i,char* tftpserver, tftpsessiontracker tracker) {
    char *source_id = source_ip_port(i); // source id(ip:port)
    char *destination_id = destination_ip_port(i); // destination id(ip:port)
    udpsegment *udp = i->create_udpsegment(i);
    // Is it a new TFTP connection request to the supervised server?
    // The new connection can be identified by the destination port number: 69 and destination ip address
    if (udp->destination_port(udp) == 69 && !strcmp(tftpserver, get_ipaddress(i->destination_ip(i)))) {
       // Initialize data counter for new client
       put(source_id, (void*)0, tracker->tftpSessions); // 0 bytes are transported for new TFTP session
    }
    // Is the source or destination a TFTP session being tracked? 
    // We must check in both directions since the client may be reading from or writing to the server
    char *session_id = NULL;
    int session_data_size;
    if (keyExist(source_id, tracker->tftpSessions)) {
        session_data_size = (size_t)retrieve(source_id, tracker->tftpSessions);
        session_id = source_id;
    } else if (keyExist(destination_id, tracker->tftpSessions)) {
        session_data_size = (size_t)retrieve(destination_id, tracker->tftpSessions);
        session_id = destination_id; 
    } else {
        return;
    }
    // If it's a TFTP session being tracked, display the TFTP message and update traffic info
    if (session_id != NULL) {
        tftpmessage *tftp = udp->create_tftpmessage(udp); 
        printf("-- tftp message -- \n");
        tftp->print_tftpmessage(tftp); 
    }
}


// create a new tftpsessiontracker instance
tftpsessiontracker new_tftpsessiontracker() {
    tftpsessiontracker tracker = malloc(sizeof(struct tftpsessiontracker_));
    tracker->tftpSessions = initializeTable(10);
    tracker->process_tftpmessage = process_tftpmessage;
    return tracker;
}

void newTFTPSessionTracker(tftpsessiontracker *tracker) {
    if(*tracker == NULL) {
        *tracker = new_tftpsessiontracker();
    }
}
