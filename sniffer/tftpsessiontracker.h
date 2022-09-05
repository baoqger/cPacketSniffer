#ifndef _TFTP_SESSION_TRACKER_H
#define _TFTP_SESSION_TRACKER_H 

#include "generic-dict.h"
#include "ippacket.h"

typedef struct tftpsessiontracker_ *tftpsessiontracker;

struct tftpsessiontracker_ {
    HashTable tftpSessions;
    void (*process_tftpmessage)(ippacket*, char*,tftpsessiontracker);
};

void newTFTPSessionTracker(tftpsessiontracker*);
tftpsessiontracker new_tftpsessiontracker();

#endif 
