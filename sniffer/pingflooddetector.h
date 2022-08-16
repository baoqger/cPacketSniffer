#ifndef _PINGFLOODDETECTION_H
#define _PINGFLOODDETECTION_H 

#include <stdbool.h>
#include "generic-dict.h"
#include "ipaddress.h"
#include "icmppacket.h"

typedef struct pingflooddetector_  *pingflooddetector;
typedef struct pingrequestdata_ *pingrequestdata;

struct pingflooddetector_ {
    HashTable pingFloods;
    bool (*process_ping)(ipaddress*, icmppacket*, pingflooddetector);
    
};
void newPingFloodDetector(pingflooddetector*);
pingflooddetector new_pingflooddetector();
pingrequestdata   new_pingrequestdata();

#endif 
