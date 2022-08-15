#ifndef _PINGFLOODDETECTION_H
#define _PINGFLOODDETECTION_H 

#include <stdbool.h>
#include "generic-dict.h"

typedef struct pingflooddetector_  pingflooddetector;

struct pingflooddetector_ {
    HashTable pingFloods;
    bool (*process_ping)(pingflooddetector* self);
};

pingflooddetector* new_pingflooddetector(); 

#endif 
