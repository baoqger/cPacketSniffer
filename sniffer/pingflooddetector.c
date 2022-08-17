#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include "pingflooddetector.h"

struct pingrequestdata_ {
    unsigned int count_ip;           // count of received pings
    unsigned long sum_delays;        // sum of delays between successive pings
    unsigned long time_last_arrival; // time of arrival of latest ping
};

// Process ping requests, return true if a ping flood is detected for the given target IP address
bool process_ping(ipaddress *target, icmppacket *icmp, pingflooddetector detector) {
    const int tol_delay = 200;    // if delay larger than this (in ms), it's not part of an attack
    const int tol_count = 100;       // minimum number of successive pings for an attack to be considered
    const int tol_size = 1024;    // minimum payload size (in bytes) for an attack to be considered

    // Make sure its' a ping request
    if (icmp->type(icmp) != 8 || icmp->code(icmp) != 0) {
        return false;
    }

    // Is the ping request large enough to be considered as part of an attack? 
    if (icmp->length(icmp) - icmp->header_length(icmp) < tol_size) {
        return false;
    }    

    // Get current time (in milliseconds since January 1, 1970) as time of packet arrival
    struct timeval t;
    gettimeofday(&t, 0);
    unsigned long time_arrival = t.tv_sec * 1000.0 + t.tv_usec / 1000.0;

    // convert target ipaddress into string to serve as key in the dictionary
    char *target_ip = get_ipaddress(target);

    // Is it the first ping for this target?
    if (!keyExist(target_ip, detector->pingFloods)) {
        // It's a new target ip so initialize ping data for it
        pingrequestdata d = new_pingrequestdata(0, 0, time_arrival);
        put(target_ip, (void*)d, detector->pingFloods);
        return false;
    }
    
    // Update ping data for this target ip
    pingrequestdata d = retrieve(target_ip, detector->pingFloods);
    d->count_ip         += 1;
    d->sum_delays       += time_arrival - d->time_last_arrival;
    d->time_last_arrival = time_arrival;
    printf("IP address %s ping %d times.\n", target_ip, d->count_ip);
    
    // compute the mean packet inter arrival time for this target
    double mean_time = 1.0 * d->sum_delays / d->count_ip;

    // Is it an attack? If so, delete data for target (to prevent consider the next
    // ping request as a new attack) and return true to flag the attack
    
    bool attack = (d->count_ip >= tol_count) && (mean_time < tol_delay); 

    if (attack) {
        removeKey(target_ip, detector->pingFloods);
    }

    return attack;
}


// create a new pingrequestdata instance
pingrequestdata new_pingrequestdata(unsigned int count, unsigned long sum_delays, unsigned long time_last_arrival) {
    pingrequestdata p = malloc(sizeof(struct pingrequestdata_));
    p->count_ip = count;
    p->sum_delays = sum_delays;
    p->time_last_arrival = time_last_arrival;
    return p;
}

void newPingFloodDetector(pingflooddetector *detector) {
    if (*detector == NULL) {
        *detector = new_pingflooddetector();
    }
}

// create a new pingflooddetector instance
pingflooddetector new_pingflooddetector() {
    pingflooddetector detector = malloc(sizeof(struct pingflooddetector_));
    detector->pingFloods = initializeTable(10);
    detector->process_ping = process_ping;
    return detector;
} 


