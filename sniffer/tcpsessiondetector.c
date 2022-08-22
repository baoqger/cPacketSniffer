#include <stdlib.h>
#include <stdio.h>
#include "tcpsessiondetector.h"
#include "tcpsegment.h"
#include "ippacket.h"
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


