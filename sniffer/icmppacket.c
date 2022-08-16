#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include "utils.h"
#include "icmppacket.h"

jmp_buf env;


// Try-Catch-Throw macro
#define TRY if(setjmp(env) == 0)
#define CATCH else 
#define THROW longjmp(env, 1)

static unsigned int length(icmppacket *i) {
    return i->p_len;
}

// Returns the ICMP header length bytes
static unsigned int header_length(icmppacket *i) {
    if(!i->p_data) {
        return 0;
    } else {
        return 8;
    }
}

// Returns content of type header field
unsigned int type(icmppacket *i) {
    return i->p_data[0];
}

// Returns content of code header field
unsigned int code(icmppacket *i) {
    return i->p_data[1];
}



// Returns a textual description of the packet according to its type and code fields
char* description(icmppacket *i) {
    unsigned int msg_id = (i->type(i) << 8) + i->code(i);
    switch (msg_id) {
        case 0x0000 : return "echo reply";
        case 0x0300 : return "network unreachable";
        case 0x0301 : return "host unreachable";
        case 0x0302 : return "protocol unreachable";
        case 0x0303 : return "port unreachable";
        case 0x0304 : return "fragmentation needed and Don't Fragment flag set";
        case 0x0305 : return "source route failed";
        case 0x0306 : return "destination network unknown";
        case 0x0307 : return "destination host unknown";
        case 0x0308 : return "source host isolated";
        case 0x0309 : return "communication with destination network is administratively prohibited";
        case 0x030A : return "communication with destination host is administratively prohibited";
        case 0x030B : return "destination network unreachable for type of service";
        case 0x030C : return "destination host unreachable for type of service";
        case 0x030D : return "communication administratively prohibited ";
        case 0x030E : return "host precedence violation";
        case 0x030F : return "precedence cutoff in effect";
        case 0x0400 : return "source quench";
        case 0x0500 : return "redirect datagram for the network (or subnet)";
        case 0x0501 : return "redirect datagram for the host";
        case 0x0502 : return "redirect datagram for the type of service and network";
        case 0x0503 : return "redirect datagram for the type of service and host";
        case 0x0600 : return "alternate address for host";
        case 0x0800 : return "echo request";
        case 0x0900 : return "normal router advertisement";
        case 0x0910 : return "does not route common traffic";
        case 0x0A00 : return "router selection";
        case 0x0B00 : return "time to live exceeded in transit";
        case 0x0B01 : return "fragment reassembly time exceeded";
        case 0x0C00 : return "pointer indicates the error";
        case 0x0C01 : return "missing a required option";
        case 0x0C02 : return "bad length";
        case 0x0D00 : return "timestamp";
        case 0x0E00 : return "timestamp reply";
        case 0x0F00 : return "information request";
        case 0x1000 : return "information reply";
        case 0x1100 : return "address mask request";
        case 0x1200 : return "address mask reply";
        case 0x1300 : return "reserved (for security)";
        case 0x1E00 : return "traceroute";
        case 0x1F00 : return "datagram conversion error";
        default     : return "unknown ICMP packet";
  }    
}

// Returns content of checksum header field
static unsigned int checksum(icmppacket *i) {
    return char2word(i->p_data + 2);
}

// Returns content of identifier header field for type 13, 14, 17 or 18 ICMP packets
unsigned int identifier(icmppacket *i) {
    if (i->code(i) == 0 || (i->type(i) == 13 || i->type(i) == 14 || i->type(i) == 17 || i->type(i) == 18)) {
        return char2word(i->p_data + 4);
    } else {
        fprintf(stderr, "ICMP packet does not hold identifier field\n");
        // exit(EXIT_FAILURE);
        THROW;
    }
}

// Returns content of sequence number header field for 13, 14, 17 or 18 ICMP packets
unsigned int sequence_number(icmppacket *i) {
    if(i->code(i) == 0 || (i->type(i) == 13 || i->type(i) == 14 || i->type(i) == 17 || i->type(i) == 18)) {
        return char2word(i->p_data + 6);
    } else {
        fprintf(stderr, "ICMP packet does not hold sequence number field.\n");
        //exit(EXIT_FAILURE);
        THROW;
    }
}

// Returns content of next-hop MTU header field for type 3 ICMP packets
unsigned int next_hop_MTU(icmppacket *i) {
    if (i->type(i) == 3) {
        return char2word(i->p_data + 6);
    } else {
        fprintf(stderr, "ICMP packet does not hold next-hop MTU field.\n");
        //exit(EXIT_FAILURE);
        THROW;
    }
}

// Return content of originate timestamp header field for type 13 or 14 ICMP packets
unsigned int originate_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && (i->type(i) == 13 || i->type(i) == 14)) {
        return char4word(i->p_data + 8);
    } else {
        fprintf(stderr, "ICMP packet does not hold originate timestamp field.\n");
        // exit(EXIT_FAILURE);
        THROW;
    }
}   

// Returns content of receive timestamp header field for type 14 ICMP packets
unsigned int receive_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && i->type(i) == 14) {
        return char4word(i->p_data + 12);
    } else {
        fprintf(stderr, "ICMP packet does not hold receive timestamp field.\n");
        THROW;
    }
} 

// Returns content of transmit timestamp header field for type 14 ICMP packets 
unsigned int transmit_timestamp(icmppacket *i) {
    if(i->code(i) == 0 && i->type(i) == 14){
        return char4word(i->p_data + 16);
    } else {
        fprintf(stderr, "ICMP packet does not hold transmit timestamp field.\n");
        THROW;
    }
}

// Returns content of IP address header field for type 5 ICMP packets
ipaddress* ip_address(icmppacket *i) {
    if(i->type(i) == 5) {
        return new_ipaddress(false, i->p_data + 4);
    } else {
        fprintf(stderr, "ICMP packet does not hold IP address field.\n");
        THROW;
    }
} 

// Returns content of address mask header field for type 17 or 18 ICMP packets
ipaddress* address_mask(icmppacket *i) {
    if(i->code(i) == 0 && (i->type(i) == 17 || i->type(i) == 18)) {
        return new_ipaddress(false, i->p_data + 8);
    } else {
        fprintf(stderr, "ICMP packet does not hold address mask field.\n");
        THROW;
    }
}

// Displaying the ICMP packet header fields in human readable format
void print_icmppacket(icmppacket *i) {
    if(i->p_data) {
        char outstr[8];
        
        // Display common header fields
        printf("type/code = %d/%d (%s)\n", i->type(i), i->code(i), i->description(i));

        sprintf(outstr, "0x%.4x", i->checksum(i));
        printf("checksum = %s\n", outstr);

        // Display speciallized header fields which depend on type and code values
        // we catch any throw execptions
        
        // Display identifier and sequence number fields for packets of type 13, 14, 17 or 18
        TRY {
            unsigned int identif = i->identifier(i);
            unsigned int seqnum = i->sequence_number(i);

            sprintf(outstr, "0x%.4x", identif);
            printf("identifier = %s\n", outstr);
            printf("sequence number = %d\n", seqnum);
        } CATCH {
        }

        // Display next-hop MTU field for packets of type 3
        TRY {
            unsigned int nexthop = i->next_hop_MTU(i);
            printf("sequence number = %d\n", nexthop);
        } CATCH {
        }

        // Display IP address field for packets of type 5
        TRY {   
            ipaddress *addr = i->ip_address(i);
            printf("IP address = ");
            addr->print_ipaddress(addr);
        } CATCH {
        }
    }
}

icmppacket* new_icmppacket(bool owned, unsigned char *p_data, unsigned int p_len) {
    icmppacket *i = malloc(sizeof(icmppacket));
    i->p_len = p_len;
    i->owned = owned;
    i->length = length;
    i->header_length = header_length;
    i->type = type;
    i->code = code;
    i->checksum = checksum;
    i->identifier = identifier;
    i->sequence_number = sequence_number;
    i->next_hop_MTU = next_hop_MTU;
    i->originate_timestamp = originate_timestamp;
    i->receive_timestamp = receive_timestamp;
    i->transmit_timestamp = transmit_timestamp;
    i->ip_address = ip_address;
    i->description = description;
    i->print_icmppacket = print_icmppacket;
    if(i->owned) { // copy data into a new block
        memcpy(i->p_data, p_data, p_len);
    } else {
        i->p_data = p_data;
    }
    return i;
}
