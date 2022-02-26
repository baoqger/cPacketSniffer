#include <stdio.h>
#include <string.h> // memset
#include <stdlib.h> // exit
#include <unistd.h> // getopt
#include <signal.h> // Ctrl+C handling
#include <arpa/inet.h> // struct in_addr
#include <time.h> // ctime
#include <pcap.h> // libpcap
#include <stdbool.h> // bool
#include "datagram.h"
#include "ethernetframe.h"
#include "ippacket.h"

pcap_t *pcap_session = NULL; // libpcap session handle
char *strfilter = NULL; // textual BPF filter
struct bpf_program binfilter; // compiled BPF filter program

bool show_raw = false; // deactivate raw display of data captured

// Function releasing all resources before ending program execution
static void shutdown_sniffer(int error_code) {
    // Destroy compiled BPF filter if need
    if (strfilter != NULL) {
        pcap_freecode(&binfilter);
    }
    // close libpcap session
    if (pcap_session != NULL) {
        pcap_close(pcap_session);
    }
    exit(error_code);
}

// ctrl+c interrupt hanlder
void bypass_sigint(int sig_no) {
    printf("**\nCapture process interrupted by user...\n");
    if (pcap_session != NULL) {
        pcap_close(pcap_session);
    }
    exit(0); // we're done
}

// callback given to pcap_loop() fro processing captural datagrams
void process_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    printf("Grabbed %d bytes (%d%%) of datagram received on %s", 
        h->caplen, 
        (int)(100.0 * h->caplen / h->len), 
        ctime((const time_t*)&h->ts.tv_sec)
    );
    // create datagram instance
    datagram *d = new_datagram(packet, h->caplen);
    if (show_raw) {
        d->print_datagram(d);
    }
    // create ethernetframe instance
    ethernetframe *e = d->create_ethernetframe(d);
    printf("---------- Ethernet frame header ----------\n");
    e->print_ethernetframe(e);
    // Display payload content according to EtherType
    switch(e->ether_type(e)) {
        case et_IPv4: {
            // create ippacket instance
            ippacket *i = e->create_ippacket(e);
            printf("-------- IP packet header --------\n");
            i->print_ippacket(i);
        }
    } 


}


int main(int argc, char *argv[]) {
    char *device = NULL;  // device to sniff
    char argch;           // to manage command line arguments
    char errbuf[PCAP_ERRBUF_SIZE];        // to handle libpcap error message
    int  siz = 1518,    // max number of bytes captured for each datagram
         promisc = 0,    // deactive promiscuous mode?? promiscuous mode??
         cnt = -1;       // capture indefinitely

    // install ctrl+c handle
    struct sigaction sa, osa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler  = &bypass_sigint;
    sigaction(SIGINT, &sa, &osa);

    while((argch = getopt(argc, argv, "hprd:f:n:")) != EOF) {
        switch(argch) {
            case 'd': // device name
                device = optarg;
                break;
            case 'f': // BPF filter
                strfilter = optarg;
                break;

            case 'h':
                printf("Usage: sniff [-d XXX -h]\n");
                printf("-d XXX: device to capture from, where XXX is device name (ex: eth0).\n");
                printf("-f 'filter' : filter captures according to BPF expression (ex: 'ip or arp'). \n");
                printf("-h : show this information.\n");
                printf("-n : number of datagrams to capture.\n");
                printf("-p : active promiscuous capture mode.\n");
                printf("-r : active raw display of captured data.\n");
                if (argc == 2) return 0;
                break;
            case 'n': // number of datagrams to capture
                cnt = atoi(optarg);
                break;
            case 'p':
                promisc = 1;
                break;
            case 'r': // active raw display of captured data
                show_raw = 1;
                break;

        }
    }

    // identify device to use
    if (device == NULL && (device = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "error - %s", errbuf);
        return -2;
    } else {
        printf("device = %s %s\n", device, promisc ? " (promiscuous)": "");
    }

    // extract IP informaiton for network connected to device
    bpf_u_int32 netp,   // ip address of network
                maskp;  // network mask
    if ((pcap_lookupnet(device, &netp, &maskp, errbuf)) == -1) {
        fprintf(stderr, "error - %s\n", errbuf);
        return -3;
    }

    // translate ip address into textual form for display
    struct in_addr addr;
    char *net;
    addr.s_addr = netp;
    if ((net = inet_ntoa(addr)) == NULL) {
        fprintf(stderr, "error - inet_ntoa() failed");
    } else {
        printf("network ip = %s\n", net);
    }

    // Translate network mask int textual for for display
    char *mask;
    addr.s_addr = maskp;
    if ((mask = inet_ntoa(addr)) == NULL) {
        fprintf(stderr, "error - inet_ntoa() failed\n");
    } else {
        printf("network mask = %s\n", mask);
    }

    // Open a libpcap capture session
    pcap_session = pcap_open_live(device, siz, promisc, 1000, errbuf);
    
    if (pcap_session == NULL) {
        fprintf(stderr, "error - pcap_open_live() failed: %s", errbuf);
        return -4;
    }

    // Compile BPF filter expression into program if one provided
    if (strfilter != NULL) {
        // compile filter expression
        if (pcap_compile(pcap_session, &binfilter, strfilter, 1, maskp) < 0) {
            fprintf(stderr, "error - pcap_compile() failed (%s)\n", pcap_geterr(pcap_session));
            shutdown_sniffer(-5); 
        }
    }

    // install compiled filter
    if (pcap_setfilter(pcap_session, &binfilter) < 0) {
        fprintf(stderr, "error - pcap_setfilter() failed (%s)\n", pcap_geterr(pcap_session));
        shutdown_sniffer(-6);
    }

    printf("BPF filter = %s\n", strfilter);

    // Start capturing
    pcap_loop(pcap_session, cnt, process_packet, NULL);

    // close the session
    pcap_close(pcap_session);
        
    shutdown_sniffer(0);
}