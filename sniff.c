#include <stdio.h>
#include <string.h> // memset
#include <stdlib.h> // exit
#include <unistd.h> // getopt
#include <signal.h> // Ctrl+C handling

#include <pcap.h> // libpcap



void bypass_sigint(int sig_no) {
    printf("**\nCapture process interrupted by user...\n");
}




int main(int argc, char *argv[]) {
    char *device = NULL;  // device to sniff
    char argch;           // to manage command line arguments
    char errbuf[PCAP_ERRBUF_SIZE];        // to handle libpcap error message
    
    // install ctrl+c handle
    struct sigaction sa, osa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler  = &bypass_sigint;
    sigaction(SIGINT, &sa, &osa);

    while((argch = getopt(argc, argv, "hd:")) != EOF) {
        switch(argch) {
            case 'd': // device name
                device = optarg;
                break;
            
            case 'h':
                printf("Usage: sniff [-d XXX -h]\n");
                printf("-d XXX: device to capture from, where XXX is device name (ex: eth0).\n");
                printf("-h : show this information.\n");

                if (argc == 2) return 0;
                break;
        }
    }

    // identify device to use
    if (device == NULL && (device = pcap_lookupdev(errbuf)) == NULL) {
        fprintf(stderr, "error - %s", errbuf);
        return -2;
    } else {
        printf("device = %s\n", device);
    }
    return 0;
}