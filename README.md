# cPacketSniffer

`cPacketSniffer` is a Linux network packets sniffer written in C language based on libpcap. 

## Goals

`cPacketSniffer` is for learning and research purpose. If you want to know how to develop a Linux network packets sniffer from scratch or practice how to write a non-trivial application in C, then this project is for you!

## Features

- Integrate with `libpcap` to support: filtering captured packets, capturing packets offline, capturing packets on specific devices and capturing packets in promiscuous mode.
- Analyze network packets at low layers of TCP/IP stack, including `Ethernet`, `ARP`, `ICMP`, `IP(IPv4)`, `TCP`, `UDP`, etc. Also one protocol in the application layer: `TFTP`. 
- Detect network security attacks:
    - ARP spoofing detection
    - Ping flood detection
- Analyze and track network traffics:
    - TCP session tracking and traffic analysis
    - TFTP session tracking and traffic analysis
- Develop a generic Map data structure based on HashTable to support varoius workflow


## Building

A clean `Makefile` is provided in this project, to build just run:

`make`

## Usage

```sh
Usage: sniffer [-d XXX -h]
-d XXX: device to capture from, where XXX is device name (ex: eth0).
-f 'filter' : filter captures according to BPF expression (ex: 'ip or arp').
-h : show this information.
-i file: read datagram from given file instead of a device.
-l file: log captured datagrams in given file.
-n : number of datagrams to capture.
-p : active promiscuous capture mode.
-q : active quite mode.
-r : active raw display of captured data.
-s: apply specified security application. Available applications: arpspoof, pingflood, tcptrack, tftptrack.
-S: #.#.#.# : IP address of TFTP server to monitor.
```

## External dependencies
`cPacketSniffer` is relying on `libpcap`, which is a famous library in the network capturing field. And the libraries are pretty straightforward to install.

## Acknowledgement
This project is based on the following open source [document](http://tcpip.marcolavoie.ca/index.html), which is owned by **Marco Lavoie**. Thanks for sharing this great document. 

The difference between my project and origial project is that I refactor the application in `C` language. The original project is written in `C++`, which is great. But I just want to use this project as a practise to enhance my C programming skills. 

The application developed in this project is the same as the original one: `network packet capture and injection` application on Linux system. 



