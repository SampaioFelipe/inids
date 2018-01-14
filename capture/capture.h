#ifndef INIDS_CAPTURE_H
#define INIDS_CAPTURE_H

#include <pcap.h>
#include "params.h"



#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>



char errbuf[PCAP_ERRBUF_SIZE]; // buffer for error handling

pcap_t* capture_device; // packet capture device

int link_hdr_len; // data link header lenght

/* Initialize capture */
void capture_init();

void capture_start_loop();

/* Callback function for packet processing. It is called for each packet arrived */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *bytes);

#endif //INIDS_CAPTURE_H
