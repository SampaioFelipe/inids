#ifndef INIDS_CAPTURE_H
#define INIDS_CAPTURE_H

#include <pcap.h>
//#include "params.h"

char errbuf[PCAP_ERRBUF_SIZE]; // buffer for error handling

/* Initialize capture */
int init_capture();

/* Callback function for packet processing. It is called for each packet arrived */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *bytes);

#endif //INIDS_CAPTURE_H
