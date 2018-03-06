#ifndef INIDS_CAPTURE_H
#define INIDS_CAPTURE_H

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "../globals/error_handler.h"
#include "../globals/encoding.h"
#include "../globals/threads_manager.h"

#define ONLINE_MODE 0
#define OFFLINE_MODE 1

char errbuf[PCAP_ERRBUF_SIZE];  // buffer for error handling

pcap_t *capture_device;         // packet capture device

/* Initialize capture */
void capture_init(int mode, char *filename, char *filter_expression);

void capture_start_loop();

/* Callback function for packet processing. It is called for each packet arrived */
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *bytes);


/* Thread sync */
extern pthread_mutex_t mutex_processing;
extern pthread_cond_t cond_processing;

/* antigens buffers */
extern antigen_buffer *cap_buf;     // capture buffer
extern antigen_buffer *proc_buf;    // process buffer

#endif //INIDS_CAPTURE_H
