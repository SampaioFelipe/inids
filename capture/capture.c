#include "capture.h"

#include <memory.h>
#include <stdlib.h>


void capture_init() {

    pcap_if_t *devices = NULL; // list of all network devices

    uint32_t src_ip, netmask;

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // find all the netowork devices and return in devices
    if (pcap_findalldevs(&devices, errbuf) < 0) {
        fprintf(stderr, "%s", errbuf);
        exit(EXIT_FAILURE);
    }

    if (devices == NULL) {
        fprintf(stderr, "no network device found");
        exit(EXIT_FAILURE);
    }

    // Open the device had been chosen
    //TODO: possibilitar que a análise possa ser feita de um arquivo ao invés da captura online: pcap_open_offline()
    capture_device = pcap_open_live(devices->name, 65555, 1, 512, errbuf); //TODO: estudar melhor os parametros

    if (capture_device == NULL) {
        fprintf(stderr, "%s",errbuf);
        exit(EXIT_FAILURE);
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(devices->name, &src_ip, &netmask, errbuf) < 0) {
        printf("pcap_lookupnet: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    struct in_addr ip_addr;
    ip_addr.s_addr = src_ip;
    printf("The IP address is %s\n", inet_ntoa(ip_addr));

//TODO: Tratar a especificação de expressões de filtro

//    // Convert the packet filter expression into a packet
//    // filter binary.
//    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
//    {
//        printf("pcap_compile(): %s\n", pcap_geterr(pd));
//        return NULL;
//    }
//
//    // Assign the packet filter to the given libpcap socket.
//    if (pcap_setfilter(pd, &bpf) < 0)
//    {
//        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
//        return NULL;
//    }
}

void capture_start_loop() {
    int count = 0;

    int data_link_type;

    // Determine the datalink layer type.
    data_link_type = pcap_datalink(capture_device);

    switch (data_link_type) {
        case DLT_NULL: // LOOPBACK
            link_hdr_len = 4;
            break;

        case DLT_EN10MB: // ETHERNET
            link_hdr_len = 14;
            break;
            //TODO: dar suporte a outros tipos de link
        default:
            fprintf(stderr, "Unsupported datalink (%d)\n", data_link_type);
            return;
    }

    //TODO: ajustar os parametros
    if (pcap_loop(capture_device, 20, process_packet, (u_char *) &count) == -1) {
        fprintf(stderr, "%s", errbuf);
        exit(EXIT_FAILURE);
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet_bytes) {
    int *counter = (int *) args;
    printf("Count: %d\n",*counter);
    *counter += 1;

    struct ip *iphdr;
    struct icmphdr *icmphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    char iphdrInfo[256], srcip[256], dstip[256];
    unsigned short id, seq;

    // Skip the datalink layer header and get the IP header fields.
    packet_bytes += link_hdr_len;
    iphdr = (struct ip *) packet_bytes;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4 * iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    packet_bytes += 4 * iphdr->ip_hl;

    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *) packet_bytes;
            printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->source),
                   dstip, ntohs(tcphdr->dest));
            printf("%s\n", iphdrInfo);
            printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                   (tcphdr->urg ? 'U' : '*'),
                   (tcphdr->ack ? 'A' : '*'),
                   (tcphdr->psh ? 'P' : '*'),
                   (tcphdr->rst ? 'R' : '*'),
                   (tcphdr->syn ? 'S' : '*'),
                   (tcphdr->fin ? 'F' : '*'),
                   ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),
                   ntohs(tcphdr->window), 4 * tcphdr->doff);
            break;

        case IPPROTO_UDP:
            udphdr = (struct udphdr *) packet_bytes;
            printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->source),
                   dstip, ntohs(udphdr->dest));
            printf("%s\n", iphdrInfo);
            break;

        case IPPROTO_ICMP:
            icmphdr = (struct icmphdr *) packet_bytes;
            printf("ICMP %s -> %s\n", srcip, dstip);
            printf("%s\n", iphdrInfo);
            memcpy(&id, (u_char *) icmphdr + 4, 2);
            memcpy(&seq, (u_char *) icmphdr + 6, 2);
            printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
                   ntohs(id), ntohs(seq));
            break;

        default:
            printf("Not supported\n");
    }

    printf("------------------------------------------------------\n\n");
}
