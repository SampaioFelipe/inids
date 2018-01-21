#include "capture.h"
#include "../utils/error_handler.h"

#include <memory.h>
#include <stdlib.h>


void capture_init(int mode, char *filename, char *filter_expression)
{
    struct bpf_program bpf; // compiled filter expression
    uint32_t src_ip, netmask;


    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    if (mode == ONLINE_MODE)
    {

        pcap_if_t *devices = NULL; // list of all network devices


        // find all the network devices and return in devices
        if (pcap_findalldevs(&devices, errbuf) < 0)
        {
            print_error(errbuf);
            exit(EXIT_FAILURE);
        }

        if (devices == NULL)
        {
            print_error(DEVICE_NOT_FOUND);
            exit(EXIT_FAILURE);
        }

        // Open the device had been chosen
        capture_device = pcap_open_live(devices->name, 65555, 1, 512, errbuf); //TODO: estudar melhor os parametros

        if (capture_device == NULL)
        {
            print_error(errbuf);
            exit(EXIT_FAILURE);
        }

        // Get network device source IP address and netmask for the filtering.
        if (pcap_lookupnet(devices->name, &src_ip, &netmask, errbuf) < 0)
        {
            print_error(errbuf);
            exit(EXIT_FAILURE);
        }

        struct in_addr ip_addr;
        ip_addr.s_addr = src_ip;
        printf("The IP address is %s\n", inet_ntoa(ip_addr));
    }
    else
    {
        capture_device = pcap_open_offline(filename, errbuf);

        if (capture_device == NULL)
        {
            print_error(errbuf);
            exit(EXIT_FAILURE);
        }

        netmask = 0;
    }


    //TODO: Tratar a especificação de expressões de filtro

    if (filter_expression != NULL)
    {
        if (pcap_compile(capture_device, &bpf, filter_expression, 1, netmask) == -1)
        {
            print_error(errbuf);
            return;
        }

        // Assign the packet filter to the given libpcap socket.
        if (pcap_setfilter(capture_device, &bpf) == -1)
        {
            print_error(errbuf);
            return;
        }
    }

}

void capture_start_loop()
{
    int count = 0;

    int data_link_type;

    // Determine the datalink layer type.
    data_link_type = pcap_datalink(capture_device);

    // TODO: dar suporte a outros tipos de link e
    switch (data_link_type)
    {
        case DLT_NULL: // LOOPBACK
            break;

        case DLT_EN10MB: // ETHERNET
            break;

        default:
            fprintf(stderr, "Unsupported datalink (%d)\n", data_link_type);
            return;
    }

    // TODO: ajustar os parametros
    if (pcap_loop(capture_device, -1, process_packet, (u_char *) &count) == -1)
    {
        print_error(errbuf);
        exit(EXIT_FAILURE);
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet_bytes)
{
    // passed argument
    int *counter = (int *) args;

    printf("Count: %d\n", *counter);
    *counter += 1;

    // headers tipes
    const struct ether_header *etherhdr;
    const struct ip *iphdr;
    const struct tcphdr *tcphdr;
    const struct icmphdr *icmphdr;
    const struct udphdr *udphdr;

    int hdr_off = 0;

    char iphdrInfo[256], srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];

    /*
     * Ethernet II frame:
     * --------------------------------------------------------------------
     * |[ MAC ADDR DST | MAC ADDR SRC | ETHER TYPE ] | PAYLOAD | CHECKSUM |
     * --------------------------------------------------------------------
     */

    etherhdr = (struct ether_header *) packet_bytes;

    /*
     * ntohs is used to convert ip addr from network byte order to host byte order
     * Remember, x86 like architecture is little endian, whereas network is big endian
     */
    if (ntohs(etherhdr->ether_type) == ETHERTYPE_IP)
    {
        hdr_off += sizeof(struct ether_header);
        iphdr = (struct ip *) (packet_bytes + hdr_off);

        // TODO: remover essa parte, pois é apenas para debug
        // inet_ntop converts de ip adress bytes to a human-readable string (inet_ntoa is deprecated)
        inet_ntop(AF_INET, &(iphdr->ip_src), srcip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iphdr->ip_dst), dstip, INET_ADDRSTRLEN);

        // TODO: remover essa parte, pois é apenas para debug
        sprintf(iphdrInfo, "VERSION:%d | HL:%d | TOS:0x%x | TOTAL LENGHT:%d |\n"
                        "ID:%d | TTL:%d | PROTOCOL:0x%x |\n"
                        "SRC:%s |\n"
                        "DST:%s |\n",
                iphdr->ip_v, 4 * iphdr->ip_hl, iphdr->ip_tos, ntohs(iphdr->ip_len),
                ntohs(iphdr->ip_id), iphdr->ip_ttl, iphdr->ip_p, srcip, dstip);

        switch (iphdr->ip_p)
        {
            case IPPROTO_TCP:
                hdr_off += sizeof(struct ip);
                tcphdr = (struct tcphdr *) (packet_bytes + hdr_off);

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

//            case IPPROTO_ICMP:
//                icmphdr = (struct icmphdr *) packet_bytes;
//                printf("ICMP %s -> %s\n", srcip, dstip);
//                printf("%s\n", iphdrInfo);
//                memcpy(&id, (u_char *) icmphdr + 4, 2);
//                memcpy(&seq, (u_char *) icmphdr + 6, 2);
//                printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
//                       ntohs(id), ntohs(seq));
//                break;

            default:
                printf("Not supported\n");
        }

    }

    printf("------------------------------------------------------\n\n");
}
