#ifndef INIDS_ENCODING_H
#define INIDS_ENCODING_H

#include <stdint.h>

/*
 * Defines the default encoding for the antigens and antibodies (data format)
 * -> Antigens are the data we want to classify
 * -> Antibodies are antigens detector
 */

/*
 * Our antigen will be a network flow between two machines
 */
struct antigen_encode {
    struct in_addr *ip_src, *ip_dst;    // source and destination ip addresses (from ip header)
    uint16_t src_port, dst_port;        // source and destination ports (from transport header)
    uint8_t ttl;                        // Time-to-Live
    uint8_t tos;                        // Type of Service

    struct timeval *ts;                 // arrival timestamp
};

struct antibody_encode {
    struct antigen_encode antigen;         // the antigen associated
    int concentration;      // the occurrence of the antibody present in the system (flow detected)
};


#endif //INIDS_ENCODING_H
