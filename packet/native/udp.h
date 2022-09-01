#pragma once

#include "../../env.h"
#include "checksum.h"

#pragma pack(push, 1)
struct udp_hdr {
public:
    unsigned short                  src;
    unsigned short                  dest;  /* src/dest UDP ports */
    unsigned short                  len;
    unsigned short                  chksum;

public:
    static struct udp_hdr* Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;
};
#pragma pack(pop)