#ifndef _SIRIUS_SERVICE_TUNNEL_P4_
#define _SIRIUS_SERVICE_TUNNEL_P4_

#include "dash_headers.p4"

/* Encodes V4 in V6 */
action service_tunnel_encode(inout headers_t hdr,
                             in IPv6Address st_dst,
                             in IPv6Address st_dst_mask,
                             in IPv6Address st_src,
                             in IPv6Address st_src_mask) {
    ipv4_t ipv4 = hdr.ip.ipv4;

    hdr.ip.ipv6.setValid();
    hdr.ip.ipv6.version = 6;
    hdr.ip.ipv6.traffic_class = 0;
    hdr.ip.ipv6.flow_label = 0;
    hdr.ip.ipv6.payload_length = ipv4.total_len - IPV4_HDR_SIZE;
    hdr.ip.ipv6.next_header = ipv4.protocol;
    hdr.ip.ipv6.hop_limit = ipv4.ttl;
    hdr.ip.ipv6.dst_addr = ((IPv6Address)ipv4.dst_addr & ~st_dst_mask) | (st_dst & st_dst_mask);
    hdr.ip.ipv6.src_addr = ((IPv6Address)ipv4.src_addr & ~st_src_mask) | (st_src & st_src_mask);
    
    hdr.ip.ipv4.setInvalid();
    hdr.ethernet.ether_type = IPV6_ETHTYPE;
}

/* Decodes V4 from V6 */
action service_tunnel_decode(inout headers_t hdr,
                             in IPv4Address src,
                             in IPv4Address dst) {
    ipv6_t ipv6 = hdr.ip.ipv6;

    hdr.ip.ipv4.setValid();
    hdr.ip.ipv4.version = 4;
    hdr.ip.ipv4.ihl = 5;
    hdr.ip.ipv4.diffserv = 0;
    hdr.ip.ipv4.total_len = ipv6.payload_length + IPV4_HDR_SIZE;
    hdr.ip.ipv4.identification = 1;
    hdr.ip.ipv4.flags = 0;
    hdr.ip.ipv4.frag_offset = 0;
    hdr.ip.ipv4.protocol = ipv6.next_header;
    hdr.ip.ipv4.ttl = ipv6.hop_limit;
    hdr.ip.ipv4.hdr_checksum = 0;
    hdr.ip.ipv4.dst_addr = dst;
    hdr.ip.ipv4.src_addr = src;

    hdr.ip.ipv6.setInvalid();
    hdr.ethernet.ether_type = IPV4_ETHTYPE;
}

#endif /* _SIRIUS_SERVICE_TUNNEL_P4_ */
