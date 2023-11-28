#ifndef _DASH_NVGRE_P4_
#define _DASH_NVGRE_P4_

#include "dash_headers.p4"

action nvgre_encap(inout headers_t hdr,
                   in EthernetAddress underlay_dmac,
                   in EthernetAddress underlay_smac,
                   in IPv4Address underlay_dip,
                   in IPv4Address underlay_sip,
                   in EthernetAddress overlay_dmac, 
                   in bit<24> vsid) {
    // FIXME: consider underlay 1 later
    hdr.ethernet_0.setValid();
    hdr.ethernet_0.dst_addr = underlay_dmac;
    hdr.ethernet_0.src_addr = underlay_smac;
    hdr.ethernet_0.ether_type = IPV4_ETHTYPE;

    hdr.ip_0.ipv4.setValid();
    hdr.ip_0.ipv4.version = 4;
    hdr.ip_0.ipv4.ihl = 5;
    hdr.ip_0.ipv4.diffserv = 0;
#ifdef TARGET_BMV2_V1MODEL
    hdr.ip_0.ipv4.total_len = hdr.ip.ipv4.total_len*(bit<16>)(bit<1>)hdr.ip.ipv4.isValid() + \
                         hdr.ip.ipv6.payload_length*(bit<16>)(bit<1>)hdr.ip.ipv6.isValid() + \
                         IPV6_HDR_SIZE*(bit<16>)(bit<1>)hdr.ip.ipv6.isValid() + \
                         ETHER_HDR_SIZE + \
                         IPV4_HDR_SIZE + \
                         NVGRE_HDR_SIZE;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
    // p4c-dpdk as of 2023-Jan-26 does not support multplication of
    // run-time variable values.  It does support 'if' statements
    // inside of P4 action bodies.
    bit<16> ip_len = 0;
    if (hdr.ip.ipv4.isValid()) {
        ip_len = ip_len + hdr.ip.ipv4.total_len;
    }
    if (hdr.ip.ipv6.isValid()) {
        ip_len = (ip_len + IPV6_HDR_SIZE +
            hdr.ip.ipv6.payload_length);
    }
    hdr.ip_0.ipv4.total_len = (ETHER_HDR_SIZE + IPV4_HDR_SIZE + NVGRE_HDR_SIZE + ip_len);
#endif // TARGET_DPDK_PNA

    hdr.ip_0.ipv4.identification = 1;
    hdr.ip_0.ipv4.flags = 0;
    hdr.ip_0.ipv4.frag_offset = 0;
    hdr.ip_0.ipv4.ttl = 64;
    hdr.ip_0.ipv4.protocol = NVGRE_PROTO;
    hdr.ip_0.ipv4.dst_addr = underlay_dip;
    hdr.ip_0.ipv4.src_addr = underlay_sip;
    hdr.ip_0.ipv4.hdr_checksum = 0;

    hdr.encap_0.nvgre.setValid();
    hdr.encap_0.nvgre.flags = 4;
    hdr.encap_0.nvgre.reserved = 0;
    hdr.encap_0.nvgre.version = 0;
    hdr.encap_0.nvgre.protocol_type = 0x6558;
    hdr.encap_0.nvgre.vsid = vsid;
    hdr.encap_0.nvgre.flow_id = 0;
}

#endif /* _DASH_NVGRE_P4_ */
