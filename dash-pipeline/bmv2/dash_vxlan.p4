#ifndef _SIRIUS_VXLAN_P4_
#define _SIRIUS_VXLAN_P4_

#include "dash_headers.p4"

action vxlan_encap(inout headers_t hdr,
                   in EthernetAddress underlay_dmac,
                   in EthernetAddress underlay_smac,
                   in IPv4Address underlay_dip,
                   in IPv4Address underlay_sip,
                   in EthernetAddress overlay_dmac, 
                   in bit<24> vni) {
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
                         UDP_HDR_SIZE + \
                         VXLAN_HDR_SIZE;
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
    hdr.ip_0.ipv4.total_len = (ETHER_HDR_SIZE + IPV4_HDR_SIZE + UDP_HDR_SIZE +
        VXLAN_HDR_SIZE + ip_len);
#endif // TARGET_DPDK_PNA
    hdr.ip_0.ipv4.identification = 1;
    hdr.ip_0.ipv4.flags = 0;
    hdr.ip_0.ipv4.frag_offset = 0;
    hdr.ip_0.ipv4.ttl = 64;
    hdr.ip_0.ipv4.protocol = UDP_PROTO;
    hdr.ip_0.ipv4.dst_addr = underlay_dip;
    hdr.ip_0.ipv4.src_addr = underlay_sip;
    hdr.ip_0.ipv4.hdr_checksum = 0;
    
    hdr.udp_0.setValid();
    hdr.udp_0.src_port = 0;
    hdr.udp_0.dst_port = UDP_PORT_VXLAN;
    hdr.udp_0.length = hdr.ip_0.ipv4.total_len - IPV4_HDR_SIZE;
    hdr.udp_0.checksum = 0;
    
    hdr.encap_0.vxlan.setValid();
    hdr.encap_0.vxlan.reserved = 0;
    hdr.encap_0.vxlan.reserved_2 = 0;
    hdr.encap_0.vxlan.flags = 0;
    hdr.encap_0.vxlan.vni = vni;

    hdr.ethernet.dst_addr = overlay_dmac;
}

action vxlan_decap(inout headers_t hdr) {
    hdr.ethernet_1.setInvalid();
    hdr.ip_1.ipv4.setInvalid();
    hdr.ip_1.ipv6.setInvalid();
    hdr.ipv4options_1.setInvalid();
    hdr.udp_1.setInvalid();
    hdr.encap_1.vxlan.setInvalid();

    hdr.ethernet_0.setInvalid();
    hdr.ip_0.ipv4.setInvalid();
    hdr.ip_0.ipv6.setInvalid();
    hdr.ipv4options_0.setInvalid();
    hdr.udp_0.setInvalid();
    hdr.encap_0.vxlan.setInvalid();
}

#endif /* _SIRIUS_VXLAN_P4_ */
