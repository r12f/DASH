#ifndef _ROUTEACTION_P4_
#define _ROUTEACTION_P4_

#include "dash_headers.p4"

/*
 * Packet transformation actions
 */
control action_staticencap(inout headers_t hdr, inout metadata_t meta)
{
    action drop() {
        meta.dropped = true;
    }

    apply {
        if (meta.encap_data.encap_type == dash_encapsulation_t.VXLAN) {
            vxlan_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        meta.encap_data.vni);
        } else if (meta.encap_data.encap_type == dash_encapsulation_t.NVGRE) {
            nvgre_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        meta.encap_data.vni);
        } else {
            drop();
        }
    }
}

control action_tunnel(inout headers_t hdr, inout metadata_t meta)
{
    action drop() {
        meta.dropped = true;
    }

    action set_tunnel_underlay0(IPv4Address     underlay_sip,
                                IPv4Address     underlay_dip,
                                EthernetAddress underlay_smac,
                                EthernetAddress underlay_dmac) {
        meta.encap_data.underlay_sip = underlay_sip != 0 ? underlay_sip : meta.encap_data.underlay_sip;
        meta.encap_data.underlay_dip = underlay_dip != 0 ? underlay_dip : meta.encap_data.underlay_dip;
        meta.encap_data.underlay_smac = underlay_smac != 0 ? underlay_smac : meta.encap_data.underlay_smac;
        meta.encap_data.underlay_dmac = underlay_dmac != 0 ? underlay_dmac : meta.encap_data.underlay_dmac;
    }

    table tunnel_underlay0 {
        key = {
            meta.tunnel_underlay0_id : exact @name("meta.tunnel_underlay0_id:tunnel_underlay0_id");
        }

        actions = {
            set_tunnel_underlay0;
            drop;
        }
        const default_action = drop;
    }

    action set_tunnel_underlay1(IPv4Address     underlay_sip,
                                IPv4Address     underlay_dip,
                                EthernetAddress underlay_smac,
                                EthernetAddress underlay_dmac) {
        // FIXME: use underlay1_sip, etc
        meta.encap_data.underlay_sip = underlay_sip != 0 ? underlay_sip : meta.encap_data.underlay_sip;
        meta.encap_data.underlay_dip = underlay_dip != 0 ? underlay_dip : meta.encap_data.underlay_dip;
        meta.encap_data.underlay_smac = underlay_smac != 0 ? underlay_smac : meta.encap_data.underlay_smac;
        meta.encap_data.underlay_dmac = underlay_dmac != 0 ? underlay_dmac : meta.encap_data.underlay_dmac;
    }

    table tunnel_underlay1 {
        key = {
            meta.tunnel_underlay1_id : exact @name("meta.tunnel_underlay1_id:tunnel_underlay1_id");
        }

        actions = {
            set_tunnel_underlay1;
            drop;
        }
        const default_action = drop;
    }

    apply {
        if ((meta.tunnel_target & TUNNEL_UNDERLAY0) != 0) {
            tunnel_underlay0.apply();
        }

        if ((meta.tunnel_target & TUNNEL_UNDERLAY1) != 0) {
            tunnel_underlay1.apply();
        }
    }
}

control action_reverse_tunnel(inout headers_t hdr, inout metadata_t meta)
{
    apply {
        // No packet transformation so far
    }
}

control action_tunnel_from_encap(inout headers_t hdr, inout metadata_t meta)
{
    apply {
        if (meta.tunnel_source == TUNNEL_UNDERLAY0) {
            if (meta.tunnel_target == TUNNEL_UNDERLAY0) {
                // FIXME: copy underlay encap
            } else if (meta.tunnel_target == TUNNEL_UNDERLAY1) {
                // FIXME: copy underlay encap
            }
        } else if (meta.tunnel_source == TUNNEL_UNDERLAY1) {
            if (meta.tunnel_target == TUNNEL_UNDERLAY0) {
                // FIXME: copy underlay encap
            } else if (meta.tunnel_target == TUNNEL_UNDERLAY1) {
                // FIXME: copy underlay encap
            }
        }
    }
}

control action_4to6(inout headers_t hdr, inout metadata_t meta)
{
    apply {
        ipv4_t ipv4 = hdr.ip.ipv4;

        hdr.ip.ipv6.setValid();
        hdr.ip.ipv6.version = 6;
        hdr.ip.ipv6.traffic_class = 0;
        hdr.ip.ipv6.flow_label = 0;
        hdr.ip.ipv6.payload_length = ipv4.total_len - 20;
        hdr.ip.ipv6.hop_limit = ipv4.ttl;
        hdr.ip.ipv6.src_addr = ((bit<128>) ipv4.src_addr & ~meta.sip_4to6_encoding_mask) \
                            | meta.sip_4to6_encoding_value;
        hdr.ip.ipv6.dst_addr = ((bit<128>) ipv4.dst_addr & ~meta.dip_4to6_encoding_mask) \
                            | meta.dip_4to6_encoding_value;
        hdr.ip.ipv4.setInvalid();
        hdr.ethernet.ether_type = IPV6_ETHTYPE;
    }
}

control action_6to4(inout headers_t hdr, inout metadata_t meta)
{
    apply {
        ipv6_t ipv6 = hdr.ip.ipv6;

        hdr.ip.ipv4.setValid();
        hdr.ip.ipv4.version = 4;
        hdr.ip.ipv4.ihl = 5;
        hdr.ip.ipv4.diffserv = 0;
        // FIXME: skip ipv6 option length ??
        hdr.ip.ipv4.total_len = 20 + ipv6.payload_length;
        hdr.ip.ipv4.identification = 1;
        hdr.ip.ipv4.flags = 0;
        hdr.ip.ipv4.frag_offset = 0;
        hdr.ip.ipv4.ttl = ipv6.hop_limit;
        hdr.ip.ipv4.protocol = ipv6.next_header;
        hdr.ip.ipv4.hdr_checksum = 0;
        hdr.ip.ipv4.src_addr = ((bit<32>) ipv6.src_addr & ~meta.sip_6to4_encoding_mask) \
                            | meta.sip_6to4_encoding_value;
        hdr.ip.ipv4.dst_addr = ((bit<32>) ipv6.dst_addr & ~meta.dip_6to4_encoding_mask) \
                            | meta.dip_6to4_encoding_value;
        hdr.ip.ipv6.setInvalid();
        hdr.ethernet.ether_type = IPV4_ETHTYPE;
    }
}

control action_nat(inout headers_t hdr, inout metadata_t meta)
{
    action do_nat(IPv4ORv6Address nat_sip,
                  IPv4ORv6Address nat_dip,
                  bit<1> ip_is_v6,
                  bit<16> nat_sport,
                  bit<16> nat_dport,
                  bit<16> nat_sport_base,
                  bit<16> nat_dport_base
                  ) {
        if (hdr.tcp.isValid()) {
            hdr.tcp.src_port = nat_sport + (hdr.tcp.src_port - nat_sport_base);
            hdr.tcp.dst_port = nat_dport + (hdr.tcp.dst_port - nat_dport_base);
        } else {
            hdr.udp.src_port = nat_sport + (hdr.udp.src_port - nat_sport_base);
            hdr.udp.dst_port = nat_dport + (hdr.udp.dst_port - nat_dport_base);
        }

        if (ip_is_v6 != 0) {
            hdr.ip.ipv6.src_addr = nat_sip;
            hdr.ip.ipv6.dst_addr = nat_dip;
        } else {
            hdr.ip.ipv4.src_addr = (bit<32>)nat_sip;
            hdr.ip.ipv4.dst_addr = (bit<32>)nat_dip;
        }
    }

    apply {
        do_nat(meta.encap_data.overlay_sip,
               meta.encap_data.overlay_dip,
               meta.encap_data.is_overlay_ip_v6,
               meta.encap_data.nat_sport,
               meta.encap_data.nat_dport,
               meta.encap_data.nat_sport_base,
               meta.encap_data.nat_dport_base);
    }
}

#endif /* _ROUTEACTION_P4_ */
