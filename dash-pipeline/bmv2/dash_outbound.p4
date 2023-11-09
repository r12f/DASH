#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"
#include "dash_service_tunnel.p4"


control outbound(inout headers_t hdr,
                 inout metadata_t meta)
{
    action drop() {
        meta.dropped = true;
    }

    /*
     * Packet transformation actions
     */
    action do_staticencap() {
        if (meta.encap_data.encap_type == dash_encapsulation_t.VXLAN) {
            vxlan_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        meta.encap_data.encap_vni);
        } else if (meta.encap_data.encap_type == dash_encapsulation_t.NVGRE) {
            nvgre_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        meta.encap_data.encap_vni);
        } else {
            drop();
        }
    }

    action do_tunnel() {
    }

    action do_tunnel_from_encap() {
    }

    action do_reverse_tunnel() {
    }

    action do_4to6() {
    }

    action do_6to4() {
    }

    action do_nat(IPv4ORv6Address nat_sip,
                  IPv4ORv6Address nat_dip,
                  bit<1> ip_is_v6;
                  bit<16> nat_sport,
                  bit<16> nat_dport,
                  bit<16> nat_sport_base,
                  bit<16> nat_dport_base,
                  ) {
        // FIXME: handle udp ...
        hdr.tcp.src_port = nat_sport + (hdr.tcp.src_port - nat_sport_base);
        hdr.tcp.dst_port = nat_dport + (hdr.tcp.dst_port - nat_dport_base);
        // FIXME: IPv6 ....
        hdr.ipv4.src_addr = (bit<32>)nat_sip;
        hdr.ipv4.dst_addr = (bit<32>)nat_dip;
    }

    action outbound_metadata_publish(MatchStage_t next_stage,
                                     bit<16> routing_type,
                                     Nexthop_t nexthop,
                                     Oid_t pipeline_oid,
                                     Oid_t mapping_oid,
                                     Oid_t tcpportmap_oid,
                                     Oid_t udpportmap_oid,
                                     bit<1> lkp_addr_is_v6,
                                     IPv4ORv6Address lkp_addr,
                                     bit<16> nat_src_port,
                                     bit<16> nat_dst_port,
                                     bit<1> is_overlay_ip_v6,
                                     IPv4ORv6Address overlay_sip,
                                     IPv4ORv6Address overlay_dip,
                                     EthernetAddress overlay_smac,
                                     EthernetAddress overlay_dmac,
                                     dash_encapsulation_t encap_type,
                                     bit<24> encap_vni,
                                     IPv4Address     underlay_sip,
                                     IPv4Address     underlay_dip,
                                     EthernetAddress underlay_smac,
                                     EthernetAddress underlay_dmac
                                    ) {
        meta.transit_to = next_stage;
        meta.routing_type = meta.routing_type | routing_type;
        meta.nexthop = nexthop != 0 ? nexthop : meta.nexthop;

        meta.pipeline_oid = pipeline_oid != 0 ? pipeline_oid : meta.pipeline_oid;
        meta.mapping_oid = mapping_oid != 0 ? mapping_oid : meta.mapping_oid;
        meta.tcpportmap_oid = tcpportmap_oid != 0 ? tcpportmap_oid : meta.tcpportmap_oid;
        meta.udpportmap_oid = udpportmap_oid != 0 ? udpportmap_oid : meta.udpportmap_oid;

        meta.lkp_addr = lkp_addr != 0 ? lkp_addr : meta.lkp_addr;
        meta.lkp_addr_is_v6 = lkp_addr_is_v6 != 0 ? lkp_addr_is_v6 : meta.lkp_addr_is_v6;

        meta.encap_data.nat_src_port = nat_src_port != 0 ? nat_src_port : meta.encap_data.nat_src_port;
        meta.encap_data.nat_dst_port = nat_dst_port != 0 ? nat_dst_port : meta.encap_data.nat_dst_port;

        meta.encap_data.is_overlay_ip_v6 = is_overlay_ip_v6 != 0 ? is_overlay_ip_v6 : meta.encap_data.is_overlay_ip_v6;
        meta.encap_data.overlay_sip = overlay_sip != 0 ? overlay_sip : meta.encap_data.overlay_sip;
        meta.encap_data.overlay_dip = overlay_dip != 0 ? overlay_dip : meta.encap_data.overlay_dip;
        meta.encap_data.overlay_smac = overlay_smac != 0 ? overlay_smac : meta.encap_data.overlay_smac;
        meta.encap_data.overlay_dmac = overlay_dmac != 0 ? overlay_dmac : meta.encap_data.overlay_dmac;

        meta.encap_data.encap_type = encap_type != 0 ? encap_type : meta.enap_data.encap_type;
        meta.encap_data.encap_vni = encap_vni != 0 ? encap_vni : meta.enap_data.encap_vni;

        meta.encap_data.underlay_sip = underlay_sip != 0 ? underlay_sip : meta.encap_data.underlay_sip;
        meta.encap_data.underlay_dip = underlay_dip != 0 ? underlay_dip : meta.encap_data.underlay_dip;
        meta.encap_data.underlay_smac = underlay_smac != 0 ? underlay_smac : meta.encap_data.underlay_smac;
        meta.encap_data.underlay_dmac = underlay_dmac != 0 ? underlay_dmac : meta.encap_data.underlay_dmac;
    }

    @name("outbound_routing|dash_outbound_routing0")
    table routing0 {
        key = {
            meta.pipeline_oid : exact @name("meta.pipeline_oid:pipeline_oid");
            meta.lkp_addr_is_v6 : exact @name("meta.lkp_addr_is_v6:lkp_addr_is_v6");
            meta.lkp_addr : lpm @name("meta.lkp_addr:lkp_addr");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @name("outbound_routing|dash_outbound_routing1")
    table routing1 {
        key = {
            meta.pipeline_oid : exact @name("meta.pipeline_oid:pipeline_oid");
            meta.lkp_addr_is_v6 : exact @name("meta.lkp_addr_is_v6:lkp_addr_is_v6");
            meta.lkp_addr : lpm @name("meta.lkp_addr:lkp_addr");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @name("outbound_ipmapping|dash_outbound_ipmapping0")
    table ipmapping0 {
        key = {
            meta.mapping_oid : exact @name("meta.mapping_oid:mapping_oid");
            meta.lkp_addr_is_v6 : exact @name("meta.lkp_addr_is_v6:lkp_addr_is_v6");
            meta.lkp_addr : exact @name("meta.lkp_addr:lkp_addr");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @name("outbound_ipmapping|dash_outbound_ipmapping1")
    table ipmapping1 {
        key = {
            meta.mapping_oid : exact @name("meta.mapping_oid:mapping_oid");
            meta.lkp_addr_is_v6 : exact @name("meta.lkp_addr_is_v6:lkp_addr_is_v6");
            meta.lkp_addr : exact @name("meta.lkp_addr:lkp_addr");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @name("outbound_tcpportmapping|dash_outbound_tcpportmapping")
    table tcpportmapping {
        key = {
            meta.tcpportmap_oid : exact @name("meta.tcpportmap_oid:tcpportmap_oid");
            meta.src_l4_port : range @name("meta.src_l4_port:src_l4_port");
            meta.dst_l4_port : range @name("meta.dst_l4_port:dst_l4_port");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @name("outbound_udpportmapping|dash_outbound_udpportmapping")
    table udpportmapping {
        key = {
            meta.udpportmap_oid : exact @name("meta.udpportmap_oid:udpportmap_oid");
            meta.src_l4_port : range @name("meta.src_l4_port:src_l4_port");
            meta.dst_l4_port : range @name("meta.dst_l4_port:dst_l4_port");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    apply {
        meta.transit_to = MATCH_START;
        //TODO: temporary, should be generic per object model
        meta.pipeline_oid = meta.eni_id;
        meta.use_src = false;
        meta.lkp_addr_is_v6 = meta.is_overlay_ip_v6;
        if (meta.use_src) {
            meta.lkp_addr = meta.src_ip_addr;
        } else {
            meta.lkp_addr = meta.dst_ip_addr;
        }

#define DO_MATCH_ROUTING(n) \
        if (meta.transit_to == MATCH_ROUTING##n) {  \
            routing##n.apply();  \
        }

        DO_MATCH_ROUTING(0)
        DO_MATCH_ROUTING(1)

#define DO_MATCH_IPMAPPING(n) \
        if (meta.transit_to == MATCH_IPMAPPING##n) {  \
            ipmapping##n.apply();  \
        }

        DO_MATCH_IPMAPPING(0)
        DO_MATCH_IPMAPPING(1)

        if (meta.transit_to == MATCH_TCPPORTMAPPING) {
            tcpportmapping.apply();
        } else if (meta.transit_to == MATCH_UDPPORTMAPPING) {
            udpportmapping.apply();
        }

        // Apply route actions
        // FIXME: action order ??
        // tcp/udp -- overlay_ip -- overlay_ether -- underlay .... ??
        if (meta.routing_type & ACTION_STATICENCAP) {
            do_staticencap();
        }
        if (meta.routing_type & ACTION_TUNNEL) {
            do_tunnel();
        }
        if (meta.routing_type & ACTION_4to6) {
            do_4to6();
        }

        if (meta.routing_type & ACTION_NAT) {
            do_nat(meta.encap_data.overlay_sip,
                   meta.encap_data.overlay_dip,
                   meta.encap_data.nat_src_port,
                   meta.encap_data.nat_dst_port,
                   // FIXME: nat_sport/dport base
                   meta.src_l4_port,
                   meta.dst_l4_port);
        }
    }
}


#endif /* _SIRIUS_OUTBOUND_P4_ */
