#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"
#include "dash_service_tunnel.p4"


typedef bit<8> MatchStage;
#define MATCH_END           0
#define MATCH_START         1
#define MATCH_ROUTING0      1
#define MATCH_ROUTING1      2
#define MATCH_IPMAPPING0    3
#define MATCH_IPMAPPING1    4
#define MATCH_TCPPORTMAPPING   5
#define MATCH_UDPPORTMAPPING   6

typedef bit<16> Nexthop;
typedef bit<32> Oid;

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

    action do_nat() {
    }

    action outbound_metadata_publish(MatchStage next_stage,
                                     bit<16> routing_type,
                                     Nexthop nexthop,
                                     Oid mapping_oid,
                                     Oid pipeline_oid,
                                     Oid tcpportmap_oid,
                                     Oid udpportmap_oid,
                                     bit<16> src_port,
                                     bit<16> dst_port,
                                     IPv4Address     overlay_sip,
                                     IPv4Address     overlay_dip,
                                     EthernetAddress overlay_smac,
                                     EthernetAddress overlay_dmac,
                                     dash_encapsulation_t encap_type,
                                     bit<24> vni,
                                     IPv4Address     underlay_sip,
                                     IPv4Address     underlay_dip,
                                     EthernetAddress underlay_smac,
                                     EthernetAddress underlay_dmac
                                    ) {
        meta.transit_to = next_stage;
        if (next_stage == MATCH_END) {
            meta.routing_type = routing_type;
        }
        meta.nexthop = nexthop;

        meta.mapping_oid = mapping_oid != 0 ? mapping_oid : meta.mapping_oid;
        meta.pipeline_oid = pipeline_oid != 0 ? pipeline_oid : meta.pipeline_oid;
        meta.tcpportmap_oid = tcpportmap_oid != 0 ? tcpportmap_oid : meta.tcpportmap_oid;
        meta.udpportmap_oid = udpportmap_oid != 0 ? udpportmap_oid : meta.udpportmap_oid;

        meta.src_port = src_port != 0 ? src_port : meta.src_port;
        meta.dst_port = dst_port != 0 ? dst_port : meta.dst_port;

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
            meta.oid : exact @name("meta.oid:oid");
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
            meta.oid : exact @name("meta.oid:oid");
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
            meta.tcp_src_port : range @name("meta.tcp_src_port:tcp_src_port");
            meta.tcp_dst_port : range @name("meta.tcp_dst_port:tcp_dst_port");
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
            meta.udp_src_port : range @name("meta.udp_src_port:udp_src_port");
            meta.udp_dst_port : range @name("meta.udp_dst_port:udp_dst_port");
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    apply {

#define DO_MATCH_ROUTING(n) \
        if (meta.transit_to == MATCH_ROUTING##n) {  \
            if (meta.use_src) {  \
                meta.lkp_addr = meta.key_metadata.src_addr;  \
            } else {  \
                meta.lkp_addr = meta.key_metadata.dst_addr;  \
            }  \
            meta.old = meta.pipeline_oid; \
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
        if (meta.routing_type & ACTION_STATICENCAP) {
            do_staticencap();
        }
        if (meta.routing_type & ACTION_TUNNEL) {
            do_tunnel();
        }
        if (meta.routing_type & ACTION_4to6) {
            do_4to6();
        }
    }
}


#endif /* _SIRIUS_OUTBOUND_P4_ */
