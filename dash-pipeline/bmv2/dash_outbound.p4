#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"
#include "dash_service_tunnel.p4"
#include "dash_routeaction.p4"


control outbound(inout headers_t hdr,
                 inout metadata_t meta)
{
    action drop() {
        meta.dropped = true;
    }

    action outbound_metadata_publish(DashMatchStage_t next_stage,
                                     DashRoutingType_t routing_type,
                                     Nexthop_t nexthop,
                                     DashOid_t pipeline_oid,
                                     DashOid_t mapping_oid,
                                     DashOid_t tcpportmap_oid,
                                     DashOid_t udpportmap_oid,
                                     bit<1> lookup_addr_is_v6,
                                     IPv4ORv6Address lookup_addr,
                                     DashTunnelTarget_t tunnel_source,
                                     DashTunnelTarget_t tunnel_target,
                                     DashTunnelId_t tunnel_underlay0_id,
                                     DashTunnelId_t tunnel_underlay1_id,
                                     bit<16> nat_sport,
                                     bit<16> nat_dport,
                                     bit<16> nat_sport_base,
                                     bit<16> nat_dport_base,
                                     bit<128> sip_4to6_encoding_value,
                                     bit<128> sip_4to6_encoding_mask,
                                     bit<128> dip_4to6_encoding_value,
                                     bit<128> dip_4to6_encoding_mask,
                                     bit<32> sip_6to4_encoding_value,
                                     bit<32> sip_6to4_encoding_mask,
                                     bit<32> dip_6to4_encoding_value,
                                     bit<32> dip_6to4_encoding_mask,
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

        meta.lookup_addr = lookup_addr != 0 ? lookup_addr : meta.lookup_addr;
        meta.lookup_addr_is_v6 = lookup_addr_is_v6 != 0 ? lookup_addr_is_v6 : meta.lookup_addr_is_v6;

        meta.tunnel_source = tunnel_source != 0 ? tunnel_source : meta.tunnel_source;
        meta.tunnel_target = tunnel_target != 0 ? tunnel_target : meta.tunnel_target;
        meta.tunnel_underlay0_id = tunnel_underlay0_id != 0 ? tunnel_underlay0_id : meta.tunnel_underlay0_id;
        meta.tunnel_underlay1_id = tunnel_underlay1_id != 0 ? tunnel_underlay1_id : meta.tunnel_underlay1_id;

        meta.sip_4to6_encoding_value = (meta.sip_4to6_encoding_value & ~sip_4to6_encoding_mask) | sip_4to6_encoding_value;
        meta.sip_4to6_encoding_mask = meta.sip_4to6_encoding_mask | sip_4to6_encoding_mask;
        meta.dip_4to6_encoding_value = (meta.dip_4to6_encoding_value & ~dip_4to6_encoding_mask) | dip_4to6_encoding_value;
        meta.dip_4to6_encoding_mask = meta.dip_4to6_encoding_mask | dip_4to6_encoding_mask;

        meta.sip_6to4_encoding_value = (meta.sip_6to4_encoding_value & ~sip_6to4_encoding_mask) | sip_6to4_encoding_value;
        meta.sip_6to4_encoding_mask = meta.sip_6to4_encoding_mask | sip_6to4_encoding_mask;
        meta.dip_6to4_encoding_value = (meta.dip_6to4_encoding_value & ~dip_6to4_encoding_mask) | dip_6to4_encoding_value;
        meta.dip_6to4_encoding_mask = meta.dip_6to4_encoding_mask | dip_6to4_encoding_mask;

        meta.encap_data.nat_sport = nat_sport != 0 ? nat_sport : meta.encap_data.nat_sport;
        meta.encap_data.nat_dport = nat_dport != 0 ? nat_dport : meta.encap_data.nat_dport;
        meta.encap_data.nat_sport_base = nat_sport_base != 0 ? nat_sport_base : meta.encap_data.nat_sport_base;
        meta.encap_data.nat_dport_base = nat_dport_base != 0 ? nat_dport_base : meta.encap_data.nat_dport_base;

        meta.encap_data.is_overlay_ip_v6 = is_overlay_ip_v6 != 0 ? is_overlay_ip_v6 : meta.encap_data.is_overlay_ip_v6;
        meta.encap_data.overlay_sip = overlay_sip != 0 ? overlay_sip : meta.encap_data.overlay_sip;
        meta.encap_data.overlay_dip = overlay_dip != 0 ? overlay_dip : meta.encap_data.overlay_dip;
        meta.encap_data.overlay_smac = overlay_smac != 0 ? overlay_smac : meta.encap_data.overlay_smac;
        meta.encap_data.overlay_dmac = overlay_dmac != 0 ? overlay_dmac : meta.encap_data.overlay_dmac;

        meta.encap_data.encap_type = encap_type != 0 ? encap_type : meta.encap_data.encap_type;
        meta.encap_data.vni = encap_vni != 0 ? encap_vni : meta.encap_data.vni;

        meta.encap_data.underlay_sip = underlay_sip != 0 ? underlay_sip : meta.encap_data.underlay_sip;
        meta.encap_data.underlay_dip = underlay_dip != 0 ? underlay_dip : meta.encap_data.underlay_dip;
        meta.encap_data.underlay_smac = underlay_smac != 0 ? underlay_smac : meta.encap_data.underlay_smac;
        meta.encap_data.underlay_dmac = underlay_dmac != 0 ? underlay_dmac : meta.encap_data.underlay_dmac;
    }

    @name("outbound_routing|dash_outbound_routing0")
    table routing0 {
        key = {
            meta.pipeline_oid : exact @name("meta.pipeline_oid:pipeline_oid");
            meta.lookup_addr_is_v6 : exact @name("meta.lookup_addr_is_v6:lookup_addr_is_v6");
            meta.lookup_addr : lpm @name("meta.lookup_addr:lookup_addr");
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
            meta.lookup_addr_is_v6 : exact @name("meta.lookup_addr_is_v6:lookup_addr_is_v6");
            meta.lookup_addr : lpm @name("meta.lookup_addr:lookup_addr");
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
            meta.lookup_addr_is_v6 : exact @name("meta.lookup_addr_is_v6:lookup_addr_is_v6");
            meta.lookup_addr : exact @name("meta.lookup_addr:lookup_addr");
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
            meta.lookup_addr_is_v6 : exact @name("meta.lookup_addr_is_v6:lookup_addr_is_v6");
            meta.lookup_addr : exact @name("meta.lookup_addr:lookup_addr");
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
#ifdef STATEFUL_P4
           ConntrackOut.apply(0);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackOut.apply(hdr, meta);
#endif // PNA_CONNTRACK

        /* ACL */
        if (!meta.conntrack_data.allow_out) {
            acl.apply(hdr, meta);
        }

#ifdef STATEFUL_P4
            ConntrackIn.apply(1);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK

        meta.transit_to = DashMatchStage_t.MATCH_START;
        //TODO: temporary, should be generic per object model
        meta.pipeline_oid = (DashOid_t)meta.eni_id;
        meta.use_src = false;
        meta.lookup_addr_is_v6 = meta.is_overlay_ip_v6;
        if (meta.use_src) {
            meta.lookup_addr = meta.src_ip_addr;
        } else {
            meta.lookup_addr = meta.dst_ip_addr;
        }

#define DO_MATCH_ROUTING(n) \
        if (meta.transit_to == DashMatchStage_t.MATCH_ROUTING##n) {  \
            routing##n.apply();  \
        }

        DO_MATCH_ROUTING(0)
        DO_MATCH_ROUTING(1)

#define DO_MATCH_IPMAPPING(n) \
        if (meta.transit_to == DashMatchStage_t.MATCH_IPMAPPING##n) {  \
            ipmapping##n.apply();  \
        }

        DO_MATCH_IPMAPPING(0)
        DO_MATCH_IPMAPPING(1)

        if (meta.transit_to == DashMatchStage_t.MATCH_TCPPORTMAPPING) {
            tcpportmapping.apply();
        } else if (meta.transit_to == DashMatchStage_t.MATCH_UDPPORTMAPPING) {
            udpportmapping.apply();
        }

        // Apply route actions
        // FIXME: action order ??
        // tcp/udp -- overlay_ip -- overlay_ether -- underlay .... ??
        if ((meta.routing_type & ACTION_STATICENCAP) != 0) {
            action_staticencap.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_TUNNEL) != 0) {
            action_tunnel.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_REVERSE_TUNNEL) != 0) {
            action_reverse_tunnel.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_TUNNEL_FROM_ENCAP) != 0) {
            action_tunnel_from_encap.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_4to6) != 0) {
            action_4to6.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_6to4) != 0) {
            action_6to4.apply(hdr, meta);
        }

        if ((meta.routing_type & ACTION_NAT) != 0) {
            action_nat.apply(hdr, meta);
        }
    }
}


#endif /* _SIRIUS_OUTBOUND_P4_ */
