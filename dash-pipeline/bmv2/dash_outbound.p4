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
        meta.pkt_meta.dropped = true;
    }

    action outbound_metadata_publish(dash_match_stage_t next_stage,
                                     dash_routing_type_t routing_type,
                                     @SaiVal[type="sai_object_id_t"] dash_oid_t pipeline_oid,
                                     @SaiVal[type="sai_object_id_t"] dash_oid_t mapping_oid,
                                     @SaiVal[type="sai_object_id_t"] dash_oid_t tcpportmap_oid,
                                     @SaiVal[type="sai_object_id_t"] dash_oid_t udpportmap_oid,
                                     bit<1> lookup_addr_is_v6,
                                     IPv4ORv6Address lookup_addr,
                                     dash_tunnel_target_t tunnel_source,
                                     dash_tunnel_target_t tunnel_target,
                                     dash_tunnel_id_t tunnel_underlay0_id,
                                     dash_tunnel_id_t tunnel_underlay1_id,
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
                                     bit<1> is_nat_ip_v6,
                                     IPv4ORv6Address nat_sip,
                                     IPv4ORv6Address nat_dip,
                                     EthernetAddress nat_smac,
                                     EthernetAddress nat_dmac,
                                     @SaiVal[type="sai_dash_encapsulation_t", default_value="SAI_DASH_ENCAPSULATION_VXLAN"]
                                     dash_encapsulation_t tunnel_type,
                                     bit<24> encap_vni,
                                     IPv4Address     tunnel_sip,
                                     IPv4Address     tunnel_dip,
                                     EthernetAddress tunnel_smac,
                                     EthernetAddress tunnel_dmac
                                    ) {
        meta.transit_to = next_stage;
        meta.routing_type = meta.routing_type | routing_type;

        meta.pipeline_oid = pipeline_oid != 0 ? pipeline_oid : meta.pipeline_oid;
        meta.mapping_oid = mapping_oid != 0 ? mapping_oid : meta.mapping_oid;
        meta.tcpportmap_oid = tcpportmap_oid != 0 ? tcpportmap_oid : meta.tcpportmap_oid;
        meta.udpportmap_oid = udpportmap_oid != 0 ? udpportmap_oid : meta.udpportmap_oid;

        meta.pkt_meta.lookup_addr = lookup_addr != 0 ? lookup_addr : meta.pkt_meta.lookup_addr;
        meta.pkt_meta.lookup_addr_is_v6 = lookup_addr_is_v6 != 0 ? lookup_addr_is_v6 : meta.pkt_meta.lookup_addr_is_v6;

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

        meta.nat.nat_sport = nat_sport != 0 ? nat_sport : meta.nat.nat_sport;
        meta.nat.nat_dport = nat_dport != 0 ? nat_dport : meta.nat.nat_dport;
        meta.nat.nat_sport_base = nat_sport_base != 0 ? nat_sport_base : meta.nat.nat_sport_base;
        meta.nat.nat_dport_base = nat_dport_base != 0 ? nat_dport_base : meta.nat.nat_dport_base;

        meta.nat.is_ipv6 = is_nat_ip_v6 != 0 ? is_nat_ip_v6 : meta.nat.is_ipv6;
        meta.nat.nat_sip = nat_sip != 0 ? nat_sip : meta.nat.nat_sip;
        meta.nat.nat_dip = nat_dip != 0 ? nat_dip : meta.nat.nat_dip;
        meta.nat.nat_smac = nat_smac != 0 ? nat_smac : meta.nat.nat_smac;
        meta.nat.nat_dmac = nat_dmac != 0 ? nat_dmac : meta.nat.nat_dmac;

        meta.tunnel_0.tunnel_type = tunnel_type != 0 ? tunnel_type : meta.tunnel_0.tunnel_type;
        meta.tunnel_0.tunnel_vni = encap_vni != 0 ? encap_vni : meta.tunnel_0.tunnel_vni;

        meta.tunnel_0.tunnel_sip = tunnel_sip != 0 ? tunnel_sip : meta.tunnel_0.tunnel_sip;
        meta.tunnel_0.tunnel_dip = tunnel_dip != 0 ? tunnel_dip : meta.tunnel_0.tunnel_dip;
        meta.tunnel_0.tunnel_smac = tunnel_smac != 0 ? tunnel_smac : meta.tunnel_0.tunnel_smac;
        meta.tunnel_0.tunnel_dmac = tunnel_dmac != 0 ? tunnel_dmac : meta.tunnel_0.tunnel_dmac;
    }

    @SaiTable[name = "outbound_routing", stage = "routing0", api = "dash_outbound_routing"]
    table routing0 {
        key = {
            meta.pipeline_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.pkt_meta.lookup_addr_is_v6 : exact;
            meta.pkt_meta.lookup_addr : lpm;
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @SaiTable[name = "outbound_routing", stage = "routing1", api = "dash_outbound_routing"]
    table routing1 {
        key = {
            meta.pipeline_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.pkt_meta.lookup_addr_is_v6 : exact;
            meta.pkt_meta.lookup_addr : lpm;
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @SaiTable[name = "outbound_ca_to_pa", stage = "ipmapping0", api = "dash_outbound_ca_to_pa"]
    table ipmapping0 {
        key = {
            meta.mapping_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.pkt_meta.lookup_addr_is_v6 : exact;
            meta.pkt_meta.lookup_addr : exact;
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @SaiTable[name = "outbound_ca_to_pa", stage = "ipmapping1", api = "dash_outbound_ca_to_pa"]
    table ipmapping1 {
        key = {
            meta.mapping_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.pkt_meta.lookup_addr_is_v6 : exact;
            meta.pkt_meta.lookup_addr : exact;
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @SaiTable[name = "outbound_tcpportmapping", api = "dash_outbound_tcpportmapping"]
    table tcpportmapping {
        key = {
            meta.tcpportmap_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.flow.sport : range;
            meta.flow.dport : range;
        }

        actions = {
            outbound_metadata_publish;
            drop;
        }
        const default_action = drop;
    }

    @SaiTable[name = "outbound_udpportmapping", api = "dash_outbound_udppportmapping"]
    table udpportmapping {
        key = {
            meta.udpportmap_oid : exact @SaiVal[type = "sai_object_id_t"];
            meta.flow.sport : range;
            meta.flow.dport : range;
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

        meta.transit_to = dash_match_stage_t.MATCH_START;
        //TODO: temporary, should be generic per object model
        meta.pkt_meta.use_src = false;
        meta.pkt_meta.lookup_addr_is_v6 = meta.flow.is_ipv6;
        if (meta.pkt_meta.use_src) {
            meta.pkt_meta.lookup_addr = meta.flow.sip;
        } else {
            meta.pkt_meta.lookup_addr = meta.flow.dip;
        }

#define DO_MATCH_ROUTING(n) \
        if (meta.transit_to == dash_match_stage_t.MATCH_ROUTING##n) {  \
            routing##n.apply();  \
        }

        DO_MATCH_ROUTING(0)
        DO_MATCH_ROUTING(1)

#define DO_MATCH_IPMAPPING(n) \
        if (meta.transit_to == dash_match_stage_t.MATCH_IPMAPPING##n) {  \
            ipmapping##n.apply();  \
        }

        DO_MATCH_IPMAPPING(0)
        DO_MATCH_IPMAPPING(1)

        if (meta.transit_to == dash_match_stage_t.MATCH_TCPPORTMAPPING) {
            tcpportmapping.apply();
        } else if (meta.transit_to == dash_match_stage_t.MATCH_UDPPORTMAPPING) {
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
