#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"
#include "dash_service_tunnel.p4"

control outbound(inout headers_t hdr,
                 inout metadata_t meta)
{
    action set_route_meter_attrs(bit<1> meter_policy_en,
                                 bit<16> meter_class) {
        meta.meter_policy_en = meter_policy_en;
        meta.route_meter_class = meter_class;
    }
    action route_vnet(bit<16> dst_vnet_id,
                      bit<1> meter_policy_en,
                      bit<16> meter_class) {
        meta.dst_vnet_id = dst_vnet_id;
        meta.lkup_dst_ip_addr = meta.dst_ip_addr;
        meta.is_lkup_dst_ip_v6 = meta.is_overlay_ip_v6;
        set_route_meter_attrs(meter_policy_en, meter_class);

        meta.routing_type = dash_routing_type_t.VNET;
        routing_eval.apply();
    }

    action route_vnet_direct(bit<16> dst_vnet_id,
                             bit<1> is_overlay_ip_v4_or_v6,
                             IPv4ORv6Address overlay_ip,
                             bit<1> meter_policy_en,
                             bit<16> meter_class) {
        meta.dst_vnet_id = dst_vnet_id;
        meta.lkup_dst_ip_addr = overlay_ip;
        meta.is_lkup_dst_ip_v6 = is_overlay_ip_v4_or_v6;
        set_route_meter_attrs(meter_policy_en, meter_class);

        meta.routing_type = dash_routing_type_t.VNET_DIRECT;
        routing_eval.apply();
    }

    action route_direct(bit<1> meter_policy_en,
                        bit<16> meter_class) {
        set_route_meter_attrs(meter_policy_en, meter_class);

        meta.routing_type = dash_routing_type_t.DIRECT;
        routing_eval.apply();
    }

    action drop() {
        meta.dropped = true;
    }

    action route_service_tunnel(bit<1> is_overlay_dip_v4_or_v6,
                                IPv4ORv6Address overlay_dip,
                                bit<1> is_overlay_dip_mask_v4_or_v6,
                                IPv4ORv6Address overlay_dip_mask,
                                bit<1> is_overlay_sip_v4_or_v6,
                                IPv4ORv6Address overlay_sip,
                                bit<1> is_overlay_sip_mask_v4_or_v6,
                                IPv4ORv6Address overlay_sip_mask,
                                bit<1> is_underlay_dip_v4_or_v6,
                                IPv4ORv6Address underlay_dip,
                                bit<1> is_underlay_sip_v4_or_v6,
                                IPv4ORv6Address underlay_sip,
                                dash_encapsulation_t dash_encapsulation,
                                bit<24> tunnel_key,
                                bit<1> meter_policy_en,
                                bit<16> meter_class) {
        /* Assume the overlay addresses provided are always IPv6 and the original are IPv4 */
        /* assert(is_overlay_dip_v4_or_v6 == 1 && is_overlay_sip_v4_or_v6 == 1);
        assert(is_overlay_dip_mask_v4_or_v6 == 1 && is_overlay_sip_mask_v4_or_v6 == 1);
        assert(is_underlay_dip_v4_or_v6 != 1 && is_underlay_sip_v4_or_v6 != 1); */
        meta.encap_data.original_overlay_dip = hdr.ipv4.src_addr;
        meta.encap_data.original_overlay_sip = hdr.ipv4.dst_addr;

        meta.encap_data.st_dst = overlay_dip;
        meta.encap_data.st_dst_mask = overlay_dip_mask;
        meta.encap_data.st_src = overlay_sip;
        meta.encap_data.st_src_mask = overlay_sip_mask;

        /* encapsulation will be done in apply block based on dash_encapsulation */
        meta.encap_data.underlay_dip = underlay_dip == 0 ? meta.encap_data.original_overlay_dip : (IPv4Address)underlay_dip;
        meta.encap_data.underlay_sip = underlay_sip == 0 ? meta.encap_data.original_overlay_sip : (IPv4Address)underlay_sip;
        meta.encap_data.overlay_dmac = hdr.ethernet.dst_addr;
        meta.encap_data.dash_encapsulation = dash_encapsulation;
        meta.encap_data.service_tunnel_key = tunnel_key;
        set_route_meter_attrs(meter_policy_en, meter_class);

        meta.routing_type = dash_routing_type_t.SERVICETUNNEL;
        routing_eval.apply();
    }

#ifdef TARGET_BMV2_V1MODEL

    direct_counter(CounterType.packets_and_bytes) routing_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
    // See the #ifdef with same preprocessor symbol in dash_pipeline.p4
    DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) routing_counter;
#endif  // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif  // TARGET_DPDK_PNA

    @name("outbound_routing|dash_outbound_routing")
    table routing {
        key = {
            meta.eni_id : exact @name("meta.eni_id:eni_id");
            meta.is_overlay_ip_v6 : exact @name("meta.is_overlay_ip_v6:is_destination_v4_or_v6");
            meta.dst_ip_addr : lpm @name("meta.dst_ip_addr:destination");
        }

        actions = {
            route_vnet; /* for expressroute - ecmp of overlay */
            route_vnet_direct;
            route_direct;
            route_service_tunnel;
            drop;
        }
        const default_action = drop;

#ifdef TARGET_BMV2_V1MODEL
        counters = routing_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
        pna_direct_counter = routing_counter;
#endif // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif // TARGET_DPDK_PNA
    }

    action route_vnet_encap(IPv4Address underlay_dip,
                              EthernetAddress overlay_dmac,
                              bit<1> use_dst_vnet_vni,
                              bit<16> meter_class,
                              bit<1> meter_class_override) {
        if (use_dst_vnet_vni == 1)
            meta.vnet_id = meta.dst_vnet_id;
        meta.encap_data.overlay_dmac = overlay_dmac;
        meta.encap_data.underlay_dip = underlay_dip;
        meta.mapping_meter_class = meter_class;
        meta.mapping_meter_class_override = meter_class_override;

        meta.routing_type = dash_routing_type_t.VNET_ENCAP;
        routing_eval.apply();
    }

    action route_privatelink(IPv4Address underlay_ip,
                              EthernetAddress mac_address,
                              IPv6Address overlay_sip,
                              IPv6Address overlay_dip,
                              bit<16> meter_class,
                              bit<1> meter_class_override) {

        meta.encap_data.overlay_dmac = mac_address;
        meta.encap_data.overlay_dip = overlay_dip;
        meta.encap_data.overlay_sip = overlay_sip;

        meta.encap_data.underlay_dmac = mac_address;
        meta.encap_data.underlay_dip = underlay_ip;

        meta.mapping_meter_class = meter_class;
        meta.mapping_meter_class_override = meter_class_override;

        meta.routing_type = dash_routing_type_t.PRIVATELINK;
        routing_eval.apply();
    }

    action route_privatelinknsg(IPv4Address underlay_ip,
                              EthernetAddress mac_address,
                              IPv6Address overlay_sip,
                              IPv6Address overlay_dip,
                              bit<16> appliance_id,
                              bit<16> meter_class,
                              bit<1> meter_class_override) {
        meta.encap_data.overlay_dmac = mac_address;
        meta.encap_data.overlay_dip = overlay_dip;
        meta.encap_data.overlay_sip = overlay_sip;

        meta.encap_data.underlay_dmac = mac_address;
        meta.encap_data.underlay_dip = underlay_ip;

        meta.routing_appliance_id = appliance_id;

        meta.mapping_meter_class = meter_class;
        meta.mapping_meter_class_override = meter_class_override;

        meta.routing_type = dash_routing_type_t.PRIVATELINKNSG;
        routing_eval.apply();
    }

    action route_privatelinkmap(IPv4Address underlay_ip,
                              EthernetAddress mac_address,
                              IPv6Address overlay_sip,
                              IPv6Address overlay_dip,
                              bit<16> port_mapping_id,
                              bit<16> meter_class,
                              bit<1> meter_class_override) {
        meta.encap_data.overlay_dmac = mac_address;
        meta.encap_data.overlay_dip = overlay_dip;
        meta.encap_data.overlay_sip = overlay_sip;

        meta.encap_data.underlay_dmac = mac_address;
        meta.encap_data.underlay_dip = underlay_ip;

        meta.routing_port_mapping_id = port_mapping_id;

        meta.mapping_meter_class = meter_class;
        meta.mapping_meter_class_override = meter_class_override;

        meta.routing_type = dash_routing_type_t.PRIVATELINKMAP;
        routing_eval.apply();
>>>>>>> Routing type modeling
    }

#ifdef TARGET_BMV2_V1MODEL
    direct_counter(CounterType.packets_and_bytes) vnet_mapping_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
    DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) vnet_mapping_counter;
#endif  // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif  // TARGET_DPDK_PNA

    @name("outbound_routing|dash_outbound_vnet_mapping")
    table vnet_mapping {
        key = {
            /* Flow for express route */
            meta.dst_vnet_id: exact @name("meta.dst_vnet_id:dst_vnet_id");
            meta.is_lkup_dst_ip_v6 : exact @name("meta.is_lkup_dst_ip_v6:is_dip_v4_or_v6");
            meta.lkup_dst_ip_addr : exact @name("meta.lkup_dst_ip_addr:dip");
        }

        actions = {
            route_vnet_encap;
            route_privatelink;
            route_privatelinknsg;
            route_privatelinkmap;
            @defaultonly drop;
        }
        const default_action = drop;

#ifdef TARGET_BMV2_V1MODEL
        counters = vnet_mapping_counter;
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
        pna_direct_counter = vnet_mapping_counter;
#endif // DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#endif // TARGET_DPDK_PNA
    }

    action set_vnet_attrs(bit<24> vni) {
        meta.encap_data.vni = vni;
    }

    @name("vnet|dash_vnet")
    table vnet {
        key = {
            meta.vnet_id : exact @name("meta.vnet_id:vnet_id");
        }

        actions = {
            set_vnet_attrs;
        }
    }

    action route_privatelinknat(IPv4Address underlay_ip,
                              EthernetAddress mac_address,
                              bit<16> src_port_min,
                              bit<16> src_port_max,
                              bit<16> dst_port_min,
                              bit<16> dst_port_max,
                              IPv6Address _4to6_dip_encoding,
                              bit<16> nat_dport
                              ) {
        meta.encap_data.overlay_dmac = mac_address;
        meta.encap_data.underlay_dmac = mac_address;
        meta.encap_data.underlay_dip = underlay_ip;

        meta.routing_type = dash_routing_type_t.PRIVATELINKNAT;
        routing_eval.apply();
    }

    @name("outbound_routing|dash_outbound_pl_port_mapping")
    table pl_port_mapping {
        key = {
            meta.routing_port_mapping_id: exact @name("meta.routing_port_mapping_id:routing_port_mapping_id");
        }

        actions = {
            route_privatelinknat;
            @defaultonly drop;
        }
        const default_action = drop;
    }

    /*
     * a list of route actions, doing packet transformation
     */
    action do_vnet_mapping() {
        vnet_mapping.apply();
    }

    action do_staticencap(bit<24> vni) {
        if (meta.encap_data.dash_encapsulation == dash_encapsulation_t.VXLAN) {
            vxlan_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        vni);
        } else if (meta.encap_data.dash_encapsulation == dash_encapsulation_t.NVGRE) {
            nvgre_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        vni);
        } else {
            drop();
        }
    }

    action do_4to6() {
        service_tunnel_encode(hdr,
                              meta.encap_data.st_dst,
                              meta.encap_data.st_dst_mask,
                              meta.encap_data.st_src,
                              meta.encap_data.st_src_mask);
    }

    action do_tunnel() {
    }

    action do_nat() {
    }

    action do_pl_port_mapping() {
        pl_port_mapping.apply();
    }


    /*
     * a list of routing type eval actions
     */
    action routing_eval_direct() {
        /* nothing for overlay */
        /* send to underlay router directly */
    }

    action routing_eval_vnet() {
        do_vnet_mapping();
    }

    action routing_eval_vnet_direct() {
        do_vnet_mapping();
    }

    action routing_eval_vnet_encap() {
        vnet.apply();
        do_staticencap(meta.encap_data.vni);
    }

    action routing_eval_servicetunnel() {
        do_4to6();
        do_staticencap(meta.encap_data.service_tunnel_key);
    }

    action routing_eval_privatelink() {
        do_4to6();
        do_staticencap(meta.encap_data.vni);
    }

    action routing_eval_privatelinknsg() {
        do_4to6();
        do_staticencap(meta.encap_data.vni);
        do_tunnel();
    }

    action routing_eval_privatelinkmap() {
        do_pl_port_mapping();
    }

    action routing_eval_privatelinknat() {
        do_4to6();
        do_nat();
        do_staticencap(meta.encap_data.vni);
    }

    @name("outbound_routing|dash_outbound_routing_eval")
    table routing_eval {
        key = {
            meta.routing_type : exact @name("meta.routing_type:routing_type");
        }

        actions = {
            routing_eval_direct;
            routing_eval_vnet;
            routing_eval_vnet_direct;
            routing_eval_vnet_encap;
            routing_eval_servicetunnel;
            routing_eval_privatelink;
            routing_eval_privatelinknsg;
            routing_eval_privatelinkmap;
            routing_eval_privatelinknat;
        }
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

        routing.apply();
    }
}

#endif /* _SIRIUS_OUTBOUND_P4_ */
