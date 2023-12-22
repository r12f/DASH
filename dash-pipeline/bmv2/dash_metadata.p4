#ifndef _SIRIUS_METADATA_P4_
#define _SIRIUS_METADATA_P4_

#include "dash_headers.p4"

struct encap_data_t {
    bit<24> vni;
    bit<24> dest_vnet_vni;
    IPv4Address underlay_sip;
    IPv4Address underlay_dip;
    EthernetAddress underlay_smac;
    EthernetAddress underlay_dmac;
    EthernetAddress overlay_dmac;
    dash_encapsulation_t dash_encapsulation;
    bit<24> service_tunnel_key;
    IPv4Address original_overlay_sip;
    IPv4Address original_overlay_dip;
}

enum bit<16> dash_direction_t {
    INVALID = 0,
    OUTBOUND = 1,
    INBOUND = 2
}

struct conntrack_data_t {
    bool allow_in;
    bool allow_out;
}

struct eni_data_t {
    bit<32> cps;
    bit<32> pps;
    bit<32> flows;
    bit<1>  admin_state;
    IPv6Address pl_sip;
    IPv6Address pl_sip_mask;
    IPv4Address pl_underlay_sip;
}

enum bit<8> dash_ha_role_t {
    DASH_HA_ROLE_DEAD = 0,
    DASH_HA_ROLE_ACTIVE = 1,
    DASH_HA_ROLE_STANDBY = 2,
    DASH_HA_ROLE_STANDALONE = 3,
    DASH_HA_ROLE_SWITCHING_TO_ACTIVE = 4
};

struct metadata_t {
    bool dropped;
    dash_direction_t direction;
    encap_data_t encap_data;
    EthernetAddress eni_addr;
    bit<16> ha_set_id;
    dash_ha_role_t ha_role;
    bit<1> peer_ip_is_v6;
    IPv4ORv6Address peer_ip;
    bit<16> dp_channel_dst_port;
    bit<16> dp_channel_src_port_min;
    bit<16> dp_channel_src_port_max;
    bit<32> dp_channel_probe_interval_ms;
    bit<16> vnet_id;
    bit<16> dst_vnet_id;
    bit<16> eni_id;
    eni_data_t eni_data;
    bit<16> inbound_vm_id;
    bit<8> appliance_id;
    bit<1> is_overlay_ip_v6;
    bit<1> is_lkup_dst_ip_v6;
    bit<8> ip_protocol;
    IPv4ORv6Address dst_ip_addr;
    IPv4ORv6Address src_ip_addr;
    IPv4ORv6Address lkup_dst_ip_addr;
    conntrack_data_t conntrack_data;
    bit<16> src_l4_port;
    bit<16> dst_l4_port;
    bit<16> stage1_dash_acl_group_id;
    bit<16> stage2_dash_acl_group_id;
    bit<16> stage3_dash_acl_group_id;
    bit<16> stage4_dash_acl_group_id;
    bit<16> stage5_dash_acl_group_id;
    bit<1> meter_policy_en;
    bit<1> mapping_meter_class_override;
    bit<16> meter_policy_id;
    bit<16> policy_meter_class;
    bit<16> route_meter_class;
    bit<16> mapping_meter_class;
    bit<16> meter_class;
    bit<32> meter_bucket_index;
}

#endif /* _SIRIUS_METADATA_P4_ */
