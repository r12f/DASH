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

    bit<1> is_overlay_ip_v6;
    IPv4ORv6Address overlay_sip;
    IPv4ORv6Address overlay_dip;
    EthernetAddress overlay_smac;
    EthernetAddress overlay_dmac;

    bit<16> nat_sport;
    bit<16> nat_dport;
    bit<16> nat_sport_base;
    bit<16> nat_dport_base;

    dash_encapsulation_t encap_type;
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

typedef bit<32> dash_routing_type_t;
#define ACTION_STATICENCAP      (1<<0)
#define ACTION_TUNNEL           (1<<1)
#define ACTION_4to6             (1<<2)
#define ACTION_6to4             (1<<3)
#define ACTION_NAT              (1<<4)
#define ACTION_REVERSE_TUNNEL   (1<<5)
#define ACTION_TUNNEL_FROM_ENCAP    (1<<6)

typedef bit<32> dash_oid_t;

enum bit<8> dash_match_stage_t {
    MATCH_END            = 0,
    MATCH_START          = 1,
    MATCH_ROUTING0       = 1,
    MATCH_ROUTING1       = 2,
    MATCH_IPMAPPING0     = 3,
    MATCH_IPMAPPING1     = 4,
    MATCH_TCPPORTMAPPING = 5,
    MATCH_UDPPORTMAPPING = 6
}

typedef bit<16> nexthop_t;

typedef bit<8> dash_tunnel_target_t;
#define TUNNEL_UNDERLAY0 1
#define TUNNEL_UNDERLAY1 2

typedef bit<16> dash_tunnel_id_t;

struct metadata_t {
    bool dropped;
    dash_direction_t direction;
    dash_routing_type_t routing_type;
    encap_data_t encap_data;
    EthernetAddress eni_addr;
    bit<16> vnet_id;
    bit<16> dst_vnet_id;
    bit<16> eni_id;
    eni_data_t eni_data;
    bit<16> inbound_vm_id;
    bit<8> appliance_id;
    bit<1> is_overlay_ip_v6;
    bit<8> ip_protocol;
    IPv4ORv6Address dst_ip_addr;
    IPv4ORv6Address src_ip_addr;
    bit<1> lookup_addr_is_v6;
    IPv4ORv6Address lookup_addr;
    bool use_src;
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


    dash_match_stage_t transit_to;
    nexthop_t nexthop;
    dash_oid_t mapping_oid;
    dash_oid_t pipeline_oid;
    dash_oid_t tcpportmap_oid;
    dash_oid_t udpportmap_oid;

    dash_tunnel_target_t tunnel_source;
    dash_tunnel_target_t tunnel_target;
    dash_tunnel_id_t tunnel_underlay0_id;
    dash_tunnel_id_t tunnel_underlay1_id;

	bit<128> sip_4to6_encoding_value;
	bit<128> sip_4to6_encoding_mask;
	bit<128> dip_4to6_encoding_value;
	bit<128> dip_4to6_encoding_mask;

	bit<32> sip_6to4_encoding_value;
	bit<32> sip_6to4_encoding_mask;
	bit<32> dip_6to4_encoding_value;
	bit<32> dip_6to4_encoding_mask;
}

#endif /* _SIRIUS_METADATA_P4_ */
