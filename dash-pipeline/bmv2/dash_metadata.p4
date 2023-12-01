#ifndef _SIRIUS_METADATA_P4_
#define _SIRIUS_METADATA_P4_

#include "dash_headers.p4"

struct dash_tunnel_t {
    dash_encapsulation_t tunnel_type;
    bit<24> tunnel_vni;
    IPv4Address tunnel_sip;
    IPv4Address tunnel_dip;
    EthernetAddress tunnel_smac;
    EthernetAddress tunnel_dmac;
}

enum bit<16> dash_direction_t {
    INVALID = 0,
    OUTBOUND = 1,
    INBOUND = 2
}

struct conntrack_data_t {
    bool allow_in;
    bool allow_out;
    IPv4Address original_overlay_sip;
    IPv4Address original_overlay_dip;
}

struct eni_data_t {
    bit<32> cps;
    bit<32> pps;
    bit<32> flows;
    bit<1>  admin_state;
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

struct pkt_metadata_t {
    bool dropped;
    dash_direction_t direction;
    bool use_src;
    bit<1> lookup_addr_is_v6;
    IPv4ORv6Address lookup_addr;
}

struct dash_flow_t {
    // flow keys
    bit<8> proto;
    bit<1> is_ipv6;
    IPv4ORv6Address sip;
    IPv4ORv6Address dip;
    bit<16> sport;
    bit<16> dport;

    // flow states
}

struct dash_nat_t {
    bit<16> nat_sport;
    bit<16> nat_dport;
    bit<16> nat_sport_base;
    bit<16> nat_dport_base;
    bit<1> is_ipv6;
    IPv4ORv6Address nat_sip;
    IPv4ORv6Address nat_dip;
    EthernetAddress nat_smac;
    EthernetAddress nat_dmac;
}

struct metadata_t {
    pkt_metadata_t pkt_meta;
    dash_flow_t flow;
    dash_nat_t nat;
    dash_tunnel_t tunnel_0;
    dash_tunnel_t tunnel_1;

    EthernetAddress eni_addr;
    bit<16> vnet_id;
    bit<16> dst_vnet_id;
    bit<16> eni_id;
    eni_data_t eni_data;

    conntrack_data_t conntrack_data;
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

    dash_routing_type_t routing_type;
    dash_match_stage_t transit_to;
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
