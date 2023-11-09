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

    bit<16> nat_src_port;
    bit<16> nat_dst_port;

    dash_encapsulation_t dash_encapsulation;
    bit<24> service_tunnel_key;
    IPv4Address original_overlay_sip;
    IPv4Address original_overlay_dip;
    IPv6Address st_dst;
    IPv6Address st_dst_mask;
    IPv6Address st_src;
    IPv6Address st_src_mask;
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

enum bit<16> dash_routing_type_t {
    DIRECT = 0,
    VNET = 1,
    VNET_DIRECT = 2,
    VNET_ENCAP = 3,
    SERVICETUNNEL = 4,
    PRIVATELINK = 5,
    PRIVATELINKNSG = 6,
    PRIVATELINKMAP = 7,
    PRIVATELINKNAT = 8
}

typedef bit<32> RoutingType_t;
#define ACTION_STATICENCAP      (1<<0)
#define ACTION_TUNNEL           (1<<1)
#define ACTION_4to6             (1<<2)
#define ACTION_6to4             (1<<3)
#define ACTION_NAT              (1<<4)

typedef bit<32> Oid_t;
typedef bit<8> MatchStage_t;
#define MATCH_END           0
#define MATCH_START         1
#define MATCH_ROUTING0      1
#define MATCH_ROUTING1      2
#define MATCH_IPMAPPING0    3
#define MATCH_IPMAPPING1    4
#define MATCH_TCPPORTMAPPING   5
#define MATCH_UDPPORTMAPPING   6

typedef bit<16> Nexthop_t;

struct metadata_t {
    bool dropped;
    dash_direction_t direction;
    RoutingType_t routing_type;
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
    bit<1> lkp_addr_is_v6;
    IPv4ORv6Address lkp_addr;
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


    MatchStage_t transit_to;
    Nexthop_t nexthop;
    Oid_t mapping_oid;
    Oid_t pipeline_oid;
    Oid_t tcpportmap_oid;
    Oid_t udpportmap_oid;
}

#endif /* _SIRIUS_METADATA_P4_ */
