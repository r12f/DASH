#ifndef _SIRIUS_PARSER_P4_
#define _SIRIUS_PARSER_P4_

#include "dash_headers.p4"

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported,
    InvalidIPv4Header
}

#define UDP_PORT_VXLAN 4789
#define UDP_PROTO 17
#define TCP_PROTO 6
#define NVGRE_PROTO 0x2f
#define IPV4_ETHTYPE 0x0800
#define IPV6_ETHTYPE 0x86dd

parser dash_parser(
    packet_in packet
    , out headers_t hd
    , inout metadata_t meta
#ifdef TARGET_BMV2_V1MODEL
    , inout standard_metadata_t standard_meta
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
    , in pna_main_parser_input_metadata_t istd
#endif // TARGET_DPDK_PNA
    )
{
    /*
     * First header parser
     */
    state start {
        // Most packets are 'underlay0 | overlay'
        packet.extract(hd.ethernet_0);
        transition select(hd.ethernet_0.ether_type) {
            IPV4_ETHTYPE:  parse_ipv4_0;
            IPV6_ETHTYPE:  parse_ipv6_0;
            default: accept;
        }
    }

    state parse_ipv4_0 {
        packet.extract(hd.ip_0.ipv4);
        verify(hd.ip_0.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ip_0.ipv4.ihl >= 5, error.InvalidIPv4Header);
        transition select (hd.ip_0.ipv4.ihl) {
                5: dispatch_on_protocol_0;
                default: parse_ipv4options_0;
        }
    }

    state parse_ipv4options_0 {
        packet.extract(hd.ipv4options_0,
                    (bit<32>)(((bit<16>)hd.ip_0.ipv4.ihl - 5) * 32));
        transition dispatch_on_protocol_0;
    }

    state dispatch_on_protocol_0 {
        transition select(hd.ip_0.ipv4.protocol) {
            UDP_PROTO: parse_udp_0;
            TCP_PROTO: parse_tcp_0;
            default: move_underlay0_to_overlay;
        }
    }

    state parse_ipv6_0 {
        packet.extract(hd.ip_0.ipv6);
        transition select(hd.ip_0.ipv6.next_header) {
            UDP_PROTO: parse_udp_0;
            TCP_PROTO: parse_tcp_0;
            default: move_underlay0_to_overlay;
        }
    }

    state parse_udp_0 {
        packet.extract(hd.udp_0);
        transition select(hd.udp_0.dst_port) {
            UDP_PORT_VXLAN: parse_vxlan_0;
            default: move_underlay0_to_overlay;
         }
    }

    state parse_tcp_0 {
        packet.extract(hd.tcp);
        transition move_underlay0_to_overlay;
    }

    state move_underlay0_to_overlay {
        hd.ethernet = hd.ethernet_0;
        hd.ip = hd.ip_0;
        hd.ipv4options = hd.ipv4options_0;
        hd.udp = hd.udp_0;

        hd.ethernet_0.setInvalid();
        hd.ip_0.ipv4.setInvalid();
        hd.ip_0.ipv6.setInvalid();
        hd.ipv4options_0.setInvalid();
        hd.udp_0.setInvalid();

        transition accept;
    }

    state parse_vxlan_0 {
        packet.extract(hd.encap_0.vxlan);
        transition parse_ethernet_1;
    }

    /*
     * Second header parser
     */
    state parse_ethernet_1 {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            IPV4_ETHTYPE:  parse_ipv4_1;
            IPV6_ETHTYPE:  parse_ipv6_1;
            default: accept;
        }
    }

    state parse_ipv4_1 {
        packet.extract(hd.ip.ipv4);
        verify(hd.ip.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ip.ipv4.ihl >= 5, error.InvalidIPv4Header);
        transition select (hd.ip.ipv4.ihl) {
                5: dispatch_on_protocol_1;
                default: parse_ipv4options_1;
        }
    }

    state parse_ipv4options_1 {
        packet.extract(hd.ipv4options,
                    (bit<32>)(((bit<16>)hd.ip.ipv4.ihl - 5) * 32));
        transition dispatch_on_protocol_1;
    }

    state dispatch_on_protocol_1 {
        transition select(hd.ip.ipv4.protocol) {
            UDP_PROTO: parse_udp_1;
            TCP_PROTO: parse_tcp_1;
            default: accept;
        }
    }

    state parse_ipv6_1 {
        packet.extract(hd.ip.ipv6);
        transition select(hd.ip.ipv6.next_header) {
            UDP_PROTO: parse_udp_1;
            TCP_PROTO: parse_tcp_1;
            default: accept;
        }
    }

    state parse_udp_1 {
        packet.extract(hd.udp);
        transition select(hd.udp.dst_port) {
            UDP_PORT_VXLAN: parse_vxlan_1;
            default: accept;
         }
    }

    state parse_tcp_1 {
        packet.extract(hd.tcp);
        transition accept;
    }

    state parse_vxlan_1 {
        // Move underlay0 to underlay1
        hd.ethernet_1 = hd.ethernet_0;
        hd.ip_1 = hd.ip_0;
        hd.ipv4options_1 = hd.ipv4options_0;
        hd.udp_1 = hd.udp_0;
        hd.encap_1 = hd.encap_0;

        // Move overlay o underlay0
        hd.ethernet_0 = hd.ethernet;
        hd.ip_0 = hd.ip;
        hd.ipv4options_0 = hd.ipv4options;
        hd.udp_0 = hd.udp;
        packet.extract(hd.encap_0.vxlan);

        hd.ethernet.setInvalid();
        hd.ip.ipv4.setInvalid();
        hd.ip.ipv6.setInvalid();
        hd.ipv4options.setInvalid();
        hd.udp.setInvalid();

        transition parse_ethernet_2;
    }

    /*
     * Third header parser
     */
    state parse_ethernet_2 {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            IPV4_ETHTYPE:  parse_ipv4_2;
            IPV6_ETHTYPE:  parse_ipv6_2;
            default: accept;
        }
    }

    state parse_ipv4_2 {
        packet.extract(hd.ip.ipv4);
        verify(hd.ip.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ip.ipv4.ihl >= 5, error.InvalidIPv4Header);
        transition select (hd.ip.ipv4.ihl) {
                5: dispatch_on_protocol_2;
                default: parse_ipv4options_2;
        }
    }

    state parse_ipv4options_2 {
        packet.extract(hd.ipv4options,
                    (bit<32>)(((bit<16>)hd.ip.ipv4.ihl - 5) * 32));
        transition dispatch_on_protocol_2;
    }

    state dispatch_on_protocol_2 {
        transition select(hd.ip.ipv4.protocol) {
            UDP_PROTO: parse_udp_2;
            TCP_PROTO: parse_tcp_2;
            default: accept;
        }
    }

    state parse_ipv6_2 {
        packet.extract(hd.ip.ipv6);
        transition select(hd.ip.ipv6.next_header) {
            UDP_PROTO: parse_udp_2;
            TCP_PROTO: parse_tcp_2;
            default: accept;
        }
    }

    state parse_udp_2 {
        packet.extract(hd.udp);
        transition accept;
    }

    state parse_tcp_2 {
        packet.extract(hd.tcp);
        transition accept;
    }
}

control dash_deparser(
      packet_out packet
    , in headers_t hdr
#ifdef TARGET_DPDK_PNA
    , in metadata_t meta
    , in pna_main_output_metadata_t ostd
#endif // TARGET_DPDK_PNA
    )
{
    apply {
        packet.emit(hdr.ethernet_1);
        packet.emit(hdr.ip_1.ipv4);
        packet.emit(hdr.ipv4options_1);
        packet.emit(hdr.ip_1.ipv6);
        packet.emit(hdr.udp_1);
        packet.emit(hdr.encap_1.vxlan);
        packet.emit(hdr.encap_1.nvgre);

        packet.emit(hdr.ethernet_0);
        packet.emit(hdr.ip_0.ipv4);
        packet.emit(hdr.ipv4options_0);
        packet.emit(hdr.ip_0.ipv6);
        packet.emit(hdr.udp_0);
        packet.emit(hdr.encap_0.vxlan);
        packet.emit(hdr.encap_0.nvgre);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ip.ipv4);
        packet.emit(hdr.ipv4options);
        packet.emit(hdr.ip.ipv6);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

#endif /* _SIRIUS_PARSER_P4_ */
