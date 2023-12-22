#ifndef _DASH_HA_P4_
#define _DASH_HA_P4_

#include "dash_metadata.p4"

control ha(inout headers_t hdr,
           inout metadata_t meta)
{
    action set_ha_set_attr(
        bit<1> peer_ip_is_v6,
        @SaiVal[type="sai_ip_address_t"] IPv4ORv6Address peer_ip,
        bit<16> dp_channel_dst_port,
        bit<16> dp_channel_src_port_min,
        bit<16> dp_channel_src_port_max,
        bit<32> dp_channel_probe_interval_ms
    ) {
        meta.peer_ip_is_v6 = peer_ip_is_v6;
        meta.peer_ip = peer_ip;
        meta.dp_channel_dst_port = dp_channel_dst_port;
        meta.dp_channel_src_port_min = dp_channel_src_port_min;
        meta.dp_channel_src_port_max = dp_channel_src_port_max;
        meta.dp_channel_probe_interval_ms = dp_channel_probe_interval_ms;
    }

    @SaiTable[api = "dash_ha", api_order=0, isobject="true"]
    table ha_set {
        key = {
            meta.ha_set_id : exact @SaiVal[type="sai_object_id_t"];
        }
        actions = {
            set_ha_set_attr;
        }
    }

    apply {
        ha_set.apply();
    }
}

#endif