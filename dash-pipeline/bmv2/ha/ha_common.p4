#ifndef _DASH_HA_COMMON_P4_
#define _DASH_HA_COMMON_P4_

control ha_common_role_handle_unexpected_packet(inout metadata_t meta) { apply {
    return;
} }

#endif /* _DASH_HA_COMMON_P4_ */