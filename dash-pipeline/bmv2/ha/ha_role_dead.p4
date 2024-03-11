#ifndef _DASH_HA_ROLE_DEAD_P4_
#define _DASH_HA_ROLE_DEAD_P4_

#include "ha_common.p4"

//
// HA role: Dead
//
control ha_dead_role_handle_packet(inout metadata_t meta) { apply {
    // We are not expecting any packets being sent to dead role.
    ha_common_role_handle_unexpected_packet.apply(meta);
} }

#endif /* _DASH_HA_ROLE_DEAD_P4_ */