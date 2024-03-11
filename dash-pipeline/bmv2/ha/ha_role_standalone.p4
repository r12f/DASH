#ifndef _DASH_HA_ROLE_STANDALONE_P4_
#define _DASH_HA_ROLE_STANDALONE_P4_

#include "ha_common.p4"

//
// HA role: Standalone
//
control ha_standalone_role_handle_packet(inout metadata_t meta) { apply {
} }

#endif /* _DASH_HA_ROLE_STANDALONE_P4_ */