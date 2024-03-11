#ifndef _DASH_HA_ROLE_ACTIVE_P4_
#define _DASH_HA_ROLE_ACTIVE_P4_

#include "ha_common.p4"

//
// HA role: Active
//
control ha_active_role_handle_packet_on_flow_miss(inout metadata_t meta) { apply {
    switch (meta.packet_type) {
        // For regular packets, move on with the rest of the pipeline to get the flow created.
        dash_packet_type_t.DEFAULT: {
            return;
        }

        // FROM_DPAPP: If the packet went through the data plane app and back to the pipeline again
        //             without flow created, something might be wrong.
        // FLOW_SYNC_REQ: For active role, we should never receive a flow sync packet.
        // FLOW_SYNC_ACK: If a flow is not even created, We should never receive a response packet.
        default: {
            ha_common_role_handle_unexpected_packet.apply(meta);
        }
    }
} }

control ha_active_role_handle_packet_on_flow_created(inout metadata_t meta) { apply {
    switch (meta.packet_type) {
        // If another packet arrives before flow is sync'ed, we do the same thing as new flow to
        // ensure the packet order.
        dash_packet_type_t.DEFAULT: {
            return;
        }
        
        // If the packet is coming from data plane app, we sync it to the peer.
        dash_packet_type_t.FROM_DPAPP: {
        }

        // Flow sync ack'ed, we need to update the flow state to sync'ed.
        dash_packet_type_t.FLOW_SYNC_ACK: {
        }

        // FLOW_SYNC_REQ: For active role, we should never receive a flow sync packet.
        default: {
            ha_common_role_handle_unexpected_packet.apply(meta);
        }
    }
} }

control ha_active_role_handle_packet_on_flow_synced(inout metadata_t meta) { apply {
    switch (meta.packet_type) {
        // For regular packets or packets coming from data plane app, we don't need to do
        // anything in HA anymore.
        dash_packet_type_t.FROM_EXTERNAL:
        dash_packet_type_t.FROM_DPAPP: {
            return;
        }

        // FLOW_SYNC_REQ: We don't expect flow sync request for flows that is already sync'ed.
        // FLOW_SYNC_ACK: We don't expect flow sync ack for flows that is already sync'ed.
        default: {
            ha_common_role_handle_unexpected_packet.apply(meta);
        }
    }
} }

control ha_active_role_handle_packet(inout metadata_t meta) { apply {
    // Handle packets in different flow sync state.
    switch (meta.ha.flow_sync_state) {
        dash_ha_flow_sync_state_t.FLOW_MISS: { ha_active_role_handle_packet_on_flow_miss.apply(meta); }
        dash_ha_flow_sync_state_t.FLOW_CREATED: { ha_active_role_handle_packet_on_flow_created.apply(meta); }
        dash_ha_flow_sync_state_t.FLOW_SYNCED: { ha_active_role_handle_packet_on_flow_synced.apply(meta); }
    }
} }

#endif /* _DASH_HA_ROLE_ACTIVE_P4_ */