#ifndef _DASH_HA_ROLE_STANDBY_P4_
#define _DASH_HA_ROLE_STANDBY_P4_

#include "ha_common.p4"

//
// HA role: Standby
//
control ha_standby_role_handle_packet_on_flow_miss(inout metadata_t meta) { apply {
    switch (meta.packet_type) {
        // For regular packets, tunnel to active side.
        dash_packet_type_t.FROM_EXTERNAL: {
            return;
        }

        // When flow sync request is received, we need to create the flow in sync'ed state.
        dash_packet_type_t.FLOW_SYNC_REQ: {
        }

        // FROM_DPAPP: If the packet went through the data plane app and back to the pipeline again
        //             without flow created, something might be wrong.
        // FLOW_SYNC_ACK: If a flow is not even created, We should never receive a response packet.
        default: {
            ha_common_role_handle_unexpected_packet.apply(meta);
        }
    }
} }

control ha_standby_role_handle_packet_on_flow_created(inout metadata_t meta) { apply {
    // We don't expect any flow being in flow created state in standby role.
    // In planned switchover, the active side can ensure the flows are drained before notifying us state is changed.
    // In unplanned events, we will move to standalone state, not standby. Standby is always a steady state.
    // When this happens, we treat it the same as flow miss.
    ha_standby_role_handle_packet_on_flow_miss.apply(meta);
} }

control ha_standby_role_handle_packet_on_flow_synced(inout metadata_t meta) { apply {
    switch (meta.packet_type) {
        // For incoming packets, we tunnel it to active side.
        dash_packet_type_t.FROM_EXTERNAL: {
            return;
        }

        // If the packet is coming from DPAPP, it means the flow entry is just created, and we need
        // to send the flow sync ack to the peer.
        dash_packet_type_t.FROM_DPAPP: {
            return;
        }

        // This could happen when active haven't receive flow sync ack and new packet arrives.
        // - For flow creation, we trust the first decision and send the ack back without updates.
        // - For flow updates, we updates the flow and send the ack back, e.g. flow resimulation.
        dash_packet_type_t.FLOW_SYNC_REQ: {
            return;
        }

        // FLOW_SYNC_ACK: We don't expect flow sync ack in standby role.
        default: {
            ha_common_role_handle_unexpected_packet.apply(meta);
        }
    }
} }

control ha_standby_role_handle_packet(inout metadata_t meta) { apply {
    // Handle packets in different flow sync state.
    switch (meta.ha.flow_sync_state) {
        dash_ha_flow_sync_state_t.FLOW_MISS: { ha_standby_role_handle_packet_on_flow_miss.apply(meta); }
        dash_ha_flow_sync_state_t.FLOW_CREATED: { ha_standby_role_handle_packet_on_flow_created.apply(meta); }
        dash_ha_flow_sync_state_t.FLOW_SYNCED: { ha_standby_role_handle_packet_on_flow_synced.apply(meta); }
    }
} }

#endif /* _DASH_HA_ROLE_STANDBY_P4_ */