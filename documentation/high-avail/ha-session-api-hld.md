
### 14.4. SAI APIs

#### 14.4.1. HA session APIs

The HA session APIs can be defined as below:

- It is part of SAI DASH extensions and consists with 2 major parts: HA set and HA session.
  - HA set is a group of DPUs that are paired together.
  - HA session ties a specific HA set to enable HA for a specific ENI.
- When enabling HA, we need to first allocate the HA set, then create the HA session for the ENI with the HA set ID.
- Although in CONFIG_DB, the HA set is created by a group of vDPUs, however, the SAI API doesn't need to pass it in, since the IP address is the one that DPU really needs to know.

```c
/**
 * @brief Attribute ID for HA set
 */
typedef enum _sai_dash_ha_set_attr_t
{
    /**
     * @brief Start of attributes
     */
    SAI_DASH_HA_SET_ATTR_START,

    /**
     * @brief Peer DPU IPv4 address
     *
     * @type sai_ip4_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_PEER_DPU_IPV4 = SAI_DASH_HA_SET_ATTR_START,

    /**
     * @brief Peer DPU IPv6 address
     *
     * @type sai_ip6_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_PEER_DPU_IPV6,

    /**
     * @brief NPU IPv4 address of corresponding peer DPU
     *
     * @type sai_ip4_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_PEER_NPU_IPV4,

    /**
     * @brief NPU IPv6 address of corresponding peer DPU
     *
     * @type sai_ip6_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_PEER_NPU_IPV6,

    /**
     * @brief NPU tunnel dst port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_NPU_TUNNEL_DST_PORT,

    /**
     * @brief NPU tunnel minimum src port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_NPU_TUNNEL_SRC_PORT_MIN,

    /**
     * @brief NPU tunnel maximum src port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_NPU_TUNNEL_SRC_PORT_MAX,

    /**
     * @brief DPU data plane channel dst port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_DP_CHANNEL_DST_PORT,

    /**
     * @brief DPU data plane channel minimum src port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_DP_CHANNEL_SRC_PORT_MIN,

    /**
     * @brief DPU data plane channel maximum src port
     *
     * @type sai_uint16_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_DP_CHANNEL_SRC_PORT_MAX,

    /**
     * @brief DPU data plane channel probe interval in milliseconds
     *
     * @type sai_uint32_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @default disabled
     */
    SAI_DASH_HA_SET_ATTR_DP_CHANNEL_PROBE_INTERVAL_IN_MS,

    /**
     * @brief End of attributes
     */
    SAI_DASH_HA_SET_ATTR_END,

    /** Custom range base value */
    SAI_DASH_HA_SET_ATTR_CUSTOM_RANGE_START = 0x10000000,

    /** End of custom range base */
    SAI_DASH_HA_SET_ATTR_CUSTOM_RANGE_END,

} sai_dash_ha_set_attr_t;

/**
 * @brief Attribute data for HA role
 */
typedef enum _sai_dash_ha_role_t
{
    /**
     * @brief Dead role. This is the initial role of the ENI.
     */
    SAI_DASH_HA_ROLE_DEAD,

    /**
     * @brief Active role. This role makes flow decisions and process the
     * traffic.
     */
    SAI_DASH_HA_ROLE_ACTIVE,

    /**
     * @brief Standby role. This role acts as flow store and accepts flow
     * replication requests.
     */
    SAI_DASH_HA_ROLE_STANDBY,

    /**
     * @brief Standalone role. This role acts like active, but don't replicate
     * flows.
    */
    SAI_DASH_HA_ROLE_STANDALONE,

    /**
     * @brief Role switching to active. This role acts like active, but accepts
     * flow replication requests.
     */
    SAI_DASH_HA_ROLE_SWITCHING_TO_ACTIVE,

} sai_dash_ha_role_t;

/**
 * @brief Attribute ID for HA session
 */
typedef enum _sai_dash_ha_session_attr_t
{
    /**
     * @brief Start of attributes
     */
    SAI_DASH_HA_SESSION_ATTR_START,

    /**
     * @brief ENI object id
     *
     * @type sai_object_id_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @allownull false
     * @default disabled
     */
    SAI_DASH_HA_SESSION_ATTR_ENI_ID = SAI_DASH_HA_SESSION_ATTR_START,

    /**
     * @brief HA set object id
     *
     * @type sai_object_id_t
     * @flags MANDATORY_ON_CREATE | CREATE_ONLY
     * @allownull false
     * @default disabled
     */
    SAI_DASH_HA_SESSION_ATTR_HA_SET_ID,

    /**
     * @brief Desired HA role
     *
     * @type sai_ip6_t
     * @flags CREATE_AND_SET
     * @default SAI_DASH_HA_ROLE_DEAD
     */
    SAI_DASH_HA_SESSION_ATTR_HA_ROLE,

    /**
     * @brief End of attributes
     */
    SAI_DASH_HA_SESSION_ATTR_END,

    /** Custom range base value */
    SAI_DASH_HA_SESSION_ATTR_CUSTOM_RANGE_START = 0x10000000,

    /** End of custom range base */
    SAI_DASH_HA_SESSION_ATTR_CUSTOM_RANGE_END,

} sai_dash_ha_session_attr_t;

/**
 * @brief HA Session counter IDs in sai_get_ha_session_stats* call
 */
typedef enum _sai_ha_session_stat_t
{
    /** Start of NPU-to-DPU tunnel counters */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_START = 0x10000,

    /** NPU-to-DPU tunnel ENI ingress packet count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_PACKETS_IN = SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_START,

    /** NPU-to-DPU tunnel ENI egress packet count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_PACKETS_OUT,

    /** NPU-to-DPU tunnel ENI ingress byte count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_BYTES_IN,

    /** NPU-to-DPU tunnel ENI egress byte count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_BYTES_OUT,

    /** NPU-to-DPU tunnel ENI ingress packet discards count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_DISCARDS_IN,

    /** NPU-to-DPU tunnel ENI egress packet discards count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_DISCARDS_OUT,

    /** NPU-to-DPU tunnel ENI ingress packet error count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_ERROR_IN,

    /** NPU-to-DPU tunnel ENI egress packet error count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_ERROR_OUT,

    /** NPU-to-DPU tunnel ENI ingress packet oversize count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_OVERSIZE_IN,

    /** NPU-to-DPU tunnel ENI egress packet oversize count */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_OVERSIZE_OUT,

    /** End of NPU-to-DPU tunnel counters */
    SAI_HA_SESSION_N2D_TUNNEL_ENI_STAT_END,


    /** Start of DPU-to-DPU tunnel counters */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_START = 0x20000,

    /** DPU-to-DPU tunnel ENI inline sync packet received count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_INLINE_SYNC_PACKETS_IN,

    /** DPU-to-DPU tunnel ENI inline sync packet sent count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_INLINE_SYNC_PACKETS_OUT,

    /** DPU-to-DPU tunnel ENI meta sync packet received count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_META_SYNC_PACKETS_IN,

    /** DPU-to-DPU tunnel ENI meta sync packet sent count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_META_SYNC_PACKETS_OUT,

    /** DPU-to-DPU tunnel ENI probe packet received count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_PROBE_PACKETS_IN,

    /** DPU-to-DPU tunnel ENI probe packet sent count */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_PROBE_PACKETS_OUT,

    /** End of DPU-to-DPU tunnel counters */
    SAI_HA_SESSION_D2D_TUNNEL_ENI_STAT_END,


    /** Start of ENI pipeline counters */
    SAI_HA_SESSION_ENI_PIPELINE_STAT_START = 0x30000,

    /** Start of ENI pipeline inline flow creation counters. E.g. TCP/UDP new connection. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_START = 0x30100,

    /** Number of inline flow creation request that sent from active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_REQ_SENT = SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_START,

    /** Number of inline flow creation request that received on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_REQ_RECV,

    /** Number of inline flow creation ack request that sent from standby node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_REQ_ACK_SENT,

    /** Number of inline flow creation ack request that recevied on active node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_REQ_ACK_RECV,

    /** Number of flow created by inline replication on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_STANDBY_FLOW_CREATED,

    /** Number of flow created by inline flow replication on active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_ACTIVE_FLOW_CREATED,

    /** Average time used for inline flow replication E2E in nanoseconds . */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_AVERAGE_LATENCY_IN_NS,

    /** Minimum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_MIN_LATENCY_IN_NS,

    /** Maximum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_MAX_LATENCY_IN_NS,

    /** Number of inline flow creation request that failed for any reason. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_FAILED,

    /** Number of inline flow creation request that failed due to out of memory. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_FAILED_OOM,

    /** Number of inline flow creation request that failed due to flow conflicts. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_FAILED_FLOW_CONFLICTS,

    /** Number of inline flow creation request that succeeded by replacing existing flow. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_FLOW_OVERRIDED,

    /** End of ENI pipeline inline flow creation counters */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_CREATION_STAT_END,

    /** Start of ENI pipeline inline flow update counters. E.g. flow resimulation */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_START = 0x30200,

    /** Number of inline flow update request that sent from active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_REQ_SENT = SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_START,

    /** Number of inline flow update request that received on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_REQ_RECV,

    /** Number of inline flow update ack request that sent from standby node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_REQ_ACK_SENT,

    /** Number of inline flow update ack request that recevied on active node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_REQ_ACK_RECV,

    /** Number of flow updated by inline replication on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_STANDBY_FLOW_UPDATED,

    /** Number of flow updated by inline flow replication on active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_ACTIVE_FLOW_UPDATED,

    /** Average time used for inline flow replication E2E in nanoseconds . */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_AVERAGE_LATENCY_IN_NS,

    /** Minimum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_MIN_LATENCY_IN_NS,

    /** Maximum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_MAX_LATENCY_IN_NS,

    /** Number of inline flow update request that failed for any reason. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_FAILED,

    /** Number of inline flow update request that failed due to out of memory. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_FAILED_OOM,

    /** Number of inline flow update request that failed due to flow not found. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_FAILED_FLOW_NOT_FOUND,

    /** Number of inline flow update request that failed due to flow conflicts. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_FAILED_FLOW_CONFLICTS,

    /** Number of inline flow update request that succeeded by replacing existing flow. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_FLOW_OVERRIDED,

    /** End of ENI pipeline inline flow update counters */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_UPDATE_STAT_END,

    /** Start of ENI pipeline inline flow deletion counters. E.g. TCP connection close. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_START = 0x30300,

    /** Number of inline flow deletion request that sent from active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_REQ_SENT = SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_START,

    /** Number of inline flow deletion request that received on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_REQ_RECV,

    /** Number of inline flow deletion ack request that sent from standby node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_REQ_ACK_SENT,

    /** Number of inline flow deletion ack request that recevied on active node.*/
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_REQ_ACK_RECV,

    /** Number of flow deleted by inline replication on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_STANDBY_FLOW_DELETED,

    /** Number of flow deleted by inline flow replication on active node. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_ACTIVE_FLOW_DELETED,

    /** Average time used for inline flow replication E2E in nanoseconds . */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_AVERAGE_LATENCY_IN_NS,

    /** Minimum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_MIN_LATENCY_IN_NS,

    /** Maximum time used for inline flow replication E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_MAX_LATENCY_IN_NS,

    /** Number of inline flow deletion request that failed for any reason. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_FAILED,

    /** Number of inline flow deletion request that failed due to out of memory. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_FAILED_OOM,

    /** Number of inline flow deletion request that failed due to flow not found. */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_FAILED_FLOW_NOT_FOUND,

    /** End of ENI pipeline inline flow deletion counters */
    SAI_HA_SESSION_ENI_PIPELINE_INLINE_FLOW_DELETION_STAT_END,

    /** Start of ENI pipeline flow aging counters. E.g. Idle timeout. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_START = 0x30400,

    /** Number of flow aging request that sent from active node. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_REQ_SENT = SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_START,

    /** Number of flow aging request that received on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_REQ_RECV,

    /** Number of flow aging ack request that sent from standby node.*/
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_REQ_ACK_SENT,

    /** Number of flow aging ack request that recevied on active node.*/
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_REQ_ACK_RECV,

    /** Number of flow deleted by flow aging on standby node. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_STANDBY_FLOW_DELETED,

    /** Number of flow deleted by flow aging on active node. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_ACTIVE_FLOW_DELETED,

    /** Average time used for flow aging request E2E in nanoseconds . */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_AVERAGE_LATENCY_IN_NS,

    /** Minimum time used for flow aging request E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_MIN_LATENCY_IN_NS,

    /** Maximum time used for flow aging E2E in nanoseconds. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_MAX_LATENCY_IN_NS,

    /** Number of flow aging request that failed for any reason. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_FAILED,

    /** Number of flow aging request that failed due to out of memory. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_FAILED_OOM,

    /** Number of flow aging request that failed due to flow not found. */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_FAILED_FLOW_NOT_FOUND,

    /** End of ENI pipeline flow aging counters */
    SAI_HA_SESSION_ENI_PIPELINE_FLOW_AGING_STAT_END,

    /** End of ENI pipeline counters */
    SAI_HA_SESSION_ENI_PIPELINE_STAT_END,

    /** Custom range base value */
    SAI_DASH_HA_SESSION_STAT_CUSTOM_RANGE_START = 0x10000000,

    /** End of custom range base */
    SAI_DASH_HA_SESSION_STAT_CUSTOM_RANGE_END,
} sai_ha_session_stat_t;


/**
 * @brief Create dash_ha_set
 *
 * @param[out] dash_ha_set_id HA set id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_create_dash_ha_set_fn)(
        _Out_ sai_object_id_t *dash_ha_set_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

/**
 * @brief Remove dash_ha_set
 *
 * @param[in] dash_ha_set_id HA set id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_remove_dash_ha_set_fn)(
        _In_ sai_object_id_t dash_ha_set_id);

/**
 * @brief Set attribute for dash_ha_set
 *
 * @param[in] dash_ha_set_id HA set id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_set_dash_ha_set_attribute_fn)(
        _In_ sai_object_id_t dash_ha_set_id,
        _In_ const sai_attribute_t *attr);

/**
 * @brief Get attribute for dash_ha_set
 *
 * @param[in] dash_ha_set_id HA set id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_get_dash_ha_set_attribute_fn)(
        _In_ sai_object_id_t dash_ha_set_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

/**
 * @brief Create dash_ha_session
 *
 * @param[out] dash_ha_session_id HA session id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_create_dash_ha_session_fn)(
        _Out_ sai_object_id_t *dash_ha_session_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

/**
 * @brief Remove dash_ha_session
 *
 * @param[in] dash_ha_session_id HA session id
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_remove_dash_ha_session_fn)(
        _In_ sai_object_id_t dash_ha_session_id);

/**
 * @brief Set attribute for dash_ha_session
 *
 * @param[in] dash_ha_session_id HA session id
 * @param[in] attr Attribute
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_set_dash_ha_session_attribute_fn)(
        _In_ sai_object_id_t dash_ha_session_id,
        _In_ const sai_attribute_t *attr);

/**
 * @brief Get attribute for dash_ha_session
 *
 * @param[in] dash_ha_session_id HA session id
 * @param[in] attr_count Number of attributess
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 */
typedef sai_status_t (*sai_get_dash_ha_session_attribute_fn)(
        _In_ sai_object_id_t dash_ha_session_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

/**
 * @brief Get HA session statistics counters. Deprecated for backward compatibility.
 *
 * @param[in] dash_ha_session_id HA session id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
typedef sai_status_t (*sai_get_ha_session_stats_fn)(
        _In_ sai_object_id_t dash_ha_session_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _Out_ uint64_t *counters);

/**
 * @brief Get HA session statistics counters extended.
 *
 * @param[in] dash_ha_session_id HA session id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
typedef sai_status_t (*sai_get_ha_session_stats_ext_fn)(
        _In_ sai_object_id_t dash_ha_session_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _In_ sai_stats_mode_t mode,
        _Out_ uint64_t *counters);

/**
 * @brief Clear HA session statistics counters.
 *
 * @param[in] dash_ha_session_id HA session id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
typedef sai_status_t (*sai_clear_ha_session_stats_fn)(
        _In_ sai_object_id_t dash_ha_session_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids);

typedef struct _sai_dash_ha_api_t
{
    sai_create_dash_ha_set_fn              create_dash_ha_set;
    sai_remove_dash_ha_set_fn              remove_dash_ha_set;
    sai_set_dash_ha_set_attribute_fn       set_dash_ha_set_attribute;
    sai_get_dash_ha_set_attribute_fn       get_dash_ha_set_attribute;

    sai_create_dash_ha_session_fn           create_dash_ha_session;
    sai_remove_dash_ha_session_fn           remove_dash_ha_session;
    sai_set_dash_ha_session_attribute_fn    set_dash_ha_session_attribute;
    sai_get_dash_ha_session_attribute_fn    get_dash_ha_session_attribute;

    sai_get_ha_session_stats_fn             get_ha_session_stats;
    sai_get_ha_session_stats_ext_fn         get_ha_session_stats_ext;
    sai_clear_ha_session_stats_fn           clear_ha_session_stats;
} sai_dash_ha_api_t;
```