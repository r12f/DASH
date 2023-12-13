#ifndef _SIRIUS_ACL_P4_
#define _SIRIUS_ACL_P4_

#include "dash_headers.p4"

match_kind {
    /* list of ternary values
       A/A_len,B/_B-len,...
       if empty, then don't care
     */
    list,
    /* Also possibly range_list - a-b,c-d,... */
    range_list
}

/* #define DASH_MATCH */
#ifdef DASH_MATCH
#define LIST_MATCH list
#define RANGE_LIST_MATCH range_list
#else
#ifdef TARGET_BMV2_V1MODEL
#define LIST_MATCH optional
#define RANGE_LIST_MATCH optional
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#define LIST_MATCH ternary
#define RANGE_LIST_MATCH range
#endif // TARGET_DPDK_PNA
#endif

#define str(name) #name

#ifdef TARGET_BMV2_V1MODEL
#define ACL_STAGE(stage_index) \
    direct_counter(CounterType.packets_and_bytes) ## stage ## stage_index ##_counter; \
    @SaiTable[name="dash_acl_rule", stage=str(acl.stage ## stage_index), api="dash_acl", api_order=1] \
    table stage ## stage_index { \
        key = { \
            meta.stage ## stage_index ##_dash_acl_group_id : exact \
            @SaiVal[name = "dash_acl_group_id", type="sai_object_id_t", isresourcetype="true", objects="SAI_OBJECT_TYPE_DASH_ACL_GROUP"]; \
            meta.flow.dip : LIST_MATCH; \
            meta.flow.sip : LIST_MATCH; \
            meta.flow.proto : LIST_MATCH @SaiVal[name = "protocol"]; \
            meta.flow.sport : RANGE_LIST_MATCH @SaiVal[name = "src_port"]; \
            meta.flow.dport : RANGE_LIST_MATCH @SaiVal[name = "dst_port"]; \
        } \
        actions = { \
            permit; \
            permit_and_continue; \
            deny; \
            deny_and_continue; \
        } \
        default_action = deny; \
        counters = stage ## stage_index ##_counter; \
    }
#endif // TARGET_BMV2_V1MODEL
#ifdef TARGET_DPDK_PNA
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
#error "See comments in dash_acl.p4 for code changes to make"
#endif
// After this issue has been fixed:
// https://github.com/p4lang/p4c/issues/3868

// (1) Add the following line as the first line of the definition of
// ACL_STAGE:
//    DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) ## table_name ##_counter; \

// (2) Add the following line immediately after the line defining the
// default_action of the table:
//        pna_direct_counter = ## table_name ##_counter; \

#define ACL_STAGE(table_name) \
    @SaiTable[name="dash_acl_rule", stage=str(acl.stage ## stage_index), api="dash_acl"] \
    table stage ##stage_index { \
        key = { \
            meta.stage ## stage_index ##_dash_acl_group_id : exact @SaiVal[name = "dash_acl_group_id"]; \
            meta.flow.dip : LIST_MATCH; \
            meta.flow.sip : LIST_MATCH; \
            meta.flow.proto : LIST_MATCH @SaiVal[name = "protocol"]; \
            meta.flow.sport : RANGE_LIST_MATCH @SaiVal[name = "src_port"]; \
            meta.flow.dport : RANGE_LIST_MATCH @SaiVal[name = "dst_port"]; \
        } \
        actions = { \
            permit; \
            permit_and_continue; \
            deny; \
            deny_and_continue; \
        } \
        default_action = deny; \
    }
#endif // TARGET_DPDK_PNA

#define ACL_STAGE_APPLY(stage_index) \
        if ( meta.stage ## stage_index ##_dash_acl_group_id  != 0) { \
        switch (stage ## stage_index.apply().action_run) { \
            permit: {return;} \
            deny: {return;} \
        } \
        } \

/*
 * This control results in a new set of tables every time
 * it is applied, i. e. inbound ACL tables are different
 * from outbound, and API will be generated for each of them
 */
control acl(inout headers_t hdr,
            inout metadata_t meta)
{
    action permit() {}
    action permit_and_continue() {}
    action deny() {meta.pkt_meta.dropped = true;}
    action deny_and_continue() {meta.pkt_meta.dropped = true;}

ACL_STAGE(1)
ACL_STAGE(2)
ACL_STAGE(3)

    apply {
ACL_STAGE_APPLY(1)
ACL_STAGE_APPLY(2)
ACL_STAGE_APPLY(3)
    }
}
#endif /* _SIRIUS_ACL_P4_ */
