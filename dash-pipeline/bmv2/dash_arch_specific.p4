#ifndef __DASH_TARGET_SPECIFIC__
#define __DASH_TARGET_SPECIFIC__

#ifdef TARGET_BMV2_V1MODEL

#include <v1model.p4>

// Counters
#define DEFINE_TABLE_COUNTER(counter_name) direct_counter(CounterType.packets_and_bytes) counter_name;
#define ATTACH_TABLE_COUNTER(counter_name) counters = counter_name;
#define DIRECT_COUNTER_TABLE_PROPERTY counters

// DBC (Design By Contract) macros
#define REQUIRES(cond) assert(cond)

#endif // TARGET_BMV2_V1MODEL

#ifdef TARGET_DPDK_PNA

#include <pna.p4>

// Counters
#ifdef DPDK_SUPPORTS_DIRECT_COUNTER_ON_WILDCARD_KEY_TABLE
    // Omit all direct counters for tables with ternary match keys,
    // because the latest version of p4c-dpdk as of 2023-Jan-26 does
    // not support this combination of features.  If you try to
    // compile it with this code enabled, the error message looks like
    // this:
    //
    // [--Werror=target-error] error: Direct counters and direct meters are unsupported for wildcard match table outbound_acl_stage1:dash_acl_rule|dash_acl
    //
    // This p4c issue is tracking this feature gap in p4c-dpdk:
    // https://github.com/p4lang/p4c/issues/3868
    #define DEFINE_TABLE_COUNTER(counter_name) DirectCounter<bit<64>>(PNA_CounterType_t.PACKETS_AND_BYTES) counter_name;
    #define ATTACH_TABLE_COUNTER(counter_name) pna_direct_counter = counter_name;
#else
    #define DEFINE_TABLE_COUNTER(counter_name)
    #define ATTACH_TABLE_COUNTER(counter_name)
#endif

// DBC (Design By Contract) macros
// NOTE: PNA doesn't support assert, hence all macros are defined as empty
#define REQUIRES(cond)

#endif // TARGET_DPDK_PNA

#endif // __DASH_TARGET_SPECIFIC__
