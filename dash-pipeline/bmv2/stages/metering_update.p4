#ifndef _DASH_STAGE_METERING_UPDATE_P4_
#define _DASH_STAGE_METERING_UPDATE_P4_

control metering_update_stage(
    inout headers_t hdr,
    inout metadata_t meta)
{
    action check_ip_addr_family(@SaiVal[type="sai_ip_addr_family_t", isresourcetype="true"] bit<32> ip_addr_family) {
        if (ip_addr_family == 0) /* SAI_IP_ADDR_FAMILY_IPV4 */ {
            if (meta.is_overlay_ip_v6 == 1) {
                meta.dropped = true;
            }
        } else {
            if (meta.is_overlay_ip_v6 == 0) {
                meta.dropped = true;
            }
        }
    }

    @SaiTable[name = "meter_policy", api = "dash_meter", order = 1, isobject="true"]
    table meter_policy {
        key = {
            meta.meter_policy_id : exact;
        }
        actions = {
            check_ip_addr_family;
        }
    }

    action set_policy_meter_class(bit<16> meter_class) {
        meta.policy_meter_class = meter_class;
    }

    @SaiTable[name = "meter_rule", api = "dash_meter", order = 2, isobject="true"]
    table meter_rule {
        key = {
            meta.meter_policy_id: exact @SaiVal[type="sai_object_id_t", isresourcetype="true", objects="METER_POLICY"];
            hdr.u0_ipv4.dst_addr : ternary @SaiVal[name = "dip", type="sai_ip_address_t"];
        }

     actions = {
            set_policy_meter_class;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
    }
    
    // MAX_METER_BUCKET = MAX_ENI(64) * NUM_BUCKETS_PER_ENI(4096)
    #define MAX_METER_BUCKETS 262144
    DEFINE_BYTE_COUNTER(meter_bucket_outbound, MAX_METER_BUCKETS, name="outbound", action_names="meter_bucket_action", attr_type="counter_attr")
    DEFINE_BYTE_COUNTER(meter_bucket_inbound, MAX_METER_BUCKETS, name="inbound", action_names="meter_bucket_action", attr_type="counter_attr")
    action meter_bucket_action(@SaiVal[type="sai_uint32_t", skipattr="true"] bit<32> meter_bucket_index) {
        meta.meter_bucket_index = meter_bucket_index;
    }

    @SaiTable[name = "meter_bucket", api = "dash_meter", order = 0, isobject="true"]
    table meter_bucket {
        key = {
            meta.eni_id: exact @SaiVal[type="sai_object_id_t"];
            meta.meter_class: exact;
        }
        actions = {
            meter_bucket_action;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
    }

    DEFINE_TABLE_COUNTER(eni_counter)

    @SaiTable[ignored = "true"]
    table eni_meter {
        key = {
            meta.eni_id : exact @SaiVal[type="sai_object_id_t"];
            meta.direction : exact;
            meta.dropped : exact;
        }

        actions = { NoAction; }

        ATTACH_TABLE_COUNTER(eni_counter)
    }
    
    apply {
        if (meta.meter_policy_en == 1) {
            meter_policy.apply();
            meter_rule.apply();
        }

        {
            if (meta.meter_policy_en == 1) {
                meta.meter_class = meta.policy_meter_class;
            } else {
                meta.meter_class = meta.route_meter_class;
            }
            if ((meta.meter_class == 0) || (meta.mapping_meter_class_override == 1)) {
                meta.meter_class = meta.mapping_meter_class;
            }
        }

        meter_bucket.apply();
        if (meta.direction == dash_direction_t.OUTBOUND) {
            UPDATE_COUNTER(meter_bucket_outbound, meta.meter_bucket_index);
        } else if (meta.direction == dash_direction_t.INBOUND) {
            UPDATE_COUNTER(meter_bucket_inbound, meta.meter_bucket_index);
        }

        eni_meter.apply();
    }
}

#endif /* _DASH_STAGE_METERING_UPDATE_P4_ */