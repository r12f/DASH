#ifndef _SIRIUS_INBOUND_P4_
#define _SIRIUS_INBOUND_P4_

#include "dash_headers.p4"
#include "dash_service_tunnel.p4"
#include "dash_vxlan.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"

control inbound(inout headers_t hdr,
                inout metadata_t meta)
{
    apply {
#ifdef STATEFUL_P4
            ConntrackIn.apply(0);
#endif /* STATEFUL_P4 */
#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);

        if (meta.conntrack_data.original_overlay_sip != 0) {
            service_tunnel_decode(hdr,
                                  meta.conntrack_data.original_overlay_sip,
                                  meta.conntrack_data.original_overlay_dip);
        }
#endif // PNA_CONNTRACK

        /* ACL */
        if (!meta.conntrack_data.allow_in) {
            acl.apply(hdr, meta);
        }

#ifdef STATEFUL_P4
            ConntrackOut.apply(1);
#endif /* STATEFUL_P4 */
#ifdef PNA_CONNTRACK
        ConntrackOut.apply(hdr, meta);
#endif //PNA_CONNTRACK

        vxlan_encap(hdr,
                    meta.tunnel_0.tunnel_dmac,
                    meta.tunnel_0.tunnel_smac,
                    meta.tunnel_0.tunnel_dip,
                    meta.tunnel_0.tunnel_sip,
                    hdr.ethernet.dst_addr,
                    meta.tunnel_0.tunnel_vni);
    }
}

#endif /* _SIRIUS_INBOUND_P4_ */
