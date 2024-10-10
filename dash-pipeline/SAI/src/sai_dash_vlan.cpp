#include "saiimpl.h"

DASH_GENERIC_QUAD(VLAN,vlan);
DASH_GENERIC_QUAD(VLAN_MEMBER,vlan_member);

sai_vlan_api_t dash_sai_vlan_api_impl = {

    DASH_GENERIC_QUAD_API(vlan)
    DASH_GENERIC_QUAD_API(vlan_member)

    .create_vlan_members = 0,
    .remove_vlan_members = 0,
    .get_vlan_stats = 0,
    .get_vlan_stats_ext = 0,
    .clear_vlan_stats = 0,
};
