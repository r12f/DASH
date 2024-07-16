# Copyright 2022-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Thrift SAI interface VNET tests
"""

from unittest import skipIf

from sai_thrift.sai_headers import *
from sai_dash_utils import *

class ENILookupTestBase(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound ENI lookup test cases.
    
    Here we uses a simplest setup for the ENI only to make sure ENI lookup works.
    """

    def runTest(self):
        self.configureTest()
        self.vnet2VnetOutboundRoutingTest(tx_equal_to_rx=True)
        self.vnet2VnetOutboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """
        # Reconfigure configuration for tx equal to rx
        self.update_configuration_for_tx_equal_to_rx()

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host.client.vni,
                                     action = SAI_DIRECTION_LOOKUP_ENTRY_ACTION_SET_OUTBOUND_DIRECTION,
                                     eni_mac_override_type = SAI_DASH_ENI_MAC_OVERRIDE_TYPE_NONE)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        outbound_routing_group_id = self.outbound_routing_group_create(disabled=False)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.tx_host.ip),
                                 vm_vni=self.tx_host.client.vni,
                                 vnet_id=src_vnet,
                                 outbound_routing_group_id=outbound_routing_group_id)
        self.eni_mac_map_create(eni_id, self.tx_host.client.mac)  # ENI MAC
        # outbound routing
        self.outbound_routing_vnet_direct_create(outbound_routing_group_id, "192.168.1.0/24", dst_vnet,
                                                 overlay_ip="192.168.1.10")
        self.outbound_ca_to_pa_create(dst_vnet,  # DST vnet id
                                      "192.168.1.10",  # DST IP addr
                                      self.rx_host.ip,  # Underlay DIP
                                      overlay_dmac=self.rx_host.client.mac)

        # self.configure_underlay(self.tx_host, add_routes=False)

    def vnet2VnetOutboundRoutingTest(self, tx_equal_to_rx):
        """
        Outbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                     connection=self.connection, fake_mac=True, tx_equal_to_rx=True)

        print('\n', self.vnet2VnetOutboundRoutingTest.__name__, ' OK')

    def vnet2VnetOutboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong VIP
        - routing drop (CA Dst IP does not match any routing entry)
        - wrong CA Src MAC (does not match any ENI)
        """

        invalid_vip = "10.10.10.10"
        wrong_inner_dst_ip = "192.168.200.200"
        wrong_inner_src_ca_mac = "00:aa:00:aa:00:aa"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              fake_mac=True, invalid_vip=invalid_vip,
                                              invalid_inner_dst_ip=wrong_inner_dst_ip,
                                              invalid_inner_src_mac=wrong_inner_src_ca_mac)

        print('\n', self.vnet2VnetOutboundNegativeTest.__name__, ' OK')

@group("draft")
class OutboundENILookupTests(ENILookupTestBase):
    """
    Outbound ENI lookup test cases.
    
    Here we uses a simplest setup for the ENI only to make sure ENI lookup works.
    """

    def runTest(self):
        # Reconfigure configuration for tx equal to rx
        self.update_configuration_for_tx_equal_to_rx()
        self.configureTest()
        # self.configure_underlay(self.tx_host, add_routes=False)

        self.vnet2VnetOutboundRoutingTest(tx_equal_to_rx=True)
        self.vnet2VnetOutboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """
        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.tx_host.client.vni,
                                     action = SAI_DIRECTION_LOOKUP_ENTRY_ACTION_SET_OUTBOUND_DIRECTION,
                                     eni_mac_override_type = SAI_DASH_ENI_MAC_OVERRIDE_TYPE_NONE)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        outbound_routing_group_id = self.outbound_routing_group_create(disabled=False)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.tx_host.ip),
                                 vm_vni=self.tx_host.client.vni,
                                 vnet_id=src_vnet,
                                 outbound_routing_group_id=outbound_routing_group_id)
        self.eni_mac_map_create(eni_id, self.tx_host.client.mac)  # ENI MAC
        # outbound routing
        self.outbound_routing_vnet_direct_create(outbound_routing_group_id, "192.168.1.0/24", dst_vnet,
                                                 overlay_ip="192.168.1.10")
        self.outbound_ca_to_pa_create(dst_vnet,  # DST vnet id
                                      "192.168.1.10",  # DST IP addr
                                      self.rx_host.ip,  # Underlay DIP
                                      overlay_dmac=self.rx_host.client.mac)

    def vnet2VnetOutboundRoutingTest(self, tx_equal_to_rx):
        """
        Outbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                     connection=self.connection, fake_mac=True, tx_equal_to_rx=tx_equal_to_rx)

        print('\n', self.vnet2VnetOutboundRoutingTest.__name__, ' OK')

    def vnet2VnetOutboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong VIP
        - routing drop (CA Dst IP does not match any routing entry)
        - wrong CA Src MAC (does not match any ENI)
        """

        invalid_vip = "10.10.10.10"
        wrong_inner_dst_ip = "192.168.200.200"
        wrong_inner_src_ca_mac = "00:aa:00:aa:00:aa"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              fake_mac=True, invalid_vip=invalid_vip,
                                              invalid_inner_dst_ip=wrong_inner_dst_ip,
                                              invalid_inner_src_mac=wrong_inner_src_ca_mac)

        print('\n', self.vnet2VnetOutboundNegativeTest.__name__, ' OK')


@group("draft")
class OutboundENILookupTests(VnetApiEndpoints, VnetTrafficMixin):
    """
    Outbound ENI lookup test cases:

    Verifies positive and negative scenarios
    """

    def runTest(self):
        # Reconfigure configuration for tx equal to rx
        self.update_configuration_for_tx_equal_to_rx()
        self.configureTest()
        #self.configure_underlay(self.tx_host, add_routes=False)

        self.vnet2VnetInboundRoutingTest(tx_equal_to_rx=True)
        self.vnet2VnetInboundNegativeTest()

    def configureTest(self):
        """
        Setup DUT in accordance with test purpose
        """

        self.vip_create(self.tx_host.peer.ip)

        # direction lookup VNI, reserved VNI assigned to the VM->Appliance
        self.direction_lookup_create(self.rx_host.client.vni)

        src_vnet = self.vnet_create(vni=self.tx_host.client.vni)
        dst_vnet = self.vnet_create(vni=self.rx_host.client.vni)

        eni_id = self.eni_create(admin_state=True,
                                 vm_underlay_dip=sai_ipaddress(self.rx_host.ip),
                                 vm_vni=self.rx_host.client.vni,
                                 vnet_id=dst_vnet)
        self.eni_mac_map_create(eni_id, self.rx_host.client.mac)  # ENI MAC

        # Inbound routing PA Validate
        addr_mask = self.tx_host.ip_prefix.split('/')
        self.inbound_routing_decap_validate_create(eni_id, vni=self.tx_host.client.vni,
                                                   sip=addr_mask[0], sip_mask=num_to_dotted_quad(addr_mask[1]),
                                                   src_vnet_id=src_vnet)
        # PA validation entry with Permit action
        self.pa_validation_create(self.tx_host.ip, src_vnet)

    def vnet2VnetInboundRoutingTest(self, tx_equal_to_rx):
        """
        Inbound VNET to VNET test
        Verifies correct packet routing
        """

        self.verify_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                     connection=self.connection, fake_mac=False, tx_equal_to_rx=tx_equal_to_rx)

        print('\n', self.vnet2VnetInboundRoutingTest.__name__, ' OK')

    def vnet2VnetInboundNegativeTest(self):
        """
        Verifies negative scenarios (packet drop):
        - wrong CA Dst MAC
        - wrong PA Validation IP: pa validation missmatch
        - wrong Physical SIP: routing missmatch
        - wrong VIP
        - wrong VNI
        """

        invalid_vni = 1000
        invalid_ca_dst_mac = "9e:ba:ce:98:d9:e2"
        invalid_pa_sip = "10.10.5.1"  # routing missmatch
        invalid_vip = "10.10.10.10"

        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              fake_mac=False,
                                              invalid_vni=invalid_vni,
                                              invalid_outer_src_ip=invalid_pa_sip,
                                              invalid_inner_dst_mac=invalid_ca_dst_mac,
                                              invalid_vip=invalid_vip)

        invalid_pa_valid_ip = "10.10.1.25"  # pa validation missmatch
        self.verify_negative_traffic_scenario(client=self.tx_host, server=self.rx_host,
                                              fake_mac=False,
                                              invalid_outer_src_ip=invalid_pa_valid_ip)

        print('\n', self.vnet2VnetInboundNegativeTest.__name__, ' OK')