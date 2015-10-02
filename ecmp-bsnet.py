# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Modified by Junyang Chen & Da Yu.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.ofproto import inet
import hashlib


class SimpleSwitch13(app_manager.RyuApp):

    ip_to_mac = {'10.0.0.1':'a0:36:9f:32:f0:18',
                 '10.0.0.2':'a0:36:9f:3a:8c:d4'}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        #pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        #self.logger.info("msg.datapath: %s", msg.datapath.id) from here we know id are i where s(i)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if pkt_arp:
            self._handle_arp(datapath, in_port, eth, pkt_arp)
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        #self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if pkt_icmp:
            print("handling icmp packets")
            if dpid == 6790874762836790034:
                if in_port == 1 or in_port == 2:
                    self._add_linear_bipath(1, 2, msg, inet.IPPROTO_ICMP)
                    self._add_linear_bipath(2, 1, msg, inet.IPPROTO_ICMP)
                elif in_port == 5 or in_port == 6:
                    self._add_linear_bipath(5, 6, msg, inet.IPPROTO_ICMP)
                    self._add_linear_bipath(6, 5, msg, inet.IPPROTO_ICMP)
                elif in_port == 15 or in_port == 16:
                    self._add_linear_bipath(15, 16, msg, inet.IPPROTO_ICMP)
                    self._add_linear_bipath(16, 15, msg, inet.IPPROTO_ICMP)
            return

        #if pkt_ip and pkt_udp:
        #    print(pkt_ip)
        #    print(pkt_udp)
        #    ftuple = (pkt_ip.src, pkt_udp.src_port, pkt_ip.dst, pkt_udp.dst_port, 17) # nw_proto = 17
        #    print(ftuple)

        if pkt_tcp:
            ftuple = (pkt_ip.src, pkt_tcp.src_port, pkt_ip.dst, pkt_tcp.dst_port, inet.IPPROTO_TCP)
            rftuple = self._get_reverse_ftuple(ftuple)
            if dpid == 6790874762836790034:
                if in_port == 5:
                    self._add_group_mod(self._hash_ftuple(ftuple), datapath, [[6], [6, 48]], [50, 50])
                    self._add_group_mod(self._hash_ftuple(rftuple), datapath, [[5], [5, 48]], [50, 50])
                    self._add_tcp_mirror(in_port, ftuple, msg)
                elif in_port == 6:
                    self._add_group_mod(self._hash_ftuple(ftuple), datapath, [[5], [5, 48]], [50, 50])
                    self._add_group_mod(self._hash_ftuple(rftuple), datapath, [[6], [6, 48]], [50, 50])
                    self._add_tcp_mirror(in_port, ftuple, msg)
                elif in_port == 9:
                    self._add_group_mod(self._hash_ftuple(ftuple), datapath, [[10], [10, 48]], [50, 50])
                    self._add_group_mod(self._hash_ftuple(rftuple), datapath, [[9], [9, 48]], [50, 50])
                    self._add_tcp_mirror(in_port, ftuple, msg)
                elif in_port == 10:
                    self._add_group_mod(self._hash_ftuple(ftuple), datapath, [[9], [9, 48]], [50, 50])
                    self._add_group_mod(self._hash_ftuple(rftuple), datapath, [[10], [10, 48]], [50, 50])
                    self._add_tcp_mirror(in_port, ftuple, msg)
                elif in_port == 16:
                    self._add_tcp_ecmp(16, [14, 15], ftuple, msg)
                elif in_port == 14 or in_port == 15:
                    self._add_tcp_ecmp(in_port, [16], ftuple, msg)
                elif in_port == 1:
                    self._add_tcp_ecmp(1, [2, 3], ftuple, msg)
                elif in_port == 2 or in_port == 3:
                    self._add_tcp_ecmp(in_port, [1], ftuple, msg)

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        pkt = packet.Packet()
        src_ip = pkt_arp.dst_ip
        src_mac = self.ip_to_mac[pkt_arp.dst_ip]
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=src_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=src_mac,
                                 src_ip=src_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, port, pkt)
        print("Get mac address: %s", src_mac )

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def _add_linear_bipath(self, in_port, out_port, msg, proto):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        _in_port = in_port
        _out_port = out_port
        actions = [parser.OFPActionOutput(_out_port)]
        match = parser.OFPMatch(in_port=_in_port,eth_type=0x0800,ip_proto=proto)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=_in_port, actions=actions, data=data)

        # Allow return flow
        # Generate flow_mod
        _in_port = out_port
        _out_port = in_port
        actions = [parser.OFPActionOutput(_out_port)]
        match = parser.OFPMatch(in_port=_in_port,eth_type=0x0800,ip_proto=proto)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 1, match, actions)

    def _add_linear_path(self, in_port, out_port, msg, proto):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port,eth_type=0x0800,ip_proto=proto)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

    def _add_tcp_ecmp(self, in_port, out_port_list, ftuple, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("Handling tcp packets, installing ECMP flow...")

        out_port = self._get_out_port(ftuple, out_port_list)
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port = in_port,ipv4_src = ftuple[0], tcp_src = ftuple[1], ipv4_dst = ftuple[2], tcp_dst = ftuple[3], ip_proto=inet.IPPROTO_TCP, eth_type=0x0800)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 2, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 2, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        # Add return flow
        actions = [parser.OFPActionOutput(in_port)]
        match = parser.OFPMatch(in_port = out_port, ipv4_src = ftuple[2], tcp_src = ftuple[3], ipv4_dst = ftuple[0], tcp_dst = ftuple[1], ip_proto=inet.IPPROTO_TCP, eth_type=0x0800)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 2, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 2, match, actions)

    def _add_tcp_mirror(self, in_port, ftuple, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("Handling tcp packets, installing TCP mirror rule...")

        actions = [parser.OFPActionGroup(group_id = self._hash_ftuple(ftuple))]
        match = parser.OFPMatch(ipv4_src = ftuple[0], tcp_src = ftuple[1], ipv4_dst = ftuple[2], tcp_dst = ftuple[3], ip_proto=inet.IPPROTO_TCP, eth_type=0x0800)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 2, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 2, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        # Add return flow
        rftuple = self._get_reverse_ftuple(ftuple)
        actions = [parser.OFPActionGroup(group_id = self._hash_ftuple(rftuple))]
        match = parser.OFPMatch(ipv4_src = rftuple[0], tcp_src = rftuple[1], ipv4_dst = rftuple[2], tcp_dst = rftuple[3], ip_proto=inet.IPPROTO_TCP, eth_type=0x0800)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(datapath, 2, match, actions, msg.buffer_id)
        else:
            self.add_flow(datapath, 2, match, actions)

    def _swap(self, l, left, right):
        if (left < 0 or left >= len(l) or right < 0 or right >= len(l)):
            return
        temp = l[left]
        l[left] = l[right]
        l[right] = temp

    def _get_out_port(self, ftuple, out_port_list):
        return out_port_list[self._hash_ftuple(ftuple) % len(out_port_list)]

    def _hash_ftuple(self, ftuple):
        md5 = hashlib.md5()
        md5.update(str(ftuple[0]))
        md5.update(str(ftuple[1]))
        md5.update(str(ftuple[2]))
        md5.update(str(ftuple[3]))
        md5.update(str(ftuple[4]))
        digest = md5.hexdigest()
        number = int(digest, 16)
        return number % 1000

    def _add_group_mod(self, group_id, datapath, port_list, weight_list):
        print str("GENERATING group_id: " + str(group_id))
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = []
        for i in range(len(port_list)):
            actions = []
            for j in range(len(port_list[i])):
                actions.append(ofp_parser.OFPActionOutput(port_list[i][j]))
            #print str(actions)
            buckets.append(ofp_parser.OFPBucket(weight_list[i], watch_port, watch_group, actions))

        #print str(buckets)

        req = ofp_parser.OFPGroupMod(
            datapath, ofp.OFPFC_ADD,
            ofp.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    def _get_reverse_ftuple(self, ftuple):
        return (ftuple[2], ftuple[3], ftuple[0], ftuple[1], ftuple[4])