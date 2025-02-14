# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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
# from ryu.ofproto import ether
import logging
import six
import struct
import time
from ryu import cfg
import hmac  # get : to hash the distance bounding protocol tlv
import hashlib  # get : to hash the distance bounding protocol tlv
import random  # get : to generate a random number
import os  # get : to communicate with kernel level modules
import datetime  # get to know, calculate the current time
from ryu.topology import event
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.exception import RyuException
from ryu.lib import addrconv, hub
from ryu.lib.mac import DONTCARE_STR
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.port_no import port_no_to_str
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import lldp, ether_types
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from bitstring import BitArray
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
import collections

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.BoolOpt('observe-links', default=False,
                help='observe link discovery events.'),
    cfg.BoolOpt('install-lldp-flow', default=True,
                help='link discovery: explicitly install flow entry '
                     'to send lldp packet to controller'),
    cfg.BoolOpt('explicit-drop', default=True,
                help='link discovery: explicitly drop lldp packet in')
])


class Port(object):
    # This is data class passed by EventPortXXX
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto
        self._config = ofpport.config
        self._state = ofpport.state

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr
        self.name = ofpport.name

    def is_reserved(self):
        return self.port_no > self._ofproto.OFPP_MAX

    def is_down(self):
        return (self._state & self._ofproto.OFPPS_LINK_DOWN) > 0 \
            or (self._config & self._ofproto.OFPPC_PORT_DOWN) > 0

    def is_live(self):
        # NOTE: OF1.2 has OFPPS_LIVE state
        #       return (self._state & self._ofproto.OFPPS_LIVE) > 0
        return not self.is_down()

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'port_no': port_no_to_str(self.port_no),
                'hw_addr': self.hw_addr,
                'name': self.name.decode('utf-8')}

    # for Switch.del_port()
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
            (self.dpid, self.port_no, LIVE_MSG[self.is_live()])


class Switch(object):
    # This is data class passed by EventSwitchXXX
    def __init__(self, dp):
        super(Switch, self).__init__()

        self.dp = dp
        self.ports = []

    def add_port(self, ofpport):
        port = Port(self.dp.id, self.dp.ofproto, ofpport)
        if not port.is_reserved():
            self.ports.append(port)

    def del_port(self, ofpport):
        self.ports.remove(Port(ofpport))

    def to_dict(self):
        d = {'dpid': dpid_to_str(self.dp.id),
             'ports': [port.to_dict() for port in self.ports]}
        return d

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dp.id
        for port in self.ports:
            msg += str(port) + ' '

        msg += '>'
        return msg


class Link(object):
    # This is data class passed by EventLinkXXX
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d

    # this type is used for key value of LinkState
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link: %s to %s' % (self.src, self.dst)


class Host(object):
    # This is data class passed by EventHostXXX
    def __init__(self, mac, port):
        super(Host, self).__init__()
        self.port = port
        self.mac = mac
        self.ipv4 = []
        self.ipv6 = []

    def to_dict(self):
        d = {'mac': self.mac,
             'ipv4': self.ipv4,
             'ipv6': self.ipv6,
             'port': self.port.to_dict()}
        return d

    def __eq__(self, host):
        return self.mac == host.mac and self.port == host.port

    def __str__(self):
        msg = 'Host<mac=%s, port=%s,' % (self.mac, str(self.port))
        msg += ','.join(self.ipv4)
        msg += ','.join(self.ipv6)
        msg += '>'
        return msg


class HostState(dict):
    # mac address -> Host class
    def __init__(self):
        super(HostState, self).__init__()

    def add(self, host):
        mac = host.mac
        self.setdefault(mac, host)

    def update_ip(self, host, ip_v4=None, ip_v6=None):
        mac = host.mac
        host = None
        if mac in self:
            host = self[mac]

        if not host:
            return

        if ip_v4 is not None:
            if ip_v4 in host.ipv4:
                host.ipv4.remove(ip_v4)
            host.ipv4.append(ip_v4)

        if ip_v6 is not None:
            if ip_v6 in host.ipv6:
                host.ipv6.remove(ip_v6)
            host.ipv6.append(ip_v6)

    def get_by_dpid(self, dpid):
        result = []

        for mac in self:
            host = self[mac]
            if host.port.dpid == dpid:
                result.append(host)

        return result


class PortState(dict):
    # dict: int port_no -> OFPPort port
    # OFPPort is defined in ryu.ofproto.ofproto_v1_X_parser
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


class PortData(object):
    def __init__(self, is_down, lldp_data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.lldp_data = lldp_data
        self.timestamp = None
        self.sent = 0
        self.rtt_timestamp = None
        self.rtt = None

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<live=%s, timestamp=%s, sent=%d, rtt=%s>' \
               % (not self.is_down, self.timestamp, self.sent, self.rtt)

    def set_rtt_timestamp(self, timestamp):
        self.rtt_timestamp = timestamp

    def update_rtt(self, rtt):
        self.rtt = rtt
        # self._move_last_key(port) # Move to back of the list

    def get_rtt(self):
        return self.rtt


class PortDataState(dict):
    # dict: Port class -> PortData class
    # slimed down version of OrderedDict as python 2.6 doesn't support it.
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(PortDataState, self).__init__()
        self._root = root = []  # sentinel node
        root[:] = [root, root, None]  # [_PREV, _NEXT, _KEY] doubly linked list
        self._map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self._map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self._root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self._map[key] = [last, root,
                                                                 key]

    def _prepend_key(self, key):
        root = self._root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self._map[key] = [root, first,
                                                                 key]

    def _move_last_key(self, key):
        self._remove_key(key)
        self._append_key(key)

    def _move_front_key(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def add_port(self, port, lldp_data):
        if port not in self:
            self._prepend_key(port)
            self[port] = PortData(port.is_down(), lldp_data)
        else:
            self[port].is_down = port.is_down()

    def lldp_sent(self, port):
        port_data = self[port]
        port_data.lldp_sent()
        self._move_last_key(port)
        return port_data

    def lldp_received(self, port):
        self[port].lldp_received()

    def move_front(self, port):
        port_data = self.get(port, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._move_front_key(port)

    def set_down(self, port):
        is_down = port.is_down()
        port_data = self[port]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._move_front_key(port)
        return is_down

    def get_port(self, port):
        return self[port]

    def del_port(self, port):
        del self[port]
        self._remove_key(port)

    def __iter__(self):
        root = self._root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def clear(self):
        for node in self._map.values():
            del node[:]
        root = self._root
        root[:] = [root, root, None]
        self._map.clear()
        dict.clear(self)

    def items(self):
        'od.items() -> list of (key, value) pairs in od'
        return [(key, self[key]) for key in self]

    def iteritems(self):
        'od.iteritems -> an iterator over the (key, value) pairs in od'
        for k in self:
            yield (k, self[k])

    def set_rtt_timestamp(self, port, timestamp):
        self[port].set_rtt_timestamp(timestamp)

    def update_rtt(self, port, rtt):
        self[port].update_rtt(rtt)

    def get_rtt(self, port):
        return self[port].get_rtt()


class LinkState(dict):
    # dict: Link class -> timestamp
    def __init__(self):
        super(LinkState, self).__init__()
        self._map = {}

    def get_peer(self, src):
        return self._map.get(src, None)

    def update_link(self, src, dst):
        link = Link(src, dst)

        self[link] = time.time()
        self._map[src] = dst

        # return if the reverse link is also up or not
        rev_link = Link(dst, src)
        return rev_link in self

    def link_down(self, link):
        del self[link]
        del self._map[link.src]

    def rev_link_set_timestamp(self, rev_link, timestamp):
        # rev_link may or may not in LinkSet
        if rev_link in self:
            self[rev_link] = timestamp

    def port_deleted(self, src):
        dst = self.get_peer(src)
        if dst is None:
            # LOG.debug('key error. src=%s, dst=%s',
            #           port, self.links.get_peer(port))
            return None, None  # Modified to handle missing peer
        link = Link(src, dst)
        rev_link = Link(dst, src)
        del self[link]
        del self._map[src]
        # reverse link might not exist
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        return dst, rev_link_dst


class LLDPPacket(object):
    # make a LLDP packet for link discovery.

    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'  # uint32_t
    PORT_ID_SIZE = 4

    class LLDPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl, dbp, send_time=None):  # get: dbp added to enable ryu distance bounce protocol
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=(LLDPPacket.CHASSIS_ID_FMT %
                        dpid_to_str(dpid)).encode('ascii'))

        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                  port_id=struct.pack(
                                      LLDPPacket.PORT_ID_STR,
                                      port_no))

        tlv_ttl = lldp.TTL(ttl=ttl)
        tlv_dbp = lldp.DBP(dbp=dbp)
        tlv_end = lldp.End()
        tlvs = [tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_dbp]

        if send_time is not None:
            tlv_send_time = lldp.SendTime(timestamp=send_time)
            tlvs.append(tlv_send_time)

        tlvs.append(tlv_end)

        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def lldp_parse(data):
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = six.next(i)
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()

        tlv_chassis_id = lldp_pkt.tlvs[0]
        if tlv_chassis_id.subtype != lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % tlv_chassis_id.subtype)
        chassis_id = tlv_chassis_id.chassis_id.decode('utf-8')
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        tlv_port_id = lldp_pkt.tlvs[1]
        if tlv_port_id.subtype != lldp.PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % tlv_port_id.subtype)
        port_id = tlv_port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no,) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        dbp = None
        send_time = None

        for tlv in lldp_pkt.tlvs:
            if tlv.tlv_type == lldp.LLDP_TLV_DBP:
                dbp = tlv.dbp
            elif tlv.tlv_type == lldp.LLDP_TLV_SEND_TIME:
                send_time = tlv.timestamp

        return src_dpid, src_port_no, dbp, send_time  # get dbp added to get the parse result


class Switches(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION, ofproto_v1_4.OFP_VERSION]
    _EVENTS = [event.EventSwitchEnter, event.EventSwitchLeave,
               event.EventSwitchReconnected,
               event.EventPortAdd, event.EventPortDelete,
               event.EventPortModify,
               event.EventLinkAdd, event.EventLinkDelete,
               event.EventHostAdd]

    DEFAULT_TTL = 120  # unused. ignored.
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0, 0))

    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    RTT_MEASUREMENT_PERIOD = 0.05  # 50ms in seconds
    RTT_HISTORY_SIZE = 20
    RTT_THRESHOLD_MULTIPLIER = 2.0  # Adjust as needed

    def __init__(self, *args, **kwargs):
        super(Switches, self).__init__(*args, **kwargs)

        self.name = 'switches'
        self.dps = {}  # datapath_id => Datapath class
        self.port_state = {}  # datapath_id => ports
        self.ports = PortDataState()  # Port class -> PortData class
        self.links = LinkState()  # Link class -> timestamp
        self.hosts = HostState()  # mac address -> Host class list
        self.is_active = True
        self.rtt_thresholds = {}  # dpid -> RTT threshold
        self.rtt_histories = {}  # dpid -> collections.deque()
        self.simple_switch_app = None

        self.link_discovery = self.CONF.observe_links
        if self.link_discovery:
            self.install_flow = self.CONF.install_lldp_flow
            self.explicit_drop = self.CONF.explicit_drop
            self.lldp_event = hub.Event()
            self.link_event = hub.Event()
            self.rtt_event = hub.Event()
            self.threads.append(hub.spawn(self.lldp_loop))
            self.threads.append(hub.spawn(self.link_loop))
            self.threads.append(hub.spawn(self.rtt_measurement_loop))

    def close(self):
        self.is_active = False
        if self.link_discovery:
            self.lldp_event.set()
            self.link_event.set()
            self.rtt_event.set()
            hub.joinall(self.threads)

    def _register(self, dp):
        assert dp.id is not None

        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            for port in dp.ports.values():
                self.port_state[dp.id].add(port.port_no, port)
            self.rtt_thresholds[dp.id] = 0.1  # Initial threshold (e.g., 100ms)
            self.rtt_histories[dp.id] = collections.deque(maxlen=self.RTT_HISTORY_SIZE)

    def _unregister(self, dp):
        if dp.id in self.dps:
            if (self.dps[dp.id] == dp):
                del self.dps[dp.id]
                del self.port_state[dp.id]
                del self.rtt_thresholds[dp.id]
                del self.rtt_histories[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dps:
            switch = Switch(self.dps[dpid])
            for ofpport in self.port_state[dpid].values():
                switch.add_port(ofpport)
            return switch

    def _get_port(self, dpid, port_no):
        switch = self._get_switch(dpid)
        if switch:
            for p in switch.ports:
                if p.port_no == port_no:
                    return p

    def _port_added(self, port):
        def enc():
            bits_size = 512  # bits
            byte_size = int(bits_size / 8)  # bytes
            x = os.urandom(byte_size)
            m = os.urandom(byte_size)
            Np = os.urandom(byte_size)
            Nv = os.urandom(byte_size)
            hmac_code = hmac.new(key=x, msg=Np, digestmod=hashlib.sha512)
            a = hmac_code.digest()
            hmac_code = hmac.new(key=m, msg=Nv, digestmod=hashlib.sha512)
            b = hmac_code.digest()
            ai = os.urandom(byte_size)
            betai = ""
            for i in range(len(BitArray(ai).bin)):
                if BitArray(ai).bin[i] == '0':
                    betai = betai + BitArray(a).bin[i]
                else:
                    betai = betai + BitArray(b).bin[i]
            return betai

        dbp_ini = enc()
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL, dbp_ini)
        self.ports.add_port(port, lldp_data)

    def _link_down(self, port):
        try:
            dst, rev_link_dst = self.links.port_deleted(port)
        except KeyError:
            # LOG.debug('key error. src=%s, dst=%s',
            #           port, self.links.get_peer(port))
            return

        if dst is None:  # Handle case where peer doesn't exist
            return

        link = Link(port, dst)
        self.send_event_to_observers(event.EventLinkDelete(link))
        if rev_link_dst:
            rev_link = Link(dst, rev_link_dst)
            self.send_event_to_observers(event.EventLinkDelete(rev_link))
        self.ports.move_front(dst)

    def _is_edge_port(self, port):
        for link in self.links:
            if port == link.src or port == link.dst:
                return False

        return True

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        assert dp is not None
        LOG.debug(dp)

        if ev.state == MAIN_DISPATCHER:
            dp_multiple_conns = False
            if dp.id in self.dps:
                LOG.warning('Multiple connections from %s', dpid_to_str(dp.id))
                dp_multiple_conns = True
                (self.dps[dp.id]).close()

            self._register(dp)
            switch = self._get_switch(dp.id)
            LOG.debug('register %s', switch)

            if not dp_multiple_conns:
                self.send_event_to_observers(event.EventSwitchEnter(switch))
            else:
                evt = event.EventSwitchReconnected(switch)
                self.send_event_to_observers(evt)

            if not self.link_discovery:
                return

            if self.install_flow:
                ofproto = dp.ofproto
                ofproto_parser = dp.ofproto_parser

                # TODO:XXX need other versions
                if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                    rule = nx_match.ClsRule()
                    rule.set_dl_dst(addrconv.mac.text_to_bin(
                        lldp.LLDP_MAC_NEAREST_BRIDGE))
                    rule.set_dl_type(ETH_TYPE_LLDP)
                    actions = [ofproto_parser.OFPActionOutput(
                        ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
                    dp.send_flow_mod(
                        rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                        idle_timeout=0, hard_timeout=0, actions=actions,
                        priority=0xFFFF)
                elif ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
                    match = ofproto_parser.OFPMatch(
                        eth_type=ETH_TYPE_LLDP,
                        eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
                    # OFPCML_NO_BUFFER is set so that the LLDP is not
                    # buffered on switch
                    parser = ofproto_parser
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                      ofproto.OFPCML_NO_BUFFER
                                                      )]
                    inst = [parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dp, match=match,
                                            idle_timeout=0, hard_timeout=0,
                                            instructions=inst,
                                            priority=0xFFFF)
                    dp.send_msg(mod)
                else:
                    LOG.error('cannot install flow. unsupported version. %x',
                              dp.ofproto.OFP_VERSION)

            # Do not add ports while dp has multiple connections to controller.
            if not dp_multiple_conns:
                for port in switch.ports:
                    if not port.is_reserved():
                        self._port_added(port)

            self.lldp_event.set()
            self.rtt_event.set()

        elif ev.state == DEAD_DISPATCHER:
            # dp.id is None when datapath dies before handshake
            if dp.id is None:
                return

            switch = self._get_switch(dp.id)
            if switch:
                if switch.dp is dp:
                    self._unregister(dp)
                    LOG.debug('unregister %s', switch)
                    evt = event.EventSwitchLeave(switch)
                    self.send_event_to_observers(evt)

                    if not self.link_discovery:
                        return

                    for port in switch.ports:
                        if not port.is_reserved():
                            self.ports.del_port(port)
                            self._link_down(port)
                    self.lldp_event.set()
                    self.rtt_event.set()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofpport = msg.desc

        if reason == dp.ofproto.OFPPR_ADD:
            # LOG.debug('A port was added.' +
            #           '(datapath id = %s, port number = %s)',
            #           dp.id, ofpport.port_no)
            self.port_state[dp.id].add(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortAdd(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                self._port_added(port)
                self.lldp_event.set()
                self.rtt_event.set()

        elif reason == dp.ofproto.OFPPR_DELETE:
            # LOG.debug('A port was deleted.' +
            #           '(datapath id = %s, port number = %s)',
            #           dp.id, ofpport.port_no)
            self.send_event_to_observers(
                event.EventPortDelete(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery: