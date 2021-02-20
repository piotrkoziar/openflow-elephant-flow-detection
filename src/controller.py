from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app import simple_switch_13
from ryu.lib import hub
from operator import attrgetter
import ryu.app.ofctl.api as ofctl_api
from flow_manager import FlowManager
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from path_manager import PathManager

MAX_PORT_VAL = 255
UNSPECIFIED_ADDRESS = '00:00:00:00:00:00'
UNSPECIFIED_PORT = 0

CONST_PORTS_NUMBER = 2

def dummy_handler():
    print("HELLO FROM HANDLER")

class Port():
    def __init__(self, hw_addr, is_constant=False):
        self.is_constant = is_constant
        self.hw_addr = hw_addr

class FlowAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MONITOR_INTERVAL = 2 # in seconds

    def __init__(self, *args, **kwargs):
        super(FlowAwareSwitch, self).__init__(*args, **kwargs)
        self.flow_manager = FlowManager(dummy_handler)
        self.path_manager = PathManager()

        self.datapaths = {}
        self.mac_to_port = {}
        self.ports = {}

        self.monitor_thread = hub.spawn(self._monitor)

    def _register_datapath(self, datapath):
        if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.ports[datapath.id] = {}

    def _unregister_datapath(self, datapath):
        if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                self.flow_manager.delete_flows(datapath)
                del self.datapaths[datapath.id]
                del self.ports[datapath.id]

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self._register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            self._unregister_datapath(datapath)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)

            desc = self.flow_manager.get_flows()
            if desc != '':
                self.logger.info("\n%s\n", desc)

            hub.sleep(self.MONITOR_INTERVAL)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        # ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        # req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        # datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body

        self.flow_manager.update_flow_stats(dpid, body)

    def _apply_path_simple(self, datapath, ether_type, path):
        dpid = datapath.id
        parser = datapath.ofproto_parser

        p_in, p_out = path[dpid]

        p_match = parser.OFPMatch(eth_type=ether_type, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self.flow_manager.create_flow(datapath, p_match, p_actions)

        p_match = parser.OFPMatch(eth_type=ether_type, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self.flow_manager.create_flow(datapath, p_match, p_actions)

    """
    @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
        In other words, packet that occurs on @param in_port is forwarded to the destip.
    """
    def _apply_path_icmp(self, datapath, path, in_port, srcip, dstip):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        protocol = in_proto.IPPROTO_ICMP

        p1, p2 = path[dpid]
        if p2 == in_port:
            p_in = p2
            p_out = p1
        elif p1 == in_port:
            p_in = p1
            p_out = p2
        else:
            # base path does not work
            pass

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

    """
    @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
        In other words, packet that occurs on @param in_port is forwarded to the destip.
    """
    def _apply_path_tcp(self, datapath, path, in_port, srcip, dstip, src_port, dst_port):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        protocol = in_proto.IPPROTO_TCP

        p1, p2 = path[dpid]
        if p2 == in_port:
            p_in = p2
            p_out = p1
        elif p1 == in_port:
            p_in = p1
            p_out = p2
        else:
            # base path does not work
            pass

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=src_port, tcp_dst=dst_port, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, tcp_src=dst_port, tcp_dst=src_port, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

    """
    @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
        In other words, packet that occurs on @param in_port is forwarded to the destip.
    """
    def _apply_path_udp(self, datapath, path, in_port, srcip, dstip, src_port, dst_port):
        dpid = datapath.id
        parser = datapath.ofproto_parser
        protocol = in_proto.IPPROTO_UDP

        p1, p2 = path[dpid]
        if p2 == in_port:
            p_in = p2
            p_out = p1
        elif p1 == in_port:
            p_in = p1
            p_out = p2
        else:
            # base path does not work
            pass

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=src_port, udp_dst=dst_port, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, udp_src=dst_port, udp_dst=src_port, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self.flow_manager.create_flow(datapath, p_match, p_actions, has_timeouts=True)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        base_path = self.path_manager.get_base_path()

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        elif eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore multicast dns and router solicitation messages sent by hosts
            # dst: 33:33:00:00:00:fb or dst: 33:33:00:00:00:02
            return
        elif eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.logger.info("[%d]GOT ARP on port [%d]!", dpid, in_port)

            self._apply_path_simple(datapath, ether_types.ETH_TYPE_ARP, base_path)

        elif (eth.ethertype == ether_types.ETH_TYPE_IP):
            self.logger.info("[%d]IPv4 on port [%d]:", dpid, in_port)
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto

            # if ICMP Protocol
            if protocol == in_proto.IPPROTO_ICMP:
                self.logger.info("[%d]GOT ICMP on port [%d]!", dpid, in_port)
                self._apply_path_icmp(datapath, base_path, in_port, srcip, dstip)

            #  if TCP Protocol
            elif protocol == in_proto.IPPROTO_TCP:
                self.logger.info("[%d]GOT TCP on port [%d], srcip: %s!", dpid, in_port, srcip)
                t = pkt.get_protocol(tcp.tcp)
                self._apply_path_tcp(datapath, base_path, in_port, srcip, dstip, t.src_port, t.dst_port)

            #  If UDP Protocol
            elif protocol == in_proto.IPPROTO_UDP:
                self.logger.info("[%d]GOT UDP on port [%d], srcip: %s!", dpid, in_port, srcip)
                u = pkt.get_protocol(udp.udp)
                self._apply_path_udp(datapath, base_path, in_port, srcip, dstip, u.src_port, u.dst_port)

        else:
            self.logger.info("GOT ETHERTYPE: %d", eth.ethertype)
            # self-learning switch functionality
            dst = eth.dst
            src = eth.src

            self.mac_to_port.setdefault(dpid, {})

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
                self.logger.info("packet in. Dst in MAC table.\nSending [dpid=%s] [src=%s] [dst=%s] [in_port=%s] to out_port [out_port=%s]", dpid, src, dst, in_port, out_port)

            else:
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("packet in. Unknown mac.\nFlooding %s %s %s %s", dpid, src, dst, in_port)

            # if match, send to the out_port
            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:

                match = parser.OFPMatch(eth_dst=dst)
                self.logger.info("\n UPDATING %s \n", match['eth_dst'])

                self.flow_manager.create_flow(datapath, match, actions, 0)

            data = None
            # send packet_out in case of no buffer
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath

        self._register_datapath(datapath)

        self.logger.info('OFPSwitchFeatures received: '
                        'datapath_id=0x%016x n_buffers=%d '
                        'n_tables=%d auxiliary_id=%d '
                        'capabilities=0x%08x',
                        msg.datapath_id, msg.n_buffers, msg.n_tables,
                        msg.auxiliary_id, msg.capabilities)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry -
        # not matched packets will be send to the controller (packet in).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.flow_manager.create_flow(datapath, match, actions, 0)

        self.send_port_desc_stats_request(ev.msg.datapath)

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = ev.msg.datapath.id
        ofproto = ev.msg.datapath.ofproto
        parser = datapath.ofproto_parser

        ports = []
        has_only_constant = True
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                        'state=0x%08x curr=0x%08x advertised=0x%08x '
                        'supported=0x%08x peer=0x%08x curr_speed=%d '
                        'max_speed=%d' %
                        (p.port_no, p.hw_addr,
                        p.name, p.config,
                        p.state, p.curr, p.advertised,
                        p.supported, p.peer, p.curr_speed,
                        p.max_speed))
            # if port_no <= 2, mark the port as constant
            if p.port_no <= CONST_PORTS_NUMBER:
                self.ports[dpid][p.port_no] = Port(p.hw_addr, is_constant=True)
            elif p.port_no < MAX_PORT_VAL:
                has_only_constant = False
                self.ports[dpid][p.port_no] = Port(p.hw_addr, is_constant=False)

        self.logger.info('OFPPortDescStatsReply received: %s', ports)

        if not has_only_constant:
            return

        self.logger.info("DPID: %d has only const ports!", dpid)

        in_port = 1
        out_port = 2

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port)
        self.flow_manager.create_flow(datapath, match, actions)

        in_port = 2
        out_port = 1

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port)
        self.flow_manager.create_flow(datapath, match, actions)
