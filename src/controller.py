from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from flow_manager import FlowManager
import path_manager as pm

class FlowAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    MONITOR_INTERVAL = 2 # in seconds
    MAX_PORT_NUMBER = 255

    def __init__(self, *args, **kwargs):
        super(FlowAwareSwitch, self).__init__(*args, **kwargs)
        self.flow_manager = FlowManager()

        self.datapaths = {}
        self.mac_to_port = {}

        self.monitor_thread = hub.spawn(self._monitor)

    def _register_datapath(self, datapath):
        if datapath.id not in self.datapaths:
                self.logger.info('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath

    def _unregister_datapath(self, datapath):
        if datapath.id in self.datapaths:
                self.logger.info('unregister datapath: %016x', datapath.id)
                self.flow_manager.delete_flows(datapath)
                del self.datapaths[datapath.id]

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

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        body = ev.msg.body

        self.flow_manager.update_flow_stats(datapath, body)

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

        skip_path_installation = 0
        base_paths = pm.path_manager.get_base_paths()

        if len(base_paths) > 0:
            base_path = base_paths[0] # Since topology is rather simple, we use only one base path.
        else:
            # we do not have any paths defined!
            skip_path_installation = 1

        if eth.ethertype == ether_types.ETH_TYPE_LLDP and not skip_path_installation:
            # ignore lldp packet
            return
        elif eth.ethertype == ether_types.ETH_TYPE_IPV6 and not skip_path_installation:
            # ignore multicast dns and router solicitation messages sent by hosts
            # dst: 33:33:00:00:00:fb or dst: 33:33:00:00:00:02
            return
        elif eth.ethertype == ether_types.ETH_TYPE_ARP and not skip_path_installation:
            self.logger.info("[%d]GOT ARP on port [%d]!", dpid, in_port)

            self.flow_manager.apply_path_simple(datapath, ether_types.ETH_TYPE_ARP, base_path)

        elif (eth.ethertype == ether_types.ETH_TYPE_IP) and not skip_path_installation:
            self.logger.info("[%d]IPv4 on port [%d]:", dpid, in_port)
            ip = pkt.get_protocol(ipv4.ipv4)
            srcip = ip.src
            dstip = ip.dst
            protocol = ip.proto

            # if ICMP Protocol
            if protocol == in_proto.IPPROTO_ICMP:
                self.logger.info("[%d]GOT ICMP on port [%d]!", dpid, in_port)
                self.flow_manager.apply_path_icmp(datapath, base_path, in_port, srcip, dstip)

            #  if TCP Protocol
            elif protocol == in_proto.IPPROTO_TCP:
                self.logger.info("[%d]GOT TCP on port [%d], srcip: %s!", dpid, in_port, srcip)
                t = pkt.get_protocol(tcp.tcp)
                self.flow_manager.apply_path_tcp(datapath, base_path, in_port, srcip, dstip, t.src_port, t.dst_port)

            #  If UDP Protocol
            elif protocol == in_proto.IPPROTO_UDP:
                self.logger.info("[%d]GOT UDP on port [%d], srcip: %s!", dpid, in_port, srcip)
                u = pkt.get_protocol(udp.udp)
                self.flow_manager.apply_path_udp(datapath, base_path, in_port, srcip, dstip, u.src_port, u.dst_port)

        else:
            self.logger.info("GOT ETHERTYPE: %d", eth.ethertype)
            # self-learning switch functionality
            dst = eth.dst
            src = eth.src

            self.mac_to_port.setdefault(dpid, {})

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                self.logger.info("packet in. Dst in MAC table.\nSending [dpid=%s] [src=%s] [dst=%s] [in_port=%s] to out_port [out_port=%s]", dpid, src, dst, in_port, out_port)
                out_port = self.mac_to_port[dpid][dst]
                path = pm.Path(dpid, in_port, out_port)
                self.flow_manager.apply_path_eth(datapath, path, src, dst, in_port)

            else:
                out_port = ofproto.OFPP_FLOOD
                self.logger.info("packet in. Unknown mac.\nFlooding %s %s %s %s", dpid, src, dst, in_port)

                actions = [parser.OFPActionOutput(out_port)]
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

        self.flow_manager.install_table_miss_entry(datapath)

        self.send_port_desc_stats_request(ev.msg.datapath)

    def send_port_desc_stats_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = ev.msg.datapath.id

        ports = []
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

            if p.port_no < self.MAX_PORT_NUMBER:
                ports.append(p.port_no)

        self.logger.info(len(ports))
        if len(ports) == 5:
            self.logger.info("DPID: %d has two user ports! Install flow in advance.", dpid)

            # create flow to send packets between the two ports.
            path = pm.Path(dpid, 1, 2)
            self.flow_manager.apply_path_simple(datapath=datapath, ether_type=None, path=path, is_elephant=False)
