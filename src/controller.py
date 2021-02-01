from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.app import simple_switch_13
from ryu.lib import hub
from operator import attrgetter
import ryu.app.ofctl.api as ofctl_api
from flow_manager import FlowManager

MAX_PORT_VAL = 255
UNSPECIFIED_ADDRESS = '00:00:00:00:00:00'
UNSPECIFIED_PORT = 0

CONST_PORTS_NUMBER = 2


class Port():
    def __init__(self, hw_addr, is_constant=False):
        self.is_constant = is_constant
        self.hw_addr = hw_addr

class FlowAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    MONITOR_INTERVAL = 1 # in seconds

    def __init__(self, *args, **kwargs):
        super(FlowAwareSwitch, self).__init__(*args, **kwargs)
        self.flow_manager = FlowManager(self.add_flow)
        self.stp = kwargs['stplib']

        self.datapaths = {}
        self.const_only_datapaths = [] # TODO: remove
        self.mac_to_port = {}
        self.ports = {}

        self.stp.set_config({})
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.ports[datapath.id] = {}
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                self.flow_manager.remove_dpid(datapath.id)
                del self.datapaths[datapath.id]
                del self.ports[datapath.id]
                for d in self.const_only_datapaths:
                    if d.id == datapath.id:
                        self.const_only_datapaths.remove(d)
                        break

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

    # def install_flow_pair(self, datapath, dst, src, in_port, out_port):
    #     dpid = datapath.id
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
    #     actions = [parser.OFPActionOutput(out_port)]
    #     fl = Flow(dst, in_port, out_port, True, src)
    #     self.add_flow(datapath, 2, match, actions, has_timeouts=True)
    #     self.flows[dpid].append(fl)

    #     match = parser.OFPMatch(in_port=out_port, eth_dst=src)
    #     actions = [parser.OFPActionOutput(in_port)]
    #     flb = Flow(src, out_port, in_port, True, dst)
    #     self.add_flow(datapath, 2, match, actions, has_timeouts=True)
    #     self.flows[dpid].append(flb)


    # def handle_elephant(self, datapath, flow, handle_const_switches=False):

    #     self.logger.info("Handle elephant")
    #     self.logger.info("Found elephant flow in %016x. [dst=%s] [src=%s]", datapath.id, flow.dst, flow.src)

    #     if datapath in self.const_only_datapaths:
    #         self.logger.info("Returning\n")
    #         return

    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     elephant_flow_switches = {}
    #     elephant_flow_switches[datapath] = flow

    #     for dpid in self.datapaths:
    #         if dpid == datapath.id:
    #             continue

    #         fl = self.find_elephant_flow(dpid, flow.dst, flow.src)

    #         result = ofctl_api.get_datapath(self, dpid=dpid)

    #         if fl is not None:
    #             self.logger.info("Found elephant flow in %016x. [dst=%s] [src=%s]", dpid, flow.dst, flow.src)
    #             fl.is_elephant = True
    #             elephant_flow_switches[result] = fl

    #     for swdp in elephant_flow_switches.keys():

    #         if swdp in self.const_only_datapaths:
    #             break

    #         swid = swdp.id
    #         swflow = elephant_flow_switches[swdp]

    #         port_in_desc = self.ports[swid][swflow.in_port]
    #         port_out_desc = self.ports[swid][swflow.out_port]

    #         if (port_in_desc.is_constant and not port_out_desc.is_constant) or (port_out_desc.is_constant and not port_in_desc.is_constant):

    #             # new port: greater than 1 or the smaller number
    #             if port_in_desc.is_constant:
    #                 current_port = swflow.out_port
    #             else:
    #                 current_port = swflow.in_port

    #             new_port = None

    #             for pno in self.ports[swid].keys():
    #                 if (pno > current_port) and not (self.ports[swid][pno].is_constant):
    #                     new_port = pno
    #                     break

    #             if new_port is None:
    #                 for pno in self.ports[swid].keys():
    #                     if not self.ports[swid][pno].is_constant:
    #                         new_port = pno
    #                         break

    #             if new_port is None:
    #                 return

    #             self.logger.info("\nNew port is %d\n", new_port)

    #             # prepare new flow pair with higher priority
    #             if port_in_desc.is_constant:
    #                 # change flow.out_port to new_port
    #                 self.install_flow_pair(swdp, swflow.dst, swflow.src, swflow.in_port, new_port)
    #             else:
    #                 # change flow.in_port to new_port
    #                 self.install_flow_pair(swdp, swflow.dst, swflow.src, new_port, swflow.out_port)

    #     if handle_const_switches == False:
    #         return

    #     # install additional flow pairs in switches that has two const ports
    #     for c_d in self.const_only_datapaths:
    #         c_port_no1 = 1
    #         c_port_no2 = 2

    #         self.install_flow_pair(c_d, flow.dst, flow.src, c_port_no1, c_port_no2)
    #         self.install_flow_pair(c_d, flow.dst, flow.src, c_port_no2, c_port_no1)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # ignore multicast dns and router solicitation messages sent by hosts
            # dst: 33:33:00:00:00:fb or dst: 33:33:00:00:00:02
            return

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
            # self.add_flow(datapath, 1, match, actions)
            self.logger.info("\n UPDATING %s \n", match['eth_dst'])

            self.flow_manager.create_flow(dpid, dst=dst, out_port=out_port)

        data = None
        # send packet_out in case of no buffer
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                    in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            self.delete_flows(dp)
            del self.mac_to_port[dp.id]

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.info("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg

        self.logger.info('OFPSwitchFeatures received: '
                        'datapath_id=0x%016x n_buffers=%d '
                        'n_tables=%d auxiliary_id=%d '
                        'capabilities=0x%08x',
                        msg.datapath_id, msg.n_buffers, msg.n_tables,
                        msg.auxiliary_id, msg.capabilities)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry -
        # not matched packets will be send to the controller (packet in).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

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

        self.const_only_datapaths.append(datapath)
        self.logger.info("DPID: %d has only const ports!", dpid)