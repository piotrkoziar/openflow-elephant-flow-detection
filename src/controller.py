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

class Flow():
    def __init__(self, dst, in_port, out_port, is_elephant=False):
        self.dst = dst
        self.in_port = in_port
        self.out_port = out_port
        self.is_elephant = is_elephant

        self.last_byte_count = 0

    def __eq__(self, other):
        return ((self.dst == other.dst) and
            (self.in_port == other.in_port) and
            (self.out_port == other.out_port))

class FlowAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(FlowAwareSwitch, self).__init__(*args, **kwargs)
        self.stp = kwargs['stplib']

        self.elephant_thr = 10000000
        self.interval = 1

        self.datapaths = {}
        self.mac_to_port = {}
        self.flows = {}

        self.stp.set_config({})
        self.monitor_thread = hub.spawn(self._monitor)

    def find_flow(self, dpid, dst, in_port, out_port):
        for fl in self.flows[dpid]:
            if ((fl.dst == dst) and
                (fl.in_port == in_port) and
                (fl.out_port == out_port)):

                return fl

        return None

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
                self.flows[datapath.id] = []
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]
                del self.flows[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.interval)

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
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['eth_dst'])):

            flow = self.find_flow(dpid, stat.match['eth_dst'], stat.match['in_port'], stat.instructions[0].actions[0].port)

            if flow is None:
                self.logger.warning("\n%016x %8x %17s %8x\nNo correlated flow object found!\n", dpid, stat.match['in_port'], stat.match['eth_dst'], stat.instructions[0].actions[0].port)
            else:

                # calculate threshold
                thr = (stat.byte_count - flow.last_byte_count) / self.interval
                self.logger.info("Throughput = %d", thr)

                # update last packet count value
                flow.last_byte_count = stat.byte_count
                self.logger.info("Updating flow byte count")

                self.logger.info('%016x %8x %17s %8x %8d %8d',
                                dpid,
                                flow.in_port, flow.dst,
                                flow.out_port,
                                stat.packet_count, stat.byte_count)

                if thr > self.elephant_thr:
                    if flow.is_elephant == False:
                        self.logger.info("\n FOUND NEW ELEPHANT! \n")
                        flow.is_elephant = True

                        self.handle_elephant(dpid, flow)
                    else:
                        self.logger.info("\n FOUND ELEPHANT! \n")

        self.logger.info("\n\n")

    def handle_elephant(self, dpid, flow):
        if dpid not in self.border_dpids:
            return

        self.logger.info("Handle elephant")
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser

        # for dst in self.is_flow_elephant[datapath.id].keys():
        #     # self.logger.info("DST - ELEPHANT HANDLE: %s", dst)
        #     match = parser.OFPMatch(eth_dst=dst)
        #     mod = parser.OFPFlowMod(
        #         datapath, command=ofproto.OFPFC_DELETE,
        #         out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
        #         priority=1, match=match)
        #     datapath.send_msg(mod)

        #     # create new path
        #     new_out_port = self.out_port_paths[self.variant]

        #     match = parser.OFPMatch(eth_dst=dst)
        #     actions = [parser.OFPActionOutput(new_out_port)]
        #     self.add_flow(datapath, 1, match, actions)

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

    def delete_flows(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for dst in self.mac_to_port[datapath.id].keys():
            match = parser.OFPMatch(eth_dst=dst)
            mod = parser.OFPFlowMod(
                datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=1, match=match)
            datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
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

        dpid = datapath.id
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

            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

            self.add_flow(datapath, 1, match, actions)
            self.logger.info("\n UPDATING %s \n", match['eth_dst'])

            fl = Flow(dst, in_port, out_port, False)
            self.flows[dpid].append(fl)

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
        self.logger.debug("[dpid=%s][port=%d] state=%s",
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