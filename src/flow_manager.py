from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from flow import Flow
import path_manager as pm

class FlowManager():

    ELEPHANT_THRESHOLD = 10000
    FLOW_IDLE_TIMEOUT = 2000 # in seconds
    FLOW_HARD_TIMEOUT = 2500 # in seconds

    def __init__(self):
        self.elephant_thr = self.ELEPHANT_THRESHOLD

        self.flows = {}

    def _create_flow(self, datapath, match, actions, priority=None, has_timeouts=False, path=None, is_elephant=False):

        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dpid not in self.flows.keys():
            self.flows[dpid] = []

        if has_timeouts:
            tout_idle = self.FLOW_IDLE_TIMEOUT
            tout_hard = self.FLOW_HARD_TIMEOUT
        else:
            tout_idle = 0
            tout_hard = 0

        fl = self._find_flow(dpid, match, actions, priority, tout_idle, tout_hard)

        if fl is None:
            self.flows[dpid].append(Flow(match, actions, priority, tout_idle, tout_hard, path, is_elephant))
            added_flow = self.flows[dpid][-1]

            print("ADded flow:")
            print(added_flow)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                    added_flow.actions)]

            mod = parser.OFPFlowMod(datapath=datapath, priority=added_flow.priority,
                                    match=added_flow.match, instructions=inst,
                                    idle_timeout=added_flow.idle_timeout, hard_timeout=added_flow.hard_timeout)
            print(mod)
            datapath.send_msg(mod)
        else:
            print("FLOW ALREADY EXISTS! No flow mod")

    def _find_flow(self, dpid, match, actions, priority=None, tout_idle=0, tout_hard=0):
        flow = Flow(match, actions, priority, tout_idle, tout_hard)

        for fl in self.flows[dpid]:
            if fl == flow:
                return fl

        return None

    def update_flow_stats(self, datapath, stats):
        dpid = datapath.id

        for stat in stats:

            if stat.instructions:
                actions = stat.instructions[0].actions if stat.instructions[0].actions else None
            else:
                actions = None

            flow = self._find_flow(dpid, stat.match, actions, stat.priority, stat.idle_timeout, stat.hard_timeout)

            if flow is None:
                continue
            else:
                flow.update_stats(stat.packet_count, stat.byte_count)

                if flow.throughput > self.ELEPHANT_THRESHOLD:
                    if flow.is_elephant == False:
                        print("FOUND NEW ELEPHANT!")

                        flow.is_elephant = True
                        self.handle_elephant(datapath, flow)
                else:
                    flow.is_elephant = False

    """ Returns string with all flows description.
    """
    def get_flows(self):
        desc = ''
        for dpid in self.flows.keys():
            desc += "\n%016x" % dpid + '\n'
            desc += '#' * 112 + '\n'

            for flow in self.flows[dpid]:
                desc += str(flow) + '\n'

            desc += '\n' + ('#' * 112) + '\n'

        return desc

    """ Delete all flows for given datapath.
    """
    def delete_flows(self, datapath):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if dpid in self.flows.keys():
            for flow in self.flows[dpid]:
                mod = parser.OFPFlowMod(
                    datapath, command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                    priority=flow.priority, match=flow.match)
                datapath.send_msg(mod)

            del self.flows[dpid]

    """ Install table-miss flow entry -
    not matched packets will be send to the controller (packet in).
    """
    def install_table_miss_entry(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry -
        # not matched packets will be send to the controller (packet in).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self._create_flow(datapath, match, actions, 0)

    """ Create flow in both directions (for given @param datapath) that matches the route specified in the @param path
    between src and dst.
    Packet to @param dst that will be received on port_in will be send to other port specified in @param path.
    Packet to @param src that will be received on port specified in @param path other than port_in will be send to port_in.
    """
    def apply_path_eth(self, datapath, path, src, dst, in_port, is_elephant=False):
        dpid = datapath.id
        parser = datapath.ofproto_parser

        p1, p2 = path[dpid]
        if p2 == in_port:
            p_in = p2
            p_out = p1
        elif p1 == in_port:
            p_in = p1
            p_out = p2
        else:
            # base path does not work
            return

        p_match = parser.OFPMatch(eth_dst=dst, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

        p_match = parser.OFPMatch(eth_dst=src, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

    """ Create flow in both directions (for given @param datapath) that matches the route specified in the @param path.
    """
    def apply_path_simple(self, datapath, ether_type, path, is_elephant=False):
        dpid = datapath.id
        parser = datapath.ofproto_parser

        p_in, p_out = path[dpid]

        if ether_type is not None:
            p_match = parser.OFPMatch(eth_type=ether_type, in_port=p_in)
        else:
            p_match = parser.OFPMatch(in_port=p_in)
            print("NO ETHER TYPE")

        p_actions = [parser.OFPActionOutput(p_out)]
        self._create_flow(datapath, p_match, p_actions, is_elephant=is_elephant, path=path)

        if ether_type is not None:
            p_match = parser.OFPMatch(eth_type=ether_type, in_port=p_out)
        else:
            p_match = parser.OFPMatch(in_port=p_out)

        p_actions = [parser.OFPActionOutput(p_in)]
        self._create_flow(datapath, p_match, p_actions, is_elephant=is_elephant, path=path)

    """ @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
    In other words, packet that occurs on @param in_port is forwarded to the @param destip.
    """
    def apply_path_icmp(self, datapath, path, in_port, srcip, dstip, is_elephant=False):
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
            return

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

    """ @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
    In other words, packet that occurs on @param in_port is forwarded to the @param destip.
    """
    def apply_path_tcp(self, datapath, path, in_port, srcip, dstip, src_port, dst_port, is_elephant=False):
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
            return

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=src_port, tcp_dst=dst_port, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, tcp_src=dst_port, tcp_dst=src_port, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

    """ @param in_port is the switch port on which the packet was received.
    @param dstip is the destination of the packet that was received.
    In other words, packet that occurs on @param in_port is forwarded to the @param destip.
    """
    def apply_path_udp(self, datapath, path, in_port, srcip, dstip, src_port, dst_port, is_elephant=False):
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
            return

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=src_port, udp_dst=dst_port, in_port=p_in)
        p_actions = [parser.OFPActionOutput(p_out)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

        p_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=dstip, ipv4_dst=srcip, ip_proto=protocol, udp_src=dst_port, udp_dst=src_port, in_port=p_out)
        p_actions = [parser.OFPActionOutput(p_in)]
        self._create_flow(datapath, p_match, p_actions, has_timeouts=True, path=None if is_elephant else path, is_elephant=is_elephant)

    def handle_elephant(self, datapath, flow):
        dpid = datapath.id
        path = flow.path

        if path is not None:

            new_path = pm.path_manager.get_alt_path(dpid, path)
            if new_path is None:
                return
            else:
                print("FLOW PATH will be changed!", dpid)

            try:
                ipproto = flow.match['ip_proto']
            except KeyError:
                ipproto = None

            if ipproto is None:
                try:
                    ethtype = flow.match['eth_type']
                except KeyError:
                    ethtype = None
                    return

                if ethtype is not None:
                    self.apply_path_simple(datapath, ethtype, new_path, True)

            elif ipproto == in_proto.IPPROTO_ICMP:
                try:
                    in_port = flow.match['in_port']
                    srcip = flow.match['ipv4_src']
                    dstip = flow.match['ipv4_dst']
                except KeyError:
                    print("Something went wrong...KeyError, proto ICMP")
                    return

                self.apply_path_icmp(datapath, new_path, in_port, srcip, dstip, True)

            elif ipproto == in_proto.IPPROTO_TCP:
                try:
                    in_port = flow.match['in_port']
                    srcip = flow.match['ipv4_src']
                    dstip = flow.match['ipv4_dst']
                    src_port = flow.match['tcp_src']
                    dst_port = flow.match['tcp_dst']
                except KeyError:
                    print("Something went wrong...KeyError, proto TCP")
                    return

                self.apply_path_tcp(datapath, new_path, in_port, srcip, dstip, src_port, dst_port, True)

            elif ipproto == in_proto.IPPROTO_UDP:
                try:
                    in_port = flow.match['in_port']
                    srcip = flow.match['ipv4_src']
                    dstip = flow.match['ipv4_dst']
                    src_port = flow.match['udp_src']
                    dst_port = flow.match['udp_dst']
                except KeyError:
                    print("Something went wrong...KeyError, proto UDP")
                    return

                self.apply_path_udp(datapath, new_path, in_port, srcip, dstip, src_port, dst_port, True)

        else:
            print("NO PATH in elephant flow!", dpid)
