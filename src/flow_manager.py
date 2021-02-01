import time

class FlowManager():

    ELEPHANT_THRESHOLD = 10000000
    FLOW_IDLE_TIMEOUT = 2000
    FLOW_HARD_TIMEOUT = 25500

    def __init__(self, elephant_handler):
        self.elephant_thr = self.ELEPHANT_THRESHOLD

        self.elephant_handler = elephant_handler

        self.flows = {}
        self.known_dpids = []

    # nested Flow class
    class Flow():
        BASE_FLOW_PRIORITY = 1

        def __init__(self, src=None, dst=None, in_port=None, out_port=None, priority=BASE_FLOW_PRIORITY, tout_idle=0, tout_hard=0):
            self.dst = dst
            self.src = src
            self.in_port = in_port
            self.out_port = out_port

            self.is_elephant = False

            self.priority=priority

            self.idle_timeout = tout_idle
            self.hard_timeout = tout_hard

            self.packet_count = 0
            self.byte_count = 0
            self.throughput = 0
            self.timestamp = time.time()

        def __eq__(self, other):
            is_equal = True

            is_equal = is_equal if (self.dst is None) and (other.dst is None) else is_equal and (self.dst == other.dst)
            is_equal = is_equal if (self.src is None) and (other.src is None) else is_equal and (self.src == other.src)
            is_equal = is_equal if (self.in_port is None) and (other.in_port is None) else is_equal and (self.in_port == other.in_port)
            is_equal = is_equal if (self.out_port is None) and (other.out_port is None) else is_equal and (self.out_port == other.out_port)
            is_equal = is_equal and (self.idle_timeout == other.idle_timeout)
            is_equal = is_equal and (self.hard_timeout == other.hard_timeout)
            is_equal = is_equal and (self.priority == other.priority)
            return is_equal == True

        def __str__(self):
            header =  'packets  '
            header += 'bytes    '
            header += 'eth-dst           '
            header += 'eth-src           '
            header += 'in-port  '
            header += 'out-port '
            header += '\n'
            header += '-------- -------- '
            header += '----------------- '
            header += '----------------- '
            header += '-------- -------- '

            info =  '%8d' % self.packet_count
            info += '%8d' % self.byte_count
            info += '%017s' % self.dst if self.dst is not None else '%017s' % 'unspec.'
            info += '%017s' % self.src if self.src is not None else '%017s' % 'unspec.'
            info += '%8d' % self.in_port if self.in_port is not None else '%08s' % 'unspec.'
            info += '%8d' % self.out_port if self.out_port is not None else '%08s' % 'unspec.'
            info += '\n'

            return header + '\n' + info

        def update_stats(self, packet_count, byte_count):

            now = time.time()
            interval = now - self.timestamp
            self.timestamp = now

            # calculate throughput
            self.throughput = (byte_count - self.byte_count) / interval

            # update last packet and byte count value
            self.packet_count = packet_count
            self.byte_count = byte_count


    def create_flow(self, dpid, src=None, dst=None, in_port=None, out_port=None, priority=Flow.BASE_FLOW_PRIORITY, tout_idle=0, tout_hard=0):

        if dpid not in self.known_dpids:
            self.known_dpids.append(dpid)
            self.flows[dpid] = []

        fl = self.find_flow(dpid, src, dst, in_port, out_port, priority, tout_idle, tout_hard)

        if fl is None:
            self.flows[dpid].append(self.Flow(src, dst, in_port, out_port, priority, tout_idle, tout_hard))

    def find_flow(self, dpid, src=None, dst=None, in_port=None, out_port=None, priority=Flow.BASE_FLOW_PRIORITY, tout_idle=0, tout_hard=0):
        flow = self.Flow(src, dst, in_port, out_port, priority, tout_idle, tout_hard)

        for fl in self.flows[dpid]:
            if fl == flow:
                return fl

        return None

    def update_flow_stats(self, dpid, stats):
        for stat in stats:

            try:
                flow = self.find_flow(dpid, stat.match['eth_dst'], stat.match['in_port'], stat.instructions[0].actions[0].port)
            except KeyError:
                flow = None

            if flow is None:
                continue
            else:
                flow.update_stats(stat.packet_count, stat.byte_count)

    """ Returns string with all flows description.
    """
    def get_flows(self):
        desc = ''
        for dpid in self.known_dpids:
            desc += "\n%016x" % dpid + '\n'
            desc += '#' * 112 + '\n'

            for flow in self.flows[dpid]:
                desc += str(flow) + '\n'

            desc += '\n' + ('#' * 112) + '\n'

        return desc

    def detect_elephants(self):
        elephants = []
        for dpid in self.known_dpids:
            for flow in self.flows[dpid]:
                if flow.throughput > self.ELEPHANT_THRESHOLD:
                    elephants.append((flow.src, flow.dst))
        return elephants

    def remove_dpid(self, dpid):
        del self.flows[dpid]
        for d in self.known_dpids:
            if d == dpid:
                self.known_dpids.remove(d)
                break

    def run_handler(self):
        self.elephant_handler()

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, has_timeouts=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if has_timeouts:
            idl_tout = self.FLOW_IDLE_TIMEOUT
            hrd_tout = self.FLOW_HARD_TIMEOUT
        else:
            idl_tout = 0
            hrd_tout = 0

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idl_tout, hard_timeout=hrd_tout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, idle_timeout=idl_tout, hard_timeout=hrd_tout)
        datapath.send_msg(mod)

    # def delete_flows(self, datapath):
    #     ofproto = datapath.ofproto
    #     parser = datapath.ofproto_parser

    #     for dst in self.mac_to_port[datapath.id].keys():
    #         match = parser.OFPMatch(eth_dst=dst)
    #         mod = parser.OFPFlowMod(
    #             datapath, command=ofproto.OFPFC_DELETE,
    #             out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
    #             priority=1, match=match)
    #         datapath.send_msg(mod)