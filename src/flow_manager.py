import time
from ryu.ofproto import ofproto_v1_3_parser as ofparser
from ryu.ofproto import ofproto_v1_3 as ofproto
from path_manager import PathManager

class FlowManager():

    ELEPHANT_THRESHOLD = 10000000
    FLOW_IDLE_TIMEOUT = 20 # in seconds
    FLOW_HARD_TIMEOUT = 25 # in seconds

    def __init__(self, elephant_handler):
        self.elephant_thr = self.ELEPHANT_THRESHOLD

        self.elephant_handler = elephant_handler

        self.flows = {}

        self.path_manager = PathManager()

    # nested Flow class
    class Flow():
        BASE_FLOW_PRIORITY = 1

        def __init__(self, match, actions=[], priority=BASE_FLOW_PRIORITY, tout_idle=0, tout_hard=0):

            self.match = match
            self.actions = actions

            self.is_elephant = False

            self.priority=priority

            self.idle_timeout = tout_idle
            self.hard_timeout = tout_hard

            self.packet_count = 0
            self.byte_count = 0
            self.throughput = 0
            self.timestamp = time.time()

        def __resolve(self, match, key):
            try:
                ret = match[key]
            except KeyError:
                ret = None

            return ret

        def __eq__(self, other):
            is_equal = True

            # check match.
            we = self.__resolve(self.match, 'eth_dst')
            they = self.__resolve(other.match, 'eth_dst')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'eth_src')
            they = self.__resolve(other.match, 'eth_src')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'in_port')
            they = self.__resolve(other.match, 'in_port')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'eth_type')
            they = self.__resolve(other.match, 'eth_type')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'ipv4_src')
            they = self.__resolve(other.match, 'ipv4_src')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'ipv4_dst')
            they = self.__resolve(other.match, 'ipv4_dst')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'ip_proto')
            they = self.__resolve(other.match, 'ip_proto')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'udp_src')
            they = self.__resolve(other.match, 'udp_src')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'udp_dst')
            they = self.__resolve(other.match, 'udp_dst')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'tcp_src')
            they = self.__resolve(other.match, 'tcp_src')
            is_equal = is_equal and (we == they)

            we = self.__resolve(self.match, 'tcp_dst')
            they = self.__resolve(other.match, 'tcp_dst')
            is_equal = is_equal and (we == they)

            # check actions.
            try:
                we = self.actions[0].port if self.actions else None
            except AttributeError:
                we = None
            try:
                they = other.actions[0].port if other.actions else None
            except AttributeError:
                they = None
            is_equal = is_equal and (we == they)

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
            header += 'throughput   '
            header += '\n'
            header += ('-' * 8) + ' ' + ('-' * 8) + ' '
            header += ('-' * 17) + ' ' + ('-' * 17) + ' '
            header += ('-' * 8) + ' ' + ('-' * 8) + ' '
            header += ('-' * 12)

            info =  '%8d' % self.packet_count
            info += '|%8d' % self.byte_count

            dst      = self.__resolve(self.match, 'eth_dst')
            src      = self.__resolve(self.match, 'eth_src')
            in_port  = self.__resolve(self.match, 'in_port')

            try:
                out_port = self.actions[0].port if self.actions else None
            except AttributeError:
                out_port = None

            info += '|%017s' % dst if dst is not None else '|%017s' % 'unspec.'
            info += '|%017s' % src if src is not None else '|%017s' % 'unspec.'
            info += '|%8d' % in_port if in_port is not None else '|%08s' % 'unspec.'
            info += '|%8d' % out_port if out_port is not None else '|%08s' % 'unspec.'
            info += '|%12d' % self.throughput
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


    def create_flow(self, datapath, match, actions, priority=Flow.BASE_FLOW_PRIORITY, has_timeouts=False):
        dpid = datapath.id

        if dpid not in self.flows.keys():
            self.flows[dpid] = []

        if has_timeouts:
            tout_idle = self.FLOW_IDLE_TIMEOUT
            tout_hard = self.FLOW_HARD_TIMEOUT
        else:
            tout_idle = 0
            tout_hard = 0

        fl = self.find_flow(dpid, match, actions, priority, tout_idle, tout_hard)

        if fl is None:
            self.flows[dpid].append(self.Flow(match, actions, priority, tout_idle, tout_hard))
            self.__add_flow(datapath, self.flows[dpid][-1])
            # print("Added flow")
            # print(self.flows[dpid][-1])

    def find_flow(self, dpid, match, actions, priority=Flow.BASE_FLOW_PRIORITY, tout_idle=0, tout_hard=0):
        flow = self.Flow(match, actions, priority, tout_idle, tout_hard)

        for fl in self.flows[dpid]:
            if fl == flow:
                return fl

        return None

    def update_flow_stats(self, dpid, stats):
        for stat in stats:

            # print("Instructions: ")
            # print(stat.instructions)
            if stat.instructions:
                actions = stat.instructions[0].actions if stat.instructions[0].actions else None
            else:
                actions = None

            # print("Find:")
            # print(actions)
            flow = self.find_flow(dpid, stat.match, actions, stat.priority, stat.idle_timeout, stat.hard_timeout)

            if flow is None:
                continue
            else:
                # print("Update stats for flow:")
                # print(flow)
                flow.update_stats(stat.packet_count, stat.byte_count)

                if flow.throughput > self.ELEPHANT_THRESHOLD:
                    if flow.is_elephant == False:
                        print("FOUND NEW ELEPHANT")

                    flow.is_elephant = True
                    self.handle_elephant(flow)

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

    def __add_flow(self, datapath, flow):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             flow.actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=flow.priority,
                                match=flow.match, instructions=inst,
                                idle_timeout=flow.idle_timeout, hard_timeout=flow.hard_timeout)
        datapath.send_msg(mod)

    def delete_flows(self, datapath):
        dpid = datapath.id

        if dpid in self.flows.keys():
            for flow in self.flows[dpid]:
                mod = ofparser.OFPFlowMod(
                    datapath, command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                    priority=flow.priority, match=flow.match)
                datapath.send_msg(mod)

            del self.flows[dpid]

    def handle_elephant(self, flow):
        pass