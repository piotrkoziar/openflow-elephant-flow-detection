
import time

class Flow():
    BASE_FLOW_PRIORITY = 1
    ELEPHANT_FLOW_PRIORITY = 2

    def __init__(self, match, actions, priority=None, tout_idle=0, tout_hard=0, path=None, is_elephant=False):
        self.match = match
        self.actions = actions

        self.is_elephant = is_elephant

        if priority is None:
            self.priority=self.ELEPHANT_FLOW_PRIORITY if is_elephant else self.BASE_FLOW_PRIORITY
        else:
            self.priority=priority

        self.idle_timeout = tout_idle
        self.hard_timeout = tout_hard

        self.packet_count = 0
        self.byte_count = 0
        self.throughput = 0
        self.timestamp = time.time()

        self.path = path

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