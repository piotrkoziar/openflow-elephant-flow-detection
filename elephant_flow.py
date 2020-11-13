from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

class ElephantFlowTopo(Topo):
    def build(self):

        # Add hosts and border switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )

        # Add middle switches to enable multiple links
        m1 = self.addSwitch('m1')
        m2 = self.addSwitch('m2')
        m3 = self.addSwitch('m3')

        # Add links between hosts and border switches
        self.addLink( h1, s1 )
        self.addLink( h2, s2 )

        # Add links between border switches and middle switches

        """ M1 """
        self.addLink( s1, m1 )
        self.addLink( s2, m1 )

        """ M2 """
        self.addLink( s1, m2 )
        self.addLink( s2, m2 )

        """ M3 """
        self.addLink( s1, m3 )
        self.addLink( s2, m3 )


def simpleTest():
    "Create and test a simple network"
    topo = ElephantFlowTopo()
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()