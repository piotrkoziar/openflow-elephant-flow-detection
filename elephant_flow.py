from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class ElephantFlowTopo(Topo):
    def build(self):

        # Add hosts and border switches
        leftHost = self.addHost( 'h1' )
        rightHost = self.addHost( 'h2' )
        leftSwitch = self.addSwitch( 's3' )
        rightSwitch = self.addSwitch( 's4' )

        # Add middle switches to enable multiple links
        middleSwitch1 = self.addHost('m1')
        middleSwitch2 = self.addHost('m2')
        middleSwitch3 = self.addHost('m3')

        # Add links between hosts and border switches
        self.addLink( leftHost, leftSwitch )
        self.addLink( rightSwitch, rightHost )

        # Add links between border switches and middle switches
        self.addLink( leftSwitch, rightSwitch )

        """ M1 """
        self.addLink( leftSwitch, middleSwitch1 )
        self.addLink( middleSwitch1, rightSwitch )

        """ M2 """
        self.addLink( leftSwitch, middleSwitch2 )
        self.addLink( middleSwitch2, rightSwitch )

        """ M3 """
        self.addLink( leftSwitch, middleSwitch3 )
        self.addLink( middleSwitch3, rightSwitch )


def simpleTest():
    "Create and test a simple network"
    topo = ElephantFlowTopo()
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()