from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.node import RemoteController, OVSKernelSwitch, OVSSwitch, DefaultController
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

from flows_generator import generate_flows

# GLOBAL VARIABLES
experiment_duration = 180  # seconds
n_mice_flows = 45
n_elephant_flows = 5

log_dir = "."

class ElephantFlowTopo(Topo):
    def build(self):

        # Add hosts and border switches
        h1 = self.addHost( 'h1', protocols='OpenFlow13' )
        h2 = self.addHost( 'h2', protocols='OpenFlow13' )
        s1 = self.addSwitch( 's1', protocols='OpenFlow13', cls=OVSKernelSwitch )
        s2 = self.addSwitch( 's2', protocols='OpenFlow13', cls=OVSKernelSwitch )

        # Add middle switches to enable multiple links
        s3 = self.addSwitch( 's3', protocols='OpenFlow13', cls=OVSKernelSwitch  )
        s4 = self.addSwitch( 's4', protocols='OpenFlow13', cls=OVSKernelSwitch  )
        s5 = self.addSwitch( 's5', protocols='OpenFlow13', cls=OVSKernelSwitch  )

        # Add links between hosts and border switches
        self.addLink( h1, s1 )
        self.addLink( h2, s2 )

        # uncomment only for testing (DNM)
        # self.addLink( s1, s2 )

        # Add links between border switches and middle switches

        # """ SM1 """
        self.addLink( s1, s3 )
        self.addLink( s2, s3 )

        # """ SM2 """
        self.addLink( s1, s4 )
        self.addLink( s2, s4 )

        # """ SM3 """
        self.addLink( s1, s5 )
        self.addLink( s2, s5 )


def Test():
    "Create and test a simple network"
    topo = ElephantFlowTopo()

    # remote ryu controller on localhost:6653
    net = Mininet(topo, controller=partial( RemoteController, ip='127.0.0.1', port=6653 ) )
    net.start()

    user_input = "QUIT"

    while True:
        # if user enters CTRL + D then treat it as quit
        try:
            user_input = raw_input("GEN/CLI/QUIT: ")
        except EOFError as error:
            user_input = "QUIT"

        if user_input.upper() == "GEN":
            experiment_duration = int(raw_input("Experiment duration: "))
            n_elephant_flows = int(raw_input("Numb of elephant flows: "))
            n_mice_flows = int(raw_input("Numb of mice flows: "))

            generate_flows(n_elephant_flows, n_mice_flows, experiment_duration, net, log_dir)

        elif user_input.upper() == "CLI":
            info("Running CLI...\n")
            CLI(net)

        elif user_input.upper() == "QUIT":
            info("Terminating...\n")
            info("Dumping host connections")

            dumpNodeConnections(net.hosts)
            print "Testing network connectivity"
            net.stop()
            break

        else:
            print("Command not found")

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    Test()