from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.log import setLogLevel, info

from flows_generator import generate_flows

# GLOBAL VARIABLES
experiment_duration = 180  # seconds
n_mice_flows = 45
n_elephant_flows = 5

log_dir = "."

class ElephantFlowTopo(Topo):
    def build(self):

        # Add hosts and border switches
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        # s1 = self.addSwitch( 's1' )
        # s2 = self.addSwitch( 's2' )

        # # Add middle switches to enable multiple links
        # m1 = self.addSwitch('m1')
        # m2 = self.addSwitch('m2')
        # m3 = self.addSwitch('m3')

        # Add links between hosts and border switches
        self.addLink( h1, h2 )
        # self.addLink( h2, s2 )

        # # Add links between border switches and middle switches

        # """ M1 """
        # self.addLink( s1, m1 )
        # self.addLink( s2, m1 )

        # """ M2 """
        # self.addLink( s1, m2 )
        # self.addLink( s2, m2 )

        # """ M3 """
        # self.addLink( s1, m3 )
        # self.addLink( s2, m3 )


def Test():
    "Create and test a simple network"
    topo = ElephantFlowTopo()
    net = Mininet(topo)
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