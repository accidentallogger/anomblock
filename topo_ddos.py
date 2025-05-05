from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.util import dumpNodeConnections

class DDoSTopo(Topo):
    def build(self):
        # Add a switch
        switch = self.addSwitch('s1')
        
        # Add three normal hosts
        normal_host1 = self.addHost('h1', ip='10.0.0.1/24')
        normal_host2 = self.addHost('h2', ip='10.0.0.2/24')
        normal_host3 = self.addHost('h3', ip='10.0.0.3/24')
        
        # Add two attacker hosts
        attacker_host1 = self.addHost('h4', ip='10.0.0.4/24')
        attacker_host2 = self.addHost('h5', ip='10.0.0.5/24')

        # Add links between hosts and switch
        self.addLink(normal_host1, switch)
        self.addLink(normal_host2, switch)
        self.addLink(normal_host3, switch)
        self.addLink(attacker_host1, switch)
        self.addLink(attacker_host2, switch)

def run_network():
    # Create network and controller
    topo = DDoSTopo()
    net = Mininet(topo=topo, controller=Controller, switch=OVSSwitch, link=TCLink)

    # Start the network
    net.start()
    dumpNodeConnections(net.hosts)

    # Test connectivity
    print("Testing network connectivity")
    net.pingAll()

    # Simulate traffic from normal hosts and attackers
    # Normal hosts can ping each other or generate some load
    normal_host1 = net.get('h1')
    normal_host2 = net.get('h2')
    normal_host3 = net.get('h3')

    # Attackers will be running DoS/DDoS attacks using tools like hping3
    attacker_host1 = net.get('h4')
    attacker_host2 = net.get('h5')

    # Start DDoS attack simulation with hping3 (send SYN packets)
    print("Starting DDoS attack simulation...")
    attacker_host1.cmd("hping3 -S --flood -p 80 10.0.0.2 &")  # Attacker 1 attacking normal_host2
    attacker_host2.cmd("hping3 -S --flood -p 80 10.0.0.2 &")  # Attacker 2 attacking normal_host2

    # Wait for the user to stop the attack
    print("Press CTRL+C to stop the simulation...")
    net.interact()

if __name__ == '__main__':
    run_network()
