#!/usr/bin/env python3
# topo/insdn_topo.py

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController, Host # Add these if not present
from mininet.link import TCLink # Add this if using bw/delay
from mininet.log import info, setLogLevel
from time import sleep # <--- ADD THIS IMPORT

# --- START: Add the traffic_gen function here ---
def traffic_gen(net):
    info("[+] Starting traffic generation...\n")
    h1,h2,h3,h4,h5,h6 = [net.get(f'h{i}') for i in range(1,7)]
    #  Benign throughput test
    info(f"[*] Starting iperf server on {h2.name} (10.0.2.10:5001)\n")
    h2.popen('iperf -s -p 5001 &')
    info(f"[*] Starting iperf client on {h1.name} (10.0.1.10) to {h2.name} (10.0.2.10:5001) for 30s\n")
    h1.cmd('iperf -c 10.0.2.10 -p 5001 -t 30 &') # Assuming h2's IP is 10.0.2.10

    #  DoS (HULK-style flood)
    info(f"[*] Starting DoS flood from {h5.name} (10.0.3.1) to 10.0.3.10:80 for 30s\n") # Assuming h6's IP is 10.0.3.10
    h5.cmd('timeout 30s hping3 --flood 10.0.3.10 -p 80 &')

    info("[*] Waiting 35 seconds for traffic to complete...\n")
    sleep(35) # Wait for traffic to complete
    info("[+] Traffic generation finished.\n")
# --- END: Add the traffic_gen function here ---


def build():
    # Your existing topology setup (assuming it builds 'net')
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink, # Use TCLink if you have bw/delay in addLink
        cleanup=True # Important for clean shutdowns
    )

    info('*** Adding controller\n')
    # Assuming your Ryu controller is listening on localhost:6653
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Creating hosts\n')
    h1 = net.addHost('h1', ip='10.0.1.10/24')
    h2 = net.addHost('h2', ip='10.0.2.10/24')
    h3 = net.addHost('h3', ip='10.0.3.10/24')
    h4 = net.addHost('h4', ip='10.0.4.10/24')
    h5 = net.addHost('h5', ip='10.0.3.1/24') # Source of DoS, needs a valid IP
    h6 = net.addHost('h6', ip='10.0.3.2/24') # Target of DoS, needs a valid IP

    info('*** Creating switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    s4 = net.addSwitch('s4', protocols='OpenFlow13')
    s5 = net.addSwitch('s5', protocols='OpenFlow13')

    info('*** Creating links\n')
    # Example links - adjust based on your actual topology
    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(h3, s3)
    net.addLink(h4, s4)
    net.addLink(h5, s3) # Link for DoS source
    net.addLink(h6, s3) # Link for DoS target

    net.addLink(s1, s2, bw=1000)
    net.addLink(s2, s3, bw=1000)
    net.addLink(s3, s4, bw=1000)
    net.addLink(s4, s5, bw=1000)


    info('*** Starting network\n')
    net.build()
    c0.start()
    net.start() # This starts the switches and connects them to the controller

    # --- START: Call traffic_gen here after network starts ---
    traffic_gen(net)
    # --- END: Call traffic_gen here ---

    # Optional: If you want to interact with the Mininet CLI after traffic:
    # CLI(net)

    info('*** Stopping network\n')
    net.stop() # This will stop the network after traffic generation is done

if __name__ == '__main__':
    setLogLevel('info')
    build()
