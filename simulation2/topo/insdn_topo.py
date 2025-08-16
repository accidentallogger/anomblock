#!/usr/bin/env python3
# topo/insdn_topo.py

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from time import sleep

# --- START: Modified traffic_gen function for new topology ---
def traffic_gen(net):
    info("[+] Starting traffic generation...\n")

    # Get hosts by their new names
    hN1 = net.get('hN1') # Normal Traffic Generator 1
    hA1 = net.get('hA1') # Attacker 1
    hN2 = net.get('hN2') # Normal Traffic Receiver 2
    hA2 = net.get('hA2') # Attacker 2 (not used in current traffic, but available)

    # Benign throughput test: hN1 (sender) to hN2 (receiver)
    info(f"[*] Starting iperf server on {hN2.name} ({hN2.IP()}:5001) in background\n")
    hN2.popen('iperf -s -p 5001 &')

    info(f"[*] Starting iperf client on {hN1.name} ({hN1.IP()}) to {hN2.name} ({hN2.IP()}:5001) for 30s in background\n")
    hN1.cmd(f'iperf -c {hN2.IP()} -p 5001 -t 30 &') # Use f-string for dynamic IP

    # DoS (HULK-style flood): hA1 (attacker) to hN2 (target)
    info(f"[*] Starting DoS flood from {hA1.name} ({hA1.IP()}) to {hN2.name} ({hN2.IP()}:80) for 30s in background\n")
    hA1.cmd(f'timeout 30s hping3 --flood {hN2.IP()} -p 80 &') # Use f-string for dynamic IP

    info("[*] Waiting 35 seconds for traffic to complete...\n")
    sleep(35) # Wait for traffic to complete
    info("[+] Traffic generation finished.\n")
# --- END: Modified traffic_gen function ---


def build():
    net = Mininet(link=TCLink, switch=OVSSwitch, controller=None) # controller=None initially

    info('*** Adding controller\n')
    # Connect to Ryu controller on localhost:6653 (Ryu's default for OF1.3)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding switches (Tier 2: 2 connected switches)\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    info('*** Adding hosts (Tier 3: 1 attacker, 1 normal per switch)\n')
    # Hosts connected to s1
    hN1 = net.addHost('hN1', ip='10.0.1.10/24') # Normal traffic gen host for s1
    hA1 = net.addHost('hA1', ip='10.0.1.20/24') # Attacker host for s1

    # Hosts connected to s2
    hN2 = net.addHost('hN2', ip='10.0.2.10/24') # Normal traffic target host for s2
    hA2 = net.addHost('hA2', ip='10.0.2.20/24') # Attacker host for s2 (currently not used in traffic_gen)


    info('*** Creating links\n')
    # Link between the two tier-2 switches
    net.addLink(s1, s2, bw=1000)

    # Links from switches to hosts (Tier 3)
    net.addLink(hN1, s1, bw=100)
    net.addLink(hA1, s1, bw=100)
    net.addLink(hN2, s2, bw=100)
    net.addLink(hA2, s2, bw=100)

    info('*** Starting network\n')
    net.build() # Builds the network topology
    c0.start()  # Starts the controller (c0) process
    net.start() # Starts the Mininet network (switches connect to controller)

    info('*** Waiting for switches to connect to controller...\n')
    # Give switches a moment to connect and handshake with the controller
    sleep(2) # Small delay to ensure OpenFlow handshake completes

    # --- Call traffic_gen here after network starts ---
    traffic_gen(net)
    # --- End traffic_gen call ---

    # CLI(net) # Uncomment this line if you want to interact with the Mininet CLI after traffic generation
              # If left commented, the script will proceed to net.stop() immediately after traffic.

    info('*** Stopping network\n')
    net.stop() # This will stop the network after traffic generation (or CLI exit)

if __name__ == '__main__':
    setLogLevel('info')
    build()
