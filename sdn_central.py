#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import threading
import subprocess
import csv
import os
import random
from datetime import datetime

class ComplexTopo(Topo):
    def build(self):
        # Create core switches
        core1 = self.addSwitch('c1')
        core2 = self.addSwitch('c2')
        
        # Create distribution switches
        dist1 = self.addSwitch('d1')
        dist2 = self.addSwitch('d2')
        
        # Create access switches
        access1 = self.addSwitch('a1')
        access2 = self.addSwitch('a2')
        access3 = self.addSwitch('a3')
        
        # Create links between switches
        self.addLink(core1, core2, bw=1000)
        self.addLink(core1, dist1, bw=500)
        self.addLink(core1, dist2, bw=500)
        self.addLink(core2, dist1, bw=500)
        self.addLink(core2, dist2, bw=500)
        
        self.addLink(dist1, access1, bw=100)
        self.addLink(dist1, access2, bw=100)
        self.addLink(dist2, access3, bw=100)
        
        # Create hosts
        # Normal users
        for i in range(1, 6):
            self.addHost(f'user{i}', ip=f'10.0.1.{i}/24')
            self.addLink(f'user{i}', access1 if i <= 3 else access2)
        
        # Servers
        self.addHost('web', ip='10.0.2.1/24')
        self.addHost('db', ip='10.0.2.2/24')
        self.addLink('web', access2)
        self.addLink('db', access3)
        
        # Attackers
        self.addHost('attacker1', ip='10.0.3.1/24')
        self.addHost('attacker2', ip='10.0.3.2/24')
        self.addLink('attacker1', access3)
        self.addLink('attacker2', access3)

def generate_normal_traffic(net):
    """Simulate background traffic patterns"""
    hosts = [h for h in net.hosts if h.name.startswith('user') or h.name in ['web', 'db']]
    
    while True:
        src = random.choice(hosts)
        dst = random.choice(hosts)
        while dst == src:
            dst = random.choice(hosts)
            
        if src.name.startswith('user') and dst.name == 'web':
            src.cmd(f'curl -s http://{dst.IP()}/ > /dev/null &')
        elif src.name.startswith('user') and dst.name == 'db':
            src.cmd(f'nc -zv {dst.IP()} 3306 &')
        else:
            src.cmd(f'ping -c 2 {dst.IP()} > /dev/null &')
        
        time.sleep(random.uniform(0.1, 1.0))

def simulate_attacks(net):
    """Launch various attack patterns"""
    attackers = [h for h in net.hosts if h.name.startswith('attacker')]
    targets = [h for h in net.hosts if h.name in ['web', 'db'] or h.name.startswith('user')]
    
    while True:
        attacker = random.choice(attackers)
        target = random.choice(targets)
        
        attack_type = random.choice([
            f'hping3 -S -p 80 --flood {target.IP()}',
            f'hping3 --udp -p 53 --flood {target.IP()}',
            f'nmap -sS -p 1-1000 {target.IP()}'
        ])
        
        print(f"Launching attack from {attacker.name} to {target.IP()}")
        attacker.cmd(attack_type + ' &')
        time.sleep(random.uniform(5, 15))

def start_central_monitoring(net):
    """Centralized monitoring at controller level"""
    # Create directory for captures
    os.makedirs('pcaps', exist_ok=True)
    
    # Configure port mirroring (SPAN) on all switches to send traffic to controller
    for switch in net.switches:
        switch.cmd(f'ovs-vsctl -- --id=@m create mirror name=span-all '
                  f'select-all=true output-port=controller -- '
                  f'set bridge {switch.name} mirrors=@m')
    
    # Start centralized packet capture on controller
    net.get('c1').cmd('tcpdump -i any -w pcaps/central_capture.pcap &')
    
    # Start feature extraction
    threading.Thread(target=extract_central_features, daemon=True).start()

def extract_central_features():
    """Process centralized pcap file into features_central.csv"""
    csv_header = [
        'timestamp', 'src_ip', 'dst_ip', 'protocol',
        'length', 'src_port', 'dst_port', 'flags', 'ttl'
    ]
    
    while True:
        try:
            # Process the central pcap file
            cmd = [
                "tshark",
                "-r", "pcaps/central_capture.pcap",
                "-T", "fields",
                "-E", "separator=,",
                "-e", "frame.time",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "frame.protocols",
                "-e", "frame.len",
                "-e", "tcp.srcport", "-e", "udp.srcport",
                "-e", "tcp.dstport", "-e", "udp.dstport",
                "-e", "tcp.flags",
                "-e", "ip.ttl"
            ]
            
            # Write to features_central.csv
            with open('pcaps/features_central.csv', 'w') as f:
                writer = csv.writer(f)
                writer.writerow(csv_header)
                result = subprocess.run(cmd, stdout=f, text=True)
                
        except Exception as e:
            print(f"Feature extraction error: {str(e)}")
        
        time.sleep(10)  # Process every 10 seconds

def create_network():
    # Clean up previous runs
    os.system('sudo mn -c')
    os.system('rm -rf pcaps')
    
    net = Mininet(topo=ComplexTopo(), controller=RemoteController,
                 switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    
    # Add controllers
    c1 = net.addController('c1', controller=RemoteController,
                         ip='127.0.0.1', port=6653)
    c2 = net.addController('c2', controller=RemoteController,
                         ip='127.0.0.1', port=6654)
    
    net.start()
    
    # Configure OpenFlow
    for switch in net.switches:
        switch.cmd('ovs-vsctl set bridge %s protocols=OpenFlow13' % switch.name)
    
    # Start traffic generation
    threading.Thread(target=generate_normal_traffic, args=(net,), daemon=True).start()
    threading.Thread(target=simulate_attacks, args=(net,), daemon=True).start()
    
    # Start centralized monitoring
    start_central_monitoring(net)
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
