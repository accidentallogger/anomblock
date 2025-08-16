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

def extract_features_to_csv(switch_name, switch_ip, interval=10):
    """Extract packet features to a unified CSV with switch metadata"""
    csv_header = [
        'timestamp', 'switch_name', 'switch_ip',
        'src_ip', 'dst_ip', 'protocol', 'length',
        'src_port', 'dst_port', 'flags', 'ttl'
    ]
    
    csv_file = "pcaps/features.csv"
    first_run = not os.path.exists(csv_file)
    
    while True:
        try:
            # Process any new packets
            cmd = [
                "tshark",
                "-r", f"pcaps/{switch_name}.pcap",
                "-T", "fields",
                "-E", "separator=|",
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
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            with open(csv_file, 'a', newline='') as f:
                writer = csv.writer(f)
                
                if first_run:
                    writer.writerow(csv_header)
                    first_run = False
                
                for line in result.stdout.splitlines():
                    if not line:
                        continue
                        
                    parts = line.split('|')
                    writer.writerow([
                        parts[0] if len(parts) > 0 else '',       # timestamp
                        switch_name,                             # switch name
                        switch_ip,                               # switch ip
                        parts[1] if len(parts) > 1 else '',      # src_ip
                        parts[2] if len(parts) > 2 else '',      # dst_ip
                        parts[3] if len(parts) > 3 else '',      # protocol
                        parts[4] if len(parts) > 4 else '',       # length
                        parts[5] if len(parts) > 5 else (parts[6] if len(parts) > 6 else ''),  # src_port
                        parts[7] if len(parts) > 7 else (parts[8] if len(parts) > 8 else ''),  # dst_port
                        parts[9] if len(parts) > 9 else '',      # flags
                        parts[10] if len(parts) > 10 else ''     # ttl
                    ])
                    
        except Exception as e:
            print(f"Error processing {switch_name}: {str(e)}")
            
        time.sleep(interval)

def start_monitoring(net):
    """Start monitoring with unified CSV output"""
    # Create directory structure
    net.get('c1').cmd('mkdir -p pcaps')
    
    # Define switch IP mapping
    switch_ips = {
        'c1': '10.0.0.1',
        'c2': '10.0.0.2',
        'd1': '10.0.1.1',
        'd2': '10.0.1.2',
        'a1': '10.0.2.1',
        'a2': '10.0.2.2',
        'a3': '10.0.2.3'
    }
    
    # Start packet capture and feature extraction
    for switch in net.switches:
        switch.cmd(f'tcpdump -i any -w pcaps/{switch.name}.pcap &')
        threading.Thread(
            target=extract_features_to_csv,
            args=(switch.name, switch_ips.get(switch.name, '')),
            daemon=True
        ).start()
    
    # Netflow configuration
    net.get('c1').cmd('ovs-vsctl -- --id=@nf create netflow targets=\"127.0.0.1:2055\" -- \
                     set bridge c1 netflow=@nf &')
    net.get('c2').cmd('ovs-vsctl -- --id=@nf create netflow targets=\"127.0.0.1:2055\" -- \
                     set bridge c2 netflow=@nf &')

def create_network():
    # Clean up previous runs
    os.system('sudo mn -c')
    os.system('rm -f pcaps/*.pcap pcaps/features.csv')
    
    net = Mininet(topo=ComplexTopo(), controller=RemoteController, 
                 switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    
    # Add controllers
    c1 = net.addController('c1', controller=RemoteController, 
                         ip='127.0.0.1', port=6653)
    c2 = net.addController('c2', controller=RemoteController,
                         ip='127.0.0.1', port=6654)
    
    net.start()
    
    # Configure OpenFlow version
    for switch in net.switches:
        switch.cmd(f'ovs-vsctl set bridge {switch.name} protocols=OpenFlow13')
    
    # Start traffic generation
    threading.Thread(target=generate_normal_traffic, args=(net,), daemon=True).start()
    threading.Thread(target=simulate_attacks, args=(net,), daemon=True).start()
    
    # Start monitoring
    start_monitoring(net)
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_network()
