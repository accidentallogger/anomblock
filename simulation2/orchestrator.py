#!/usr/bin/env python3
import subprocess, time, os, signal, sys, pathlib

HERE = pathlib.Path(__file__).parent
env  = os.environ.copy(); env['PYTHONPATH'] = str(HERE)

def spawn(cmd, **kw): return subprocess.Popen(cmd, env=env, **kw)

def main():
    cont = spawn(['ryu-manager', 'controller/simple_switch_13.py'])
    # --- CHANGE THIS LINE ---
    sniff = spawn(['sudo', 'python3', 'capture/live_flow_export.py']) # ADD 'sudo' here
    # -----------------------
    time.sleep(5)                                     # give Ryu time
    topo  = spawn(['sudo','python3','topo/insdn_topo.py'])
    try:
        topo.wait()
    finally:
        # Send SIGINT to gracefully stop processes
        for p in (cont, sniff): p.send_signal(signal.SIGINT)
        # Wait for processes to actually terminate
        for p in (cont, sniff): p.wait()
        print('[+] Finished – dataset under flows_out/*.csv')

if __name__ == '__main__':
    main()
