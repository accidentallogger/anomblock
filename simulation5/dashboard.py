#!/usr/bin/env python3
"""
REAL-TIME SDN DASHBOARD WITH ML PREDICTION
Fixed version that doesn't interfere with Ryu controller CSV writing
"""

import asyncio
import websockets
import json
import time
import os
import threading
import pickle
import numpy as np
from http.server import SimpleHTTPRequestHandler, HTTPServer
import joblib


# --- Load XGBoost model artifacts ---
# --- Load XGBoost model artifacts ---
try:
    scaler = joblib.load("../modelxg/scaler.pkl")
    selector = joblib.load("../modelxg/selected_features.pkl")
    label_encoder = joblib.load("../modelxg/label_encoder.pkl")
    xgb_model = joblib.load("../modelxg/xgb_model.pkl")
    print("✅ ML models loaded successfully")
except Exception as e:
    print(f"❌ Failed to load ML models: {e}")
    print("⚠️  Running in monitoring-only mode (no predictions)")
    scaler = selector = label_encoder = xgb_model = None

# --- Dashboard Class ---
class RealTimeDashboard:
    def __init__(self, csv_path='/tmp/insdn_features.csv', websocket_port=8765, http_port=8000):
        self.csv_path = csv_path
        self.websocket_port = websocket_port
        self.http_port = http_port
        self.connected_clients = set()
        self.flows = []
        self.last_file_position = 0
        self.is_monitoring = False
        self.loop = None
        self.processed_flow_ids = set()
        self.empty_reads = 0
        
        # DO NOT clear CSV - let Ryu controller manage it
        print(f"📊 Monitoring existing CSV file: {csv_path}")

    # --- WebSocket Handling ---
    async def handle_websocket(self, websocket):
        self.connected_clients.add(websocket)
        print(f"🔌 WebSocket client connected. Total: {len(self.connected_clients)}")
        try:
            await websocket.send(json.dumps({
                'type': 'init', 
                'message': 'Connected to SDN Dashboard', 
                'total_flows': len(self.flows),
                'ml_loaded': scaler is not None
            }))
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    if message == 'ping':
                        await websocket.send('pong')
                except asyncio.TimeoutError:
                    try:
                        await websocket.send('ping')
                        resp = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                        if resp != 'pong': break
                    except: break
                except websockets.exceptions.ConnectionClosed:
                    break
        except Exception as e:
            print(f"WebSocket error: {e}")
        finally:
            self.connected_clients.discard(websocket)
            print(f"🔌 WebSocket client disconnected. Total: {len(self.connected_clients)}")

    async def broadcast(self, data):
        if not self.connected_clients: 
            return
        msg = json.dumps(data)
        disconnected = []
        for client in self.connected_clients:
            try: 
                await client.send(msg)
            except: 
                disconnected.append(client)
        for c in disconnected: 
            self.connected_clients.discard(c)

    # --- CSV Monitoring (NON-DESTRUCTIVE) ---
    def monitor_csv_file(self):
        print("🔍 Starting real-time CSV monitoring...")
        print("💡 IMPORTANT: Dashboard will NOT modify the CSV file")
        self.is_monitoring = True
        self.empty_reads = 0
        
        # Wait for CSV file to be created by Ryu controller
        while self.is_monitoring and not os.path.exists(self.csv_path):
            print(f"⏳ Waiting for CSV file to be created by Ryu controller...")
            time.sleep(2)
        
        # Get initial file size
        if os.path.exists(self.csv_path):
            self.last_file_position = os.path.getsize(self.csv_path)
            print(f"📁 Found CSV file, starting from position: {self.last_file_position}")
        
        while self.is_monitoring:
            try:
                if not os.path.exists(self.csv_path):
                    print(f"📁 CSV file not found, waiting...")
                    self.flows = []  # Clear flows when file disappears
                    self.last_file_position = 0
                    time.sleep(2)
                    continue

                current_size = os.path.getsize(self.csv_path)
                
                # Reset if file got smaller (was recreated)
                if current_size < self.last_file_position:
                    print("🔄 CSV file was recreated - resetting position")
                    self.last_file_position = 0
                    self.flows = []
                    continue
                
                # If file hasn't changed for 10 seconds, assume simulation stopped
                if current_size == self.last_file_position:
                    self.empty_reads += 1
                    if self.empty_reads > 20:  # 10 seconds (20 * 0.5s)
                        if self.empty_reads % 10 == 0:  # Only log every 5 seconds
                            print("💤 No new data for 10+ seconds")
                        time.sleep(0.5)
                        continue
                else:
                    self.empty_reads = 0

                # Only read if there's new content
                if self.last_file_position < current_size:
                    with open(self.csv_path, 'r') as file:
                        file.seek(self.last_file_position)
                        new_lines = file.readlines()
                        
                        if new_lines:
                            self.last_file_position = file.tell()
                            valid_new_flows = 0
                            
                            for line_num, line in enumerate(new_lines):
                                line = line.strip()
                                # Skip empty lines and header
                                if line and not line.startswith('Flow ID'):
                                    flow = self.parse_flow(line)
                                    if flow:
                                        # Create unique flow key to avoid duplicates
                                        flow_key = f"{flow['src_ip']}:{flow['src_port']}-{flow['dst_ip']}:{flow['dst_port']}-{flow['timestamp']}"
                                        if flow_key not in self.processed_flow_ids:
                                            self.processed_flow_ids.add(flow_key)
                                            
                                            # Add ML prediction if models are loaded
                                            if scaler is not None:
                                                flow['prediction'] = self.predict_flow(flow)
                                            else:
                                                flow['prediction'] = flow.get('attack_type', 'unknown')
                                            
                                            self.flows.append(flow)
                                            valid_new_flows += 1
                                            
                                            # Log the new flow
                                            pred_status = flow['prediction']
                                            if pred_status != 'Normal':
                                                print(f"🚨 ALERT: {flow['src_ip']} → {flow['dst_ip']} | Predicted: {pred_status}")
                                            else:
                                                print(f"✅ Normal: {flow['src_ip']} → {flow['dst_ip']} | {flow['total_packets']} packets")
                                            
                                            # Limit flows to prevent memory issues
                                            if len(self.flows) > 100:
                                                # Remove oldest flows
                                                removed_flows = self.flows[:50]
                                                self.flows = self.flows[50:]
                                                # Clean up processed IDs
                                                for f in removed_flows:
                                                    flow_key = f"{f['src_ip']}:{f['src_port']}-{f['dst_ip']}:{f['dst_port']}-{f['timestamp']}"
                                                    self.processed_flow_ids.discard(flow_key)
                                            
                                            # Broadcast to WebSocket clients
                                            if self.loop:
                                                asyncio.run_coroutine_threadsafe(
                                                    self.broadcast({
                                                        'type': 'new_flow', 
                                                        'flow': flow, 
                                                        'total_flows': len(self.flows), 
                                                        'timestamp': time.time()
                                                    }),
                                                    self.loop
                                                )
                            
                            if valid_new_flows > 0:
                                print(f"📊 Processed {valid_new_flows} new flows")
                                
                time.sleep(0.5)  # Check every 500ms
                
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(1)

    def parse_flow(self, line):
        try:
            parts = line.split(',')
            if len(parts) < 84:
                print(f"⚠️ Incomplete flow data: {len(parts)} columns")
                return None
            
            # Validate numeric fields
            try:
                src_port = int(parts[2]) if parts[2] else 0
                dst_port = int(parts[4]) if parts[4] else 0
                total_fwd_pkts = int(parts[8]) if parts[8] else 0
                total_bwd_pkts = int(parts[9]) if parts[9] else 0
                total_packets = total_fwd_pkts + total_bwd_pkts
                total_bytes = (int(parts[10]) if parts[10] else 0) + (int(parts[11]) if parts[11] else 0)
            except (ValueError, IndexError) as e:
                print(f"⚠️ Invalid numeric data in flow: {e}")
                return None
                
            return {
                'flow_id': parts[0],
                'src_ip': parts[1],
                'src_port': src_port,
                'dst_ip': parts[3],
                'dst_port': dst_port,
                'protocol': parts[5],
                'timestamp': float(parts[6]) if parts[6] else 0,
                'duration': float(parts[7]) if parts[7] else 0,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'attack_type': parts[83] if len(parts) > 83 else 'unknown',
                'features': parts[8:83],  # exclude last column (label)
                'received_at': time.time()
            }
        except Exception as e:
            print(f"❌ Parse error: {e} - Line: {line[:100]}...")
            return None
        
    # --- ML Prediction ---
    def predict_flow(self, flow):
        try:
            if scaler is None:
                return "no_model"
                
            # Convert features to numpy array
            feature_list = []
            for feat in flow['features']:
                try:
                    feature_list.append(float(feat) if feat else 0.0)
                except ValueError:
                    feature_list.append(0.0)
            
            feats = np.array(feature_list).reshape(1, -1)
            feats_scaled = scaler.transform(feats)
            feats_selected = selector.transform(feats_scaled)
            pred = xgb_model.predict(feats_selected)
            return label_encoder.inverse_transform(pred)[0]
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return "prediction_error"

    # --- Start Monitoring ---
    def start_monitoring(self):
        t = threading.Thread(target=self.monitor_csv_file, daemon=True)
        t.start()
        print("✅ Real-time monitoring started")

    # --- WebSocket Server ---
    async def start_websocket_server(self):
        print(f"🌐 Starting WebSocket server on port {self.websocket_port}")
        async with websockets.serve(self.handle_websocket, "0.0.0.0", self.websocket_port):
            print("✅ WebSocket server ready")
            await asyncio.Future()

    # --- HTTP Server ---
    def start_http_server(self):
        class DashboardHandler(SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=os.path.dirname(os.path.abspath(__file__)), **k)
            
            def log_message(self, fmt, *args): 
                pass  # Suppress HTTP logs
                
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self.get_dashboard_html().encode())
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        'status': 'ok',
                        'websocket_port': 8765,
                        'total_flows': len(dashboard.flows),
                        'ml_loaded': scaler is not None
                    }).encode())
                else:
                    super().do_GET()
                    
            def get_dashboard_html(self):
                ml_status = "✅ ML Models Loaded" if scaler is not None else "⚠️ ML Models Not Available"
                return f"""
<!DOCTYPE html>
<html>
<head>
<title>Real-Time SDN Dashboard</title>
<meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; margin: 0; }}
.dashboard {{ max-width: 1400px; margin: auto; }}
.header {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
.stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }}
.stat-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
.stat-number {{ font-size: 2em; font-weight: bold; color: #333; }}
.flows-container {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-height: 600px; overflow-y: auto; }}
.flow-item {{ padding: 15px; margin: 10px 0; border-left: 5px solid #007bff; background: #f8f9fa; border-radius: 5px; }}
.flow-item.attack {{ border-left-color: #dc3545; background: #f8d7da; }}
.flow-item.benign {{ border-left-color: #28a745; background: #d4edda; }}
.flow-item.unknown {{ border-left-color: #6c757d; background: #e2e3e5; }}
.connection-status {{ position: fixed; top: 10px; right: 10px; padding: 10px; border-radius: 5px; font-weight: bold; z-index: 1000; }}
.connected {{ background: #d4edda; color: #155724; border: 2px solid #28a745; }}
.disconnected {{ background: #f8d7da; color: #721c24; border: 2px solid #dc3545; }}
.reconnecting {{ background: #fff3cd; color: #856404; border: 2px solid #ffc107; }}
.ml-status {{ position: fixed; top: 10px; left: 10px; padding: 10px; border-radius: 5px; background: #cce7ff; border: 2px solid #007bff; }}
.attack-counter {{ background: #dc3545; color: white; padding: 5px 10px; border-radius: 15px; font-weight: bold; }}
</style>
</head>
<body>
<div class="ml-status" id="mlStatus">{ml_status}</div>
<div class="connection-status disconnected" id="connectionStatus">Disconnected</div>

<div class="dashboard">
<div class="header">
<h1>🚨 Real-Time SDN Security Dashboard</h1>
<p>Live network traffic monitoring with ML-powered threat detection</p>
</div>

<div class="stats">
<div class="stat-card">
    <div>Total Flows</div>
    <div class="stat-number" id="totalFlows">0</div>
</div>
<div class="stat-card">
    <div>Active Alerts</div>
    <div class="stat-number" id="attackCount">0</div>
</div>
<div class="stat-card">
    <div>Last Update</div>
    <div id="lastUpdate">Never</div>
</div>
<div class="stat-card">
    <div>Status</div>
    <div id="currentStatus">Waiting...</div>
</div>
</div>

<div class="flows-container">
<h3>📡 Live Network Flows <span id="liveIndicator" style="color: #dc3545;">●</span></h3>
<div id="flowsList">
    <div style="text-align: center; padding: 40px; color: #666;">
        <div>Waiting for incoming network flows...</div>
        <div style="font-size: 0.9em; margin-top: 10px;">Make sure Ryu controller is running and generating traffic</div>
    </div>
</div>
</div>
</div>

<script>
class RealTimeDashboard {{
    constructor() {{
        this.ws = null;
        this.flowCount = 0;
        this.attackCount = 0;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 10;
        this.reconnectDelay = 3000;
        this.isConnected = false;
        this.liveIndicator = document.getElementById('liveIndicator');
        this.connect();
    }}
    
    connect() {{
        try {{
            this.updateStatus('Connecting...', 'reconnecting');
            const wsHost = window.location.hostname;
            this.ws = new WebSocket(`ws://${{wsHost}}:8765`);
            
            this.ws.onopen = () => {{
                this.isConnected = true;
                this.reconnectAttempts = 0;
                this.updateStatus('Connected - Live monitoring', 'connected');
                this.startLiveIndicator();
                this.updateDisplay();
            }};
            
            this.ws.onmessage = (event) => {{
                try {{
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                }} catch(e) {{
                    console.log('Non-JSON message:', event.data);
                }}
            }};
            
            this.ws.onclose = (event) => {{
                this.isConnected = false;
                this.stopLiveIndicator();
                this.handleDisconnection();
            }};
            
            this.ws.onerror = (error) => {{
                this.isConnected = false;
                this.stopLiveIndicator();
                this.updateStatus('Connection error', 'disconnected');
            }};
        }} catch(error) {{
            this.handleDisconnection();
        }}
    }}
    
    handleMessage(data) {{
        switch(data.type) {{
            case 'init':
                this.flowCount = data.total_flows || 0;
                this.updateDisplay();
                break;
            case 'new_flow':
                this.addFlow(data.flow);
                this.flowCount = data.total_flows || 0;
                this.updateDisplay();
                break;
        }}
    }}
    
    addFlow(flow) {{
        const flowsList = document.getElementById('flowsList');
        
        // Clear waiting message if this is the first flow
        if (flowsList.children.length === 1 && flowsList.children[0].textContent.includes('Waiting')) {{
            flowsList.innerHTML = '';
        }}
        
        const flowElement = document.createElement('div');
        const isAttack = flow.prediction !== 'benign';
        const isUnknown = flow.prediction === 'unknown' || flow.prediction === 'prediction_error' || flow.prediction === 'no_model';
        
        if (isAttack) this.attackCount++;
        
        let className = 'benign';
        if (isAttack) className = 'attack';
        if (isUnknown) className = 'unknown';
        
        flowElement.className = `flow-item ${{className}}`;
        
        const protocolNames = {{'6': 'TCP', '17': 'UDP', '1': 'ICMP'}};
        const protocol = protocolNames[flow.protocol] || flow.protocol;
        
        flowElement.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="flex: 1;">
                    <strong>${{new Date().toLocaleTimeString()}}</strong><br>
                    <strong style="font-size: 1.1em;">${{flow.src_ip}}:${{flow.src_port}} → ${{flow.dst_ip}}:${{flow.dst_port}}</strong><br>
                    Protocol: ${{protocol}} | Packets: ${{flow.total_packets}} | Bytes: ${{flow.total_bytes}} | Duration: ${{flow.duration.toFixed(3)}}s
                </div>
                <div style="text-align: right;">
                    <span style="font-size: 1.1em; font-weight: bold; color: ${{isAttack ? '#dc3545' : (isUnknown ? '#6c757d' : '#28a745')}}">
                        ${{flow.prediction.toUpperCase()}}
                    </span>
                    ${{isAttack ? '<div class="attack-counter">ALERT</div>' : ''}}
                </div>
            </div>
        `;
        
        flowsList.insertBefore(flowElement, flowsList.firstChild);
        
        // Limit displayed flows to prevent performance issues
        if (flowsList.children.length > 50) {{
            flowsList.removeChild(flowsList.lastChild);
        }}
        
        // Add visual highlight for new flows
        flowElement.style.animation = 'highlight 0.5s ease-in-out';
        setTimeout(() => {{
            flowElement.style.animation = '';
        }}, 500);
    }}
    
    updateDisplay() {{
        document.getElementById('totalFlows').textContent = this.flowCount;
        document.getElementById('attackCount').textContent = this.attackCount;
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        document.getElementById('currentStatus').textContent = this.isConnected ? 'Live Monitoring' : 'Disconnected';
    }}
    
    updateStatus(msg, className) {{
        const status = document.getElementById('connectionStatus');
        status.textContent = msg;
        status.className = `connection-status ${{className}}`;
    }}
    
    startLiveIndicator() {{
        let visible = true;
        this.liveInterval = setInterval(() => {{
            this.liveIndicator.style.color = visible ? '#dc3545' : '#ccc';
            visible = !visible;
        }}, 1000);
    }}
    
    stopLiveIndicator() {{
        if (this.liveInterval) {{
            clearInterval(this.liveInterval);
            this.liveIndicator.style.color = '#ccc';
        }}
    }}
    
    handleDisconnection() {{
        this.updateStatus('Disconnected - Reconnecting...', 'disconnected');
        this.updateDisplay();
        if (this.reconnectAttempts < this.maxReconnectAttempts) {{
            this.reconnectAttempts++;
            setTimeout(() => this.connect(), this.reconnectDelay);
        }} else {{
            this.updateStatus('Failed to connect - Refresh page', 'disconnected');
        }}
    }}
    
    sendPing() {{
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {{
            this.ws.send('ping');
        }}
    }}
}}

// Add highlight animation
const style = document.createElement('style');
style.textContent = `
    @keyframes highlight {{
        from {{ background-color: #ffff99; }}
        to {{ background-color: inherit; }}
    }}
`;
document.head.appendChild(style);

window.addEventListener('load', () => {{
    window.dashboard = new RealTimeDashboard();
    setInterval(() => {{
        if (window.dashboard) {{
            window.dashboard.sendPing();
        }}
    }}, 25000);
}});
</script>
</body>
</html>
"""
        server = HTTPServer(('0.0.0.0', self.http_port), DashboardHandler)
        try:
            print(f"🌍 Starting HTTP server on port {self.http_port}")
            server.serve_forever()
        except KeyboardInterrupt:
            print("HTTP server stopped")
            server.shutdown()

    # --- Run Dashboard ---
    async def run(self):
        print("🚀 Starting Real-Time SDN Dashboard")
        print(f"📊 Monitoring CSV: {self.csv_path}")
        print("💡 Dashboard will NOT modify the CSV file")
        print("🔧 Make sure Ryu controller is running separately")
        
        self.loop = asyncio.get_event_loop()
        
        # Start HTTP server in background thread
        threading.Thread(target=self.start_http_server, daemon=True).start()
        
        # Start monitoring
        self.start_monitoring()
        
        # Start WebSocket server
        await self.start_websocket_server()


if __name__ == "__main__":
    dashboard = RealTimeDashboard()
    try:
        asyncio.run(dashboard.run())
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
        dashboard.is_monitoring = False