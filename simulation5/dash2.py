#!/usr/bin/env python3
"""
Real-time SDN Threat Dashboard with ML-based intrusion detection.
Run: sudo python3 dashboard.py
Open http://localhost:8000
"""

import asyncio
import websockets
import json
import time
import os
import threading
import numpy as np
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import joblib

# ---------- Robust model loading ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Try parent directory first, then same directory
model_candidates = [
    os.path.join(BASE_DIR, "..", "modelxg"),
    os.path.join(BASE_DIR, "modelxg")
]

scaler = selector = label_encoder = xgb_model = None
for model_dir in model_candidates:
    try:
        scaler = joblib.load(os.path.join(model_dir, "scaler.pkl"))
        selector = joblib.load(os.path.join(model_dir, "selected_features.pkl"))
        label_encoder = joblib.load(os.path.join(model_dir, "label_encoder.pkl"))
        xgb_model = joblib.load(os.path.join(model_dir, "xgb_model.pkl"))
        print(f"✅ ML models loaded from: {model_dir}")
        break
    except Exception:
        continue

if scaler is None:
    print("❌ Could not load ML models. Check modelxg/ folder location.")
    print("⚠️  Running in monitoring-only mode (no predictions)")

# ---------- Dashboard Class ----------
class RealTimeDashboard:
    def __init__(self, csv_path='/tmp/insdn_features.csv', websocket_port=8765, http_port=8000):
        self.csv_path = csv_path
        self.websocket_port = websocket_port
        self.http_port = http_port
        self.connected_clients = set()
        self.flows = []                 # all parsed flows
        self.alerts = []                # high-confidence attacks
        self.last_file_position = 0
        self.is_monitoring = False
        self.loop = None
        self.processed_flow_ids = set()
        self.empty_reads = 0
        self.alert_counter = 0

        print(f"📊 Monitoring existing CSV file: {csv_path}")

    # --- WebSocket ---
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

    # --- CSV Monitoring ---
    def monitor_csv_file(self):
        print("🔍 Starting real-time CSV monitoring...")
        print("💡 Dashboard will NOT modify the CSV file")
        self.is_monitoring = True
        self.empty_reads = 0

        while self.is_monitoring and not os.path.exists(self.csv_path):
            print("⏳ Waiting for CSV file from Ryu controller...")
            time.sleep(2)

        if os.path.exists(self.csv_path):
            self.last_file_position = os.path.getsize(self.csv_path)
            print(f"📁 Found CSV file, starting at position {self.last_file_position}")

        while self.is_monitoring:
            try:
                if not os.path.exists(self.csv_path):
                    print("📁 CSV file missing, clearing flows...")
                    self.flows.clear()
                    self.last_file_position = 0
                    time.sleep(2)
                    continue

                current_size = os.path.getsize(self.csv_path)
                if current_size < self.last_file_position:
                    print("🔄 CSV recreated – resetting position")
                    self.last_file_position = 0
                    self.flows.clear()
                    continue

                if current_size == self.last_file_position:
                    self.empty_reads += 1
                    if self.empty_reads > 20 and self.empty_reads % 10 == 0:
                        print("💤 No new data for 10+ seconds")
                    time.sleep(0.5)
                    continue
                else:
                    self.empty_reads = 0

                if self.last_file_position < current_size:
                    with open(self.csv_path, 'r') as file:
                        file.seek(self.last_file_position)
                        new_lines = file.readlines()
                        if new_lines:
                            self.last_file_position = file.tell()
                            valid = 0
                            for line in new_lines:
                                line = line.strip()
                                if line and not line.startswith('Flow ID'):
                                    flow = self.parse_flow(line)
                                    if not flow:
                                        continue
                                    flow_key = f"{flow['src_ip']}:{flow['src_port']}-{flow['dst_ip']}:{flow['dst_port']}-{flow['timestamp']}"
                                    if flow_key in self.processed_flow_ids:
                                        continue
                                    self.processed_flow_ids.add(flow_key)

                                    if scaler:
                                        pred_lbl, conf = self.predict_flow(flow)
                                        flow['prediction'] = pred_lbl
                                        flow['confidence'] = conf
                                    else:
                                        flow['prediction'] = flow.get('attack_type', 'unknown')
                                        flow['confidence'] = 0.0

                                    self.flows.append(flow)
                                    valid += 1

                                    # Alert if attack + high confidence
                                    if flow['prediction'] not in ('Normal', 'benign', 'unknown', 'prediction_error', 'no_model'):
                                        self.alerts.append(flow)
                                        self.alert_counter += 1
                                        print(f"🚨 [{flow['prediction']}] {flow['src_ip']} → {flow['dst_ip']} (conf: {flow['confidence']:.2f})")
                                    else:
                                        print(f"✅ Normal: {flow['src_ip']} → {flow['dst_ip']} | {flow['total_packets']} pkts")

                                    # Memory limits
                                    if len(self.flows) > 200:
                                        removed = self.flows[:100]
                                        self.flows = self.flows[100:]
                                        for f in removed:
                                            fkey = f"{f['src_ip']}:{f['src_port']}-{f['dst_ip']}:{f['dst_port']}-{f['timestamp']}"
                                            self.processed_flow_ids.discard(fkey)
                                    if len(self.alerts) > 500:
                                        self.alerts = self.alerts[-300:]

                                    # Broadcast to UI
                                    if self.loop:
                                        asyncio.run_coroutine_threadsafe(
                                            self.broadcast({
                                                'type': 'new_flow',
                                                'flow': flow,
                                                'total_flows': len(self.flows),
                                                'total_alerts': self.alert_counter,
                                                'timestamp': time.time()
                                            }),
                                            self.loop
                                        )
                            if valid > 0:
                                print(f"📊 Processed {valid} new flow(s)")
                time.sleep(0.5)
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(1)

    def parse_flow(self, line):
        try:
            parts = line.split(',')
            if len(parts) < 84:
                return None
            src_port = int(parts[2]) if parts[2] else 0
            dst_port = int(parts[4]) if parts[4] else 0
            fwd_pkts = int(parts[8]) if parts[8] else 0
            bwd_pkts = int(parts[9]) if parts[9] else 0
            tot_pkts = fwd_pkts + bwd_pkts
            tot_bytes = (int(parts[10]) if parts[10] else 0) + (int(parts[11]) if parts[11] else 0)

            return {
                'flow_id': parts[0],
                'src_ip': parts[1],
                'src_port': src_port,
                'dst_ip': parts[3],
                'dst_port': dst_port,
                'protocol': parts[5],
                'timestamp': float(parts[6]) if parts[6] else 0,
                'duration': float(parts[7]) if parts[7] else 0,
                'total_packets': tot_pkts,
                'total_bytes': tot_bytes,
                'attack_type': parts[83] if len(parts) > 83 else 'unknown',
                'features': parts[8:83],
                'received_at': time.time()
            }
        except Exception as e:
            print(f"❌ Parse error: {e} - Line: {line[:100]}...")
            return None

    def predict_flow(self, flow):
        try:
            feat_list = []
            for f in flow['features']:
                try:
                    feat_list.append(float(f) if f else 0.0)
                except ValueError:
                    feat_list.append(0.0)
            feats = np.array(feat_list).reshape(1, -1)
            feats_scaled = scaler.transform(feats)
            feats_selected = selector.transform(feats_scaled)
            probs = xgb_model.predict_proba(feats_selected)[0]
            idx = probs.argmax()
            label = label_encoder.inverse_transform([idx])[0]
            conf = float(probs[idx])
            return label, conf
        except Exception as e:
            print(f"❌ Prediction error: {e}")
            return "prediction_error", 0.0

    def start_monitoring(self):
        t = threading.Thread(target=self.monitor_csv_file, daemon=True)
        t.start()
        print("✅ Real-time monitoring thread started")

    async def start_websocket_server(self):
        print(f"🌐 WebSocket server on port {self.websocket_port}")
        async with websockets.serve(self.handle_websocket, "0.0.0.0", self.websocket_port):
            print("✅ WebSocket server ready")
            await asyncio.Future()

    # --- HTTP Server ---
    def start_http_server(self):
        dashboard_self = self

        class DashboardHandler(SimpleHTTPRequestHandler):
            def __init__(self, *a, **k):
                super().__init__(*a, directory=BASE_DIR, **k)

            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path
                query = parse_qs(parsed.query)

                if path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(get_dashboard_html().encode())
                elif path == '/health':
                    self.send_json({
                        'status': 'ok',
                        'websocket_port': dashboard_self.websocket_port,
                        'total_flows': len(dashboard_self.flows),
                        'ml_loaded': scaler is not None
                    })
                elif path == '/api/alerts':
                    self.send_json(dashboard_self.alerts[-200:])
                elif path == '/api/alerts/csv':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/csv')
                    self.send_header('Content-Disposition', 'attachment; filename="alerts.csv"')
                    self.end_headers()
                    header = "timestamp,prediction,confidence,src_ip,src_port,dst_ip,dst_port,protocol,duration,total_packets,total_bytes\n"
                    self.wfile.write(header.encode())
                    for a in dashboard_self.alerts[-500:]:
                        row = f"{a.get('timestamp','')},{a.get('prediction','')},{a.get('confidence',0):.3f},{a.get('src_ip','')},{a.get('src_port',0)},{a.get('dst_ip','')},{a.get('dst_port',0)},{a.get('protocol','')},{a.get('duration',0)},{a.get('total_packets',0)},{a.get('total_bytes',0)}\n"
                        self.wfile.write(row.encode())
                else:
                    super().do_GET()

            def send_json(self, data):
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

        def get_dashboard_html():
            ml_status = "✅ ML Models Loaded" if scaler is not None else "⚠️ ML not loaded"
            # Note: To run offline, download chart.js and put it next to this script.
            chartjs_src = "https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
            # Uncomment next line and comment above to use local file:
            # chartjs_src = "chart.umd.min.js"

            return f"""<!DOCTYPE html>
<html>
<head>
<title>SDN Threat Dashboard</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<script src="{chartjs_src}"></script>
<style>
:root {{
    --bg: #f5f5f5;
    --card-bg: #ffffff;
    --text: #333;
    --border: #ddd;
    --flow-bg: #f8f9fa;
}}
.dark-mode {{
    --bg: #1a1a2e;
    --card-bg: #16213e;
    --text: #e0e0e0;
    --border: #30475e;
    --flow-bg: #0f3460;
}}
body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 20px;
    margin: 0;
    transition: background 0.3s;
}}
.dashboard {{ max-width: 1400px; margin: auto; }}
.header {{
    background: var(--card-bg);
    padding: 20px;
    border-radius: 10px;
    margin-bottom: 20px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
}}
.stats {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 15px;
    margin-bottom: 20px;
}}
.stat-card {{
    background: var(--card-bg);
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}}
.stat-number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
.charts-container {{
    display: grid;
    grid-template-columns: 1fr 2fr;
    gap: 20px;
    margin-bottom: 20px;
}}
.chart-box {{
    background: var(--card-bg);
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}}
.controls {{
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
    flex-wrap: wrap;
    align-items: center;
}}
.controls select, .controls button {{
    padding: 8px 12px;
    border-radius: 5px;
    border: 1px solid var(--border);
    background: var(--card-bg);
    color: var(--text);
    cursor: pointer;
}}
.flows-container {{
    background: var(--card-bg);
    padding: 20px;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    max-height: 500px;
    overflow-y: auto;
}}
.flow-item {{
    padding: 15px;
    margin: 10px 0;
    border-left: 5px solid #007bff;
    background: var(--flow-bg);
    border-radius: 5px;
    cursor: pointer;
    transition: transform 0.1s;
}}
.flow-item:hover {{ transform: scale(1.01); }}
.flow-item.attack {{ border-left-color: #dc3545; background: #f8d7da; color: #333; }}
.flow-item.benign {{ border-left-color: #28a745; background: #d4edda; }}
.flow-item.unknown {{ border-left-color: #6c757d; background: #e2e3e5; }}
.modal {{
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0; top: 0;
    width: 100%; height: 100%;
    overflow: auto;
    background: rgba(0,0,0,0.5);
}}
.modal-content {{
    background: var(--card-bg);
    margin: 5% auto;
    padding: 20px;
    border-radius: 10px;
    width: 80%;
    max-height: 80%;
    overflow-y: auto;
    box-shadow: 0 5px 20px rgba(0,0,0,0.3);
}}
.close-modal {{
    float: right;
    font-size: 28px;
    cursor: pointer;
    color: var(--text);
}}
.dark-toggle {{
    position: fixed;
    top: 10px; right: 10px;
    z-index: 999;
}}
.connection-status {{
    position: fixed;
    top: 10px; left: 10px;
    padding: 8px 15px;
    border-radius: 5px;
    font-weight: bold;
    z-index: 1000;
    background: #d4edda; color: #155724;
}}
.connection-status.disconnected {{
    background: #f8d7da; color: #721c24;
}}
@media (max-width: 768px) {{
    .stats, .charts-container {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="dark-toggle">
    <button id="darkModeBtn" onclick="toggleDarkMode()" style="padding:8px 12px; border-radius:5px; border:1px solid #ccc; background: var(--card-bg); color: var(--text);">🌓 Dark Mode</button>
</div>
<div class="connection-status disconnected" id="connectionStatus">Disconnected</div>

<div class="dashboard">
<div class="header">
    <div>
        <h1>🚨 SDN Threat Dashboard</h1>
        <p>Real-time ML-powered intrusion detection</p>
    </div>
    <div id="mlStatus">{ml_status}</div>
</div>

<div class="stats">
    <div class="stat-card"><div>Total Flows</div><div class="stat-number" id="totalFlows">0</div></div>
    <div class="stat-card"><div>Active Alerts</div><div class="stat-number" id="alertCount">0</div></div>
    <div class="stat-card"><div>Last Update</div><div id="lastUpdate">--</div></div>
    <div class="stat-card"><div>Status</div><div id="currentStatus">Waiting...</div></div>
</div>

<div class="charts-container">
    <div class="chart-box">
        <h3>Attack Types</h3>
        <canvas id="attackChart" width="300" height="300"></canvas>
    </div>
    <div class="chart-box">
        <h3>Alert Timeline (last 10 min)</h3>
        <canvas id="timelineChart" width="500" height="200"></canvas>
    </div>
</div>

<div class="controls">
    <label>Filter: </label>
    <select id="filterType">
        <option value="all">All Traffic</option>
        <option value="DoS">DoS</option>
        <option value="DDoS">DDoS</option>
        <option value="Web">Web Attack</option>
        <option value="BruteForce">Brute Force</option>
        <option value="Probe">Probe</option>
        <option value="Botnet">Botnet</option>
        <option value="U2R">U2R</option>
        <option value="Normal">Normal</option>
    </select>
    <button onclick="exportAlerts()">📥 Export Alerts CSV</button>
    <button onclick="toggleAutoScroll()">⏯️ Auto-Scroll <span id="scrollStatus">ON</span></button>
    <button id="darkModeBtn2" onclick="toggleDarkMode()">🌓 Dark Mode</button>
</div>

<div class="flows-container">
<h3>📡 Live Network Flows <span id="liveIndicator" style="color: #dc3545;">●</span></h3>
<div id="flowsList">
    <div style="text-align:center; padding:40px; color:#666;">Waiting for incoming flows...</div>
</div>
</div>
</div>

<!-- Flow Detail Modal -->
<div id="flowModal" class="modal">
    <div class="modal-content">
        <span class="close-modal" onclick="closeModal()">&times;</span>
        <h2 id="modalTitle">Flow Details</h2>
        <pre id="modalContent" style="white-space:pre-wrap; word-wrap:break-word;"></pre>
    </div>
</div>

<script>
// ---------- Global State ----------
let flows = [];
let alerts = [];
let attackCounts = {{}};
let autoScroll = true;
let chartInstances = {{}};

// ---------- Charts ----------
function initCharts() {{
    const attackCtx = document.getElementById('attackChart').getContext('2d');
    chartInstances.attack = new Chart(attackCtx, {{
        type: 'doughnut',
        data: {{
            labels: [],
            datasets: [{{ data: [], backgroundColor: ['#dc3545','#fd7e14','#ffc107','#20c997','#6f42c1','#0dcaf0','#28a745','#6c757d'] }}]
        }},
        options: {{ responsive: true, plugins: {{ legend: {{ position: 'bottom' }} }} }}
    }});

    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    chartInstances.timeline = new Chart(timelineCtx, {{
        type: 'line',
        data: {{
            labels: [],
            datasets: [{{ label: 'Alerts/min', data: [], borderColor: '#dc3545', tension: 0.3 }}]
        }},
        options: {{ scales: {{ y: {{ beginAtZero: true }} }} }}
    }});
}}

function updateCharts() {{
    // Attack distribution
    const labels = Object.keys(attackCounts);
    const values = Object.values(attackCounts);
    chartInstances.attack.data.labels = labels;
    chartInstances.attack.data.datasets[0].data = values;
    chartInstances.attack.update();

    // Timeline (last 10 minutes)
    const now = new Date();
    const labelsT = [];
    const dataT = [];
    for (let i = 9; i >= 0; i--) {{
        const d = new Date(now - i*60000);
        labelsT.push(d.getHours()+':'+String(d.getMinutes()).padStart(2,'0'));
        dataT.push(0);
    }}
    alerts.forEach(a => {{
        const t = new Date(a.timestamp * 1000);
        const diffMin = (now - t) / 60000;
        const idx = Math.floor(9 - diffMin);
        if (idx >= 0 && idx < 10) dataT[idx]++;
    }});
    chartInstances.timeline.data.labels = labelsT;
    chartInstances.timeline.data.datasets[0].data = dataT;
    chartInstances.timeline.update();
}}

// ---------- Flow Handling ----------
function addFlow(flow) {{
    flows.unshift(flow);
    const pred = flow.prediction;
    attackCounts[pred] = (attackCounts[pred] || 0) + 1;

    // Alert collection & browser notification
    if (pred !== 'Normal' && pred !== 'benign' && pred !== 'unknown' && pred !== 'prediction_error' && pred !== 'no_model') {{
        alerts.unshift(flow);
        if (Notification.permission === "granted" && flow.confidence > 0.8) {{
            new Notification(`⚠️ ${{pred}} from ${{flow.src_ip}}`, {{
                body: `Confidence: ${{(flow.confidence*100).toFixed(1)}}%`
            }});
        }}
    }}

    // Filter handling – skip if doesn't match
    const filterVal = document.getElementById('filterType').value;
    if (filterVal !== 'all') {{
        if (filterVal === 'Normal') {{
            if (pred !== 'Normal' && pred !== 'benign') return;
        }} else {{
            if (pred !== filterVal) return;
        }}
    }}

    const flowsList = document.getElementById('flowsList');
    // Remove waiting message
    if (flowsList.children.length === 1 && flowsList.children[0].textContent.includes('Waiting')) {{
        flowsList.innerHTML = '';
    }}

    const isAttack = pred !== 'Normal' && pred !== 'benign' && pred !== 'unknown' && pred !== 'prediction_error' && pred !== 'no_model';
    let className = 'benign';
    if (isAttack) className = 'attack';
    if (pred === 'unknown' || pred === 'prediction_error' || pred === 'no_model') className = 'unknown';

    const protoNames = {{'6':'TCP','17':'UDP','1':'ICMP'}};
    const proto = protoNames[flow.protocol] || flow.protocol;

    const div = document.createElement('div');
    div.className = `flow-item ${{className}}`;
    div.dataset.prediction = pred;
    div.innerHTML = `
        <div style="display:flex; justify-content:space-between;">
            <div>
                <strong>${{new Date(flow.timestamp*1000).toLocaleTimeString()}}</strong><br>
                <strong>${{flow.src_ip}}:${{flow.src_port}} → ${{flow.dst_ip}}:${{flow.dst_port}}</strong><br>
                ${{proto}} | ${{flow.total_packets}} pkts | ${{(flow.total_bytes/1024).toFixed(1)}} KB
            </div>
            <div style="text-align:right;">
                <span style="font-weight:bold; color:${{isAttack ? '#dc3545' : '#28a745'}}">
                    ${{pred}} (${{(flow.confidence*100).toFixed(0)}}%)
                </span>
            </div>
        </div>
    `;
    div.onclick = () => showFlowDetails(flow);
    flowsList.insertBefore(div, flowsList.firstChild);

    if (flowsList.children.length > 100) {{
        flowsList.removeChild(flowsList.lastChild);
    }}

    if (autoScroll) flowsList.scrollTop = 0;
    updateStats();
    updateCharts();
}}

function showFlowDetails(flow) {{
    document.getElementById('modalTitle').innerText = `${{flow.src_ip}} → ${{flow.dst_ip}}`;
    let content = `Flow ID: ${{flow.flow_id}}\nTimestamp: ${{new Date(flow.timestamp*1000).toLocaleString()}}\nDuration: ${{flow.duration.toFixed(4)}}s\nProtocol: ${{flow.protocol}}\nPackets: ${{flow.total_packets}}  Bytes: ${{flow.total_bytes}}\nPrediction: ${{flow.prediction}} (conf: ${{(flow.confidence*100).toFixed(1)}}%)\nAttack label: ${{flow.attack_type}}\nFeatures: [\n`;
    if (flow.features && flow.features.length) {{
        content += flow.features.join(', ');
    }}
    content += ']';
    document.getElementById('modalContent').innerText = content;
    document.getElementById('flowModal').style.display = 'block';
}}

function closeModal() {{
    document.getElementById('flowModal').style.display = 'none';
}}
window.onclick = (e) => {{ if (e.target == document.getElementById('flowModal')) closeModal(); }};

// Filter change
document.getElementById('filterType').addEventListener('change', function() {{
    const val = this.value;
    const items = document.querySelectorAll('#flowsList .flow-item');
    items.forEach(item => {{
        const pred = item.dataset.prediction;
        if (val === 'all') {{
            item.style.display = '';
        }} else if (val === 'Normal') {{
            item.style.display = (pred === 'Normal' || pred === 'benign') ? '' : 'none';
        }} else {{
            item.style.display = (pred === val) ? '' : 'none';
        }}
    }});
}});

function exportAlerts() {{ window.open('/api/alerts/csv', '_blank'); }}

function toggleAutoScroll() {{
    autoScroll = !autoScroll;
    document.getElementById('scrollStatus').innerText = autoScroll ? 'ON' : 'OFF';
}}

function toggleDarkMode() {{
    const body = document.body;
    body.classList.toggle('dark-mode');
    const isDark = body.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDark);
    // Update button texts
    const btns = document.querySelectorAll('#darkModeBtn, #darkModeBtn2');
    btns.forEach(btn => btn.innerText = isDark ? '☀️ Light Mode' : '🌓 Dark Mode');
}}

// Init dark mode
(function() {{
    const isDark = localStorage.getItem('darkMode') === 'true';
    if (isDark) {{
        document.body.classList.add('dark-mode');
        const btns = document.querySelectorAll('#darkModeBtn, #darkModeBtn2');
        btns.forEach(btn => btn.innerText = '☀️ Light Mode');
    }}
}})();

// WebSocket
let ws;
function connectWebSocket() {{
    ws = new WebSocket(`ws://${{window.location.hostname}}:8765`);
    ws.onopen = () => {{
        document.getElementById('connectionStatus').innerText = 'Connected';
        document.getElementById('connectionStatus').classList.remove('disconnected');
    }};
    ws.onclose = () => {{
        document.getElementById('connectionStatus').innerText = 'Disconnected';
        document.getElementById('connectionStatus').classList.add('disconnected');
        setTimeout(connectWebSocket, 3000);
    }};
    ws.onmessage = (event) => {{
        const data = JSON.parse(event.data);
        if (data.type === 'new_flow') {{
            addFlow(data.flow);
            document.getElementById('totalFlows').innerText = data.total_flows;
            document.getElementById('alertCount').innerText = data.total_alerts;
            document.getElementById('lastUpdate').innerText = new Date().toLocaleTimeString();
            document.getElementById('currentStatus').innerText = 'Live';
        }}
    }};
}}

function updateStats() {{
    document.getElementById('totalFlows').innerText = flows.length;
    document.getElementById('alertCount').innerText = alerts.length;
    document.getElementById('lastUpdate').innerText = new Date().toLocaleTimeString();
}}

if (Notification.permission !== "denied") {{
    Notification.requestPermission();
}}

initCharts();
connectWebSocket();
setInterval(() => {{ if (ws && ws.readyState === WebSocket.OPEN) ws.send('ping'); }}, 25000);
</script>
</body>
</html>
"""

        server = HTTPServer(('0.0.0.0', self.http_port), DashboardHandler)
        try:
            print(f"🌍 HTTP server on port {self.http_port}")
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
            print("HTTP server stopped")

    async def run(self):
        self.loop = asyncio.get_event_loop()
        threading.Thread(target=self.start_http_server, daemon=True).start()
        self.start_monitoring()
        await self.start_websocket_server()

# ---------- Entry point ----------
if __name__ == "__main__":
    dashboard = RealTimeDashboard()
    try:
        asyncio.run(dashboard.run())
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
        dashboard.is_monitoring = False