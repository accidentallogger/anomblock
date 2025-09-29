#!/usr/bin/env python3
"""
REAL-TIME SDN Dashboard - Live packet interception without refreshing
"""

import asyncio
import websockets
import json
import time
import os
import threading
from http.server import SimpleHTTPRequestHandler, HTTPServer

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
        
    async def handle_websocket(self, websocket):
        """Handle WebSocket connections for real-time updates"""
        self.connected_clients.add(websocket)
        print(f"WebSocket client connected. Total: {len(self.connected_clients)}")
        
        try:
            # Send initial state
            await websocket.send(json.dumps({
                'type': 'init',
                'message': 'Connected to real-time SDN dashboard',
                'total_flows': len(self.flows)
            }))
            
            # Keep connection alive - handle pings and regular messages
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=30.0)
                    if message == 'ping':
                        await websocket.send('pong')
                except asyncio.TimeoutError:
                    # Send ping to check if client is still connected
                    try:
                        await websocket.send('ping')
                        # Wait for pong response
                        response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                        if response != 'pong':
                            break
                    except:
                        break
                except websockets.exceptions.ConnectionClosed:
                    break
                    
        except Exception as e:
            print(f"WebSocket error: {e}")
        finally:
            if websocket in self.connected_clients:
                self.connected_clients.remove(websocket)
            print(f"WebSocket client disconnected. Total: {len(self.connected_clients)}")
    
    async def broadcast(self, data):
        """Broadcast data to all connected WebSocket clients"""
        if not self.connected_clients:
            return
            
        message = json.dumps(data)
        disconnected_clients = []
        
        for client in self.connected_clients:
            try:
                await client.send(message)
            except:
                disconnected_clients.append(client)
        
        # Clean up disconnected clients
        for client in disconnected_clients:
            if client in self.connected_clients:
                self.connected_clients.remove(client)
    
    def monitor_csv_file(self):
        """Monitor CSV file for new flows in real-time"""
        print("🔍 Starting real-time CSV monitoring...")
        self.is_monitoring = True
        
        while self.is_monitoring:
            try:
                if not os.path.exists(self.csv_path):
                    time.sleep(1)
                    continue
                
                with open(self.csv_path, 'r') as file:
                    # Move to last read position
                    if self.last_file_position > os.path.getsize(self.csv_path):
                        # File was reset (new simulation)
                        self.last_file_position = 0
                        self.flows = []
                    
                    file.seek(self.last_file_position)
                    new_lines = file.readlines()
                    
                    if new_lines:
                        self.last_file_position = file.tell()
                        
                        for line in new_lines:
                            line = line.strip()
                            if line and not line.startswith('Flow ID'):  # Skip header and empty lines
                                flow_data = self.parse_flow(line)
                                if flow_data:
                                    self.flows.append(flow_data)
                                    print(f"LIVE: {flow_data['src_ip']} → {flow_data['dst_ip']} | {flow_data['attack_type']}")
                                    
                                    # Broadcast to WebSocket clients in real-time
                                    if self.loop:
                                        asyncio.run_coroutine_threadsafe(
                                            self.broadcast({
                                                'type': 'new_flow',
                                                'flow': flow_data,
                                                'total_flows': len(self.flows),
                                                'timestamp': time.time()
                                            }), 
                                            self.loop
                                        )
                
                time.sleep(0.1)  # Check every 100ms for real-time updates
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(1)
    
    def parse_flow(self, csv_line):
        """Parse a CSV line into flow data"""
        try:
            parts = csv_line.split(',')
            if len(parts) < 84:
                return None
                
            return {
                'flow_id': parts[0],
                'src_ip': parts[1],
                'src_port': parts[2],
                'dst_ip': parts[3],
                'dst_port': parts[4],
                'protocol': parts[5],
                'timestamp': parts[6],
                'duration': parts[7],
                'total_packets': int(parts[8]) + int(parts[9]),
                'total_bytes': int(parts[10]) + int(parts[11]),
                'attack_type': parts[83],
                'received_at': time.time()
            }
        except Exception as e:
            print(f"Parse error: {e}")
            return None
    
    def start_monitoring(self):
        """Start the CSV monitoring in a separate thread"""
        self.monitor_thread = threading.Thread(target=self.monitor_csv_file, daemon=True)
        self.monitor_thread.start()
        print("Real-time monitoring started")
    
    async def start_websocket_server(self):
        """Start the WebSocket server"""
        print(f"Starting WebSocket server on port {self.websocket_port}")
        
        # Create the WebSocket server with the correct handler
        async with websockets.serve(self.handle_websocket, "0.0.0.0", self.websocket_port):
            print("WebSocket server ready")
            await asyncio.Future()  # Run forever
    
    def start_http_server(self):
        """Start HTTP server for serving the dashboard page"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        class DashboardHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=current_dir, **kwargs)
            
            def log_message(self, format, *args):
                # Suppress normal HTTP logging
                pass
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    html = self.get_dashboard_html()
                    self.wfile.write(html.encode())
                elif self.path == '/health':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'ok', 'websocket_port': 8765}).encode())
                else:
                    super().do_GET()
            
            def get_dashboard_html(self):
                return """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Real-Time SDN Dashboard</title>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                        .dashboard { max-width: 1200px; margin: 0 auto; }
                        .header { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
                        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                        .stat-number { font-size: 2em; font-weight: bold; color: #333; }
                        .flows-container { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                        .flow-item { padding: 15px; margin: 10px 0; border-left: 5px solid #007bff; background: #f8f9fa; border-radius: 5px; }
                        .flow-item.attack { border-left-color: #dc3545; background: #f8d7da; }
                        .flow-item.benign { border-left-color: #28a745; background: #d4edda; }
                        .connection-status { position: fixed; top: 10px; right: 10px; padding: 10px; border-radius: 5px; font-weight: bold; }
                        .connected { background: #d4edda; color: #155724; border: 2px solid #28a745; }
                        .disconnected { background: #f8d7da; color: #721c24; border: 2px solid #dc3545; }
                        .reconnecting { background: #fff3cd; color: #856404; border: 2px solid #ffc107; }
                    </style>
                </head>
                <body>
                    <div class="dashboard">
                        <div class="header">
                            <h1> Real-Time SDN Security Dashboard</h1>
                            <p>Live packet interception - No page refresh needed</p>
                        </div>
                        
                        <div class="connection-status disconnected" id="connectionStatus">
                            Disconnected
                        </div>
                        
                        <div class="stats">
                            <div class="stat-card">
                                <div>Total Flows</div>
                                <div class="stat-number" id="totalFlows">0</div>
                            </div>
                            <div class="stat-card">
                                <div>Active Connections</div>
                                <div class="stat-number" id="activeConnections">0</div>
                            </div>
                            <div class="stat-card">
                                <div>Last Update</div>
                                <div id="lastUpdate">Never</div>
                            </div>
                            <div class="stat-card">
                                <div>Status</div>
                                <div id="currentStatus">Waiting for connection...</div>
                            </div>
                        </div>
                        
                        <div class="flows-container">
                            <h3> Live Network Flows</h3>
                            <div id="flowsList">
                                <div style="text-align: center; padding: 20px; color: #666;">
                                    Waiting for incoming flows...
                                </div>
                            </div>
                        </div>
                    </div>

                    <script>
                        class RealTimeDashboard {
                            constructor() {
                                this.ws = null;
                                this.flowCount = 0;
                                this.reconnectAttempts = 0;
                                this.maxReconnectAttempts = 10;
                                this.reconnectDelay = 3000;
                                this.isConnected = false;
                                
                                this.connect();
                            }
                            
                            connect() {
                                try {
                                    this.updateStatus('Connecting...', 'reconnecting');
                                    const wsHost = window.location.hostname;
                                    this.ws = new WebSocket(`ws://${wsHost}:8765`);
                                    
                                    this.ws.onopen = () => {
                                        console.log('WebSocket connected successfully');
                                        this.isConnected = true;
                                        this.reconnectAttempts = 0;
                                        this.updateStatus('Connected - Live monitoring', 'connected');
                                        this.updateDisplay();
                                    };
                                    
                                    this.ws.onmessage = (event) => {
                                        try {
                                            const data = JSON.parse(event.data);
                                            this.handleMessage(data);
                                        } catch (e) {
                                            console.log('Non-JSON message:', event.data);
                                        }
                                    };
                                    
                                    this.ws.onclose = (event) => {
                                        console.log('WebSocket disconnected:', event.code, event.reason);
                                        this.isConnected = false;
                                        this.handleDisconnection();
                                    };
                                    
                                    this.ws.onerror = (error) => {
                                        console.error('WebSocket error:', error);
                                        this.isConnected = false;
                                        this.updateStatus('Connection error', 'disconnected');
                                    };
                                    
                                } catch (error) {
                                    console.error('Connection error:', error);
                                    this.handleDisconnection();
                                }
                            }
                            
                            handleMessage(data) {
                                switch(data.type) {
                                    case 'init':
                                        this.flowCount = data.total_flows || 0;
                                        this.updateDisplay();
                                        break;
                                        
                                    case 'new_flow':
                                        this.addFlow(data.flow);
                                        this.flowCount = data.total_flows || 0;
                                        this.updateDisplay();
                                        break;
                                        
                                    case 'pong':
                                        // Handle pong response
                                        break;
                                }
                            }
                            
                            addFlow(flow) {
                                const flowsList = document.getElementById('flowsList');
                                
                                // Remove waiting message if it exists
                                if (flowsList.children.length === 1 && 
                                    flowsList.children[0].textContent.includes('Waiting')) {
                                    flowsList.innerHTML = '';
                                }
                                
                                const flowElement = document.createElement('div');
                                const isAttack = flow.attack_type !== 'benign';
                                
                                flowElement.className = `flow-item ${isAttack ? 'attack' : 'benign'}`;
                                flowElement.innerHTML = `
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <div>
                                            <strong>${new Date().toLocaleTimeString()}</strong><br>
                                            <strong>${flow.src_ip}:${flow.src_port} → ${flow.dst_ip}:${flow.dst_port}</strong><br>
                                            Protocol: ${flow.protocol} | Packets: ${flow.total_packets} | Duration: ${flow.duration}s
                                        </div>
                                        <div style="text-align: right;">
                                            <span style="font-size: 1.1em; font-weight: bold; color: ${isAttack ? '#dc3545' : '#28a745'}">
                                                ${flow.attack_type.toUpperCase()}
                                            </span>
                                        </div>
                                    </div>
                                `;
                                
                                // Add to top
                                flowsList.insertBefore(flowElement, flowsList.firstChild);
                                
                                // Keep only last 20 flows
                                if (flowsList.children.length > 20) {
                                    flowsList.removeChild(flowsList.lastChild);
                                }
                            }
                            
                            updateDisplay() {
                                document.getElementById('totalFlows').textContent = this.flowCount;
                                document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
                                document.getElementById('currentStatus').textContent = this.isConnected ? 'Live' : 'Disconnected';
                                document.getElementById('activeConnections').textContent = this.isConnected ? 'Connected' : 'Disconnected';
                            }
                            
                            updateStatus(message, className) {
                                const statusElement = document.getElementById('connectionStatus');
                                statusElement.textContent = message;
                                statusElement.className = `connection-status ${className}`;
                            }
                            
                            handleDisconnection() {
                                this.updateStatus('Disconnected - Reconnecting...', 'disconnected');
                                this.updateDisplay();
                                
                                if (this.reconnectAttempts < this.maxReconnectAttempts) {
                                    this.reconnectAttempts++;
                                    setTimeout(() => this.connect(), this.reconnectDelay);
                                } else {
                                    this.updateStatus('Failed to connect - Refresh page', 'disconnected');
                                }
                            }
                            
                            sendPing() {
                                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                                    this.ws.send('ping');
                                }
                            }
                        }
                        
                        // Initialize dashboard when page loads
                        window.addEventListener('load', () => {
                            window.dashboard = new RealTimeDashboard();
                            
                            // Send ping every 25 seconds to keep connection alive
                            setInterval(() => {
                                if (window.dashboard) {
                                    window.dashboard.sendPing();
                                }
                            }, 25000);
                        });
                    </script>
                </body>
                </html>
                """
        
        print(f"Starting HTTP server on port {self.http_port}")
        server = HTTPServer(('0.0.0.0', self.http_port), DashboardHandler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
    
    async def run(self):
        """Start the complete dashboard system"""
        print("Starting Real-Time SDN Dashboard")
        print(f"Monitoring: {self.csv_path}")
        
        # Store the event loop for thread-safe operations
        self.loop = asyncio.get_event_loop()
        
        # Start HTTP server in background thread
        http_thread = threading.Thread(target=self.start_http_server, daemon=True)
        http_thread.start()
        
        # Start CSV monitoring in background thread
        self.start_monitoring()
        
        # Start WebSocket server (runs in main thread)
        await self.start_websocket_server()

if __name__ == "__main__":
    dashboard = RealTimeDashboard()
    
    try:
        asyncio.run(dashboard.run())
    except KeyboardInterrupt:
        print("\nDashboard stopped by user")
        dashboard.is_monitoring = False