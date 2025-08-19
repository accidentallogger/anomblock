#!/usr/bin/env python3
"""
dashboard.py

Enhanced Streamlit UI that shows:
1. Recent detections (from API /recent endpoint)
2. Live packet stream (from API /packets endpoint)
"""

import time
import requests
import streamlit as st
import pandas as pd
import plotly.express as px

API_BASE = st.sidebar.text_input("API base URL", value="http://127.0.0.1:8000")
POLL_SECS = st.sidebar.slider("Refresh (s)", 1, 10, 2)
MAX_ROWS = st.sidebar.slider("Show last N", 10, 500, 100)
SHOW_PACKETS = st.sidebar.checkbox("Show live packets", True)

st.set_page_config(layout="wide")
st.title("InSDN Live Monitoring Dashboard")

st.sidebar.markdown("""
**Configuration:**
- Ensure `api_server.py` is running
- Ryu app should post flows to the API
- Packet capture must be enabled in Ryu controller
""")

# Initialize session state
if "packet_history" not in st.session_state:
    st.session_state.packet_history = pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "protocol", "length"])

status_placeholder = st.empty()

# Layout
if SHOW_PACKETS:
    col1, col2 = st.columns([3, 2])
else:
    col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("Recent Flow Detections")
    detections_table = st.empty()
    
    st.subheader("Detection Statistics")
    stats_col1, stats_col2, stats_col3 = st.columns(3)
    
    with stats_col1:
        total_flows_box = st.empty()
    with stats_col2:
        attack_flows_box = st.empty()
    with stats_col3:
        normal_flows_box = st.empty()

with col2:
    if SHOW_PACKETS:
        st.subheader("Live Packet Stream")
        packet_view = st.empty()
        
        st.subheader("Packet Size Distribution")
        packet_chart = st.empty()

def fetch_recent():
    try:
        r = requests.get(API_BASE.rstrip("/") + "/recent", params={"n": MAX_ROWS}, timeout=2.0)
        r.raise_for_status()
        return r.json().get("recent", [])
    except Exception as e:
        return {"error": str(e)}

def fetch_packets():
    try:
        r = requests.get(API_BASE.rstrip("/") + "/packets", params={"n": 50}, timeout=2.0)
        r.raise_for_status()
        return r.json().get("packets", [])
    except Exception as e:
        return {"error": str(e)}

def update_packet_history(packets):
    if not packets or isinstance(packets, dict):
        return
    
    new_packets = []
    for pkt in packets:
        new_packets.append({
            "timestamp": pkt.get("timestamp", time.time()),
            "src_ip": pkt.get("src_ip", "0.0.0.0"),
            "dst_ip": pkt.get("dst_ip", "0.0.0.0"),
            "protocol": pkt.get("protocol", "unknown"),
            "length": pkt.get("length", 0),
            "direction": pkt.get("direction", "unknown")
        })
    
    # Update session state
    new_df = pd.DataFrame(new_packets)
    st.session_state.packet_history = pd.concat([
        st.session_state.packet_history, 
        new_df
    ]).drop_duplicates().tail(1000)  # Keep last 1000 packets

def display_packet_stream():
    if st.session_state.packet_history.empty:
        packet_view.write("No packets received yet")
        return
    
    # Show last 20 packets in a table
    last_packets = st.session_state.packet_history.tail(20)
    packet_view.table(last_packets[["timestamp", "src_ip", "dst_ip", "protocol", "length"]])
    
    # Show packet size distribution
    fig = px.histogram(
        st.session_state.packet_history,
        x="length",
        nbins=20,
        title="Packet Size Distribution",
        labels={"length": "Packet Size (bytes)"}
    )
    packet_chart.plotly_chart(fig, use_container_width=True)

if "last_ts" not in st.session_state:
    st.session_state.last_ts = 0

while True:
    # Fetch and display detections
    data = fetch_recent()
    if isinstance(data, dict) and data.get("error"):
        status_placeholder.error(f"Error fetching /recent: {data['error']}")
    else:
        rows = data
        if rows:
            # Build DataFrame
            df_rows = []
            for r in rows:
                row = {
                    "timestamp": r.get("ts"),
                    "flow_id": r.get("flow_id"),
                    "src_ip": r.get("meta", {}).get("src_ip", ""),
                    "dst_ip": r.get("meta", {}).get("dst_ip", ""),
                    "dst_port": r.get("meta", {}).get("dst_port", ""),
                    "label": r.get("label", "unknown"),
                    "confidence": max(r.get("probs", [0])) * 100 if r.get("probs") else 0,
                    "duration": r.get("model_row", {}).get("Flow Duration", 0)
                }
                df_rows.append(row)

            df = pd.DataFrame(df_rows)
            if not df.empty:
                # Formatting
                df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
                df["confidence"] = df["confidence"].round(1)
                df["duration"] = df["duration"].round(3)
                
                # Display
                detections_table.dataframe(
                    df[["timestamp", "src_ip", "dst_ip", "dst_port", "label", "confidence", "duration"]],
                    use_container_width=True,
                    hide_index=True
                )
                
                # Update stats
                total_flows = len(df)
                attack_flows = len(df[df["label"] != "normal"])
                normal_flows = total_flows - attack_flows
                
                total_flows_box.metric("Total Flows", total_flows)
                attack_flows_box.metric("Attack Flows", attack_flows, delta=f"{attack_flows/total_flows:.1%}")
                normal_flows_box.metric("Normal Flows", normal_flows, delta=f"{normal_flows/total_flows:.1%}")
                
                status_placeholder.info(f"Showing {len(df)} recent detections. Refresh every {POLL_SECS}s")
            else:
                detections_table.write("No detections yet")
    
    # Fetch and display packets if enabled
    if SHOW_PACKETS:
        packets = fetch_packets()
        if isinstance(packets, dict) and packets.get("error"):
            pass  # Silently ignore packet errors for now
        else:
            update_packet_history(packets)
            display_packet_stream()
    
    time.sleep(POLL_SECS)