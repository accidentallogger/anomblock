import streamlit as st
import pandas as pd
import numpy as np
import socket
import struct
import joblib
from tensorflow.keras.models import load_model

# =======================
# Helper Functions
# =======================
def ip_to_int(ip):
    """Convert dotted IPv4 to integer"""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except socket.error:
        return 0

# =======================
# Load Model + Preprocessors
# =======================
@st.cache_resource
def load_all_models():
    model = load_model("model2/lstm_model.h5")
    scaler = joblib.load("model2/scaler.pkl")
    label_encoder = joblib.load("model2/label_encoder.pkl")
    return model, scaler, label_encoder

loaded_model, loaded_scaler, loaded_label_encoder = load_all_models()

# Attack mapping
attack_mapping = {
    0: "Normal",
    1: "SYN Flood",
    2: "UDP Flood",
    3: "ICMP Flood",
    4: "Nmap",
    5: "SSH Brute-force Simulation",
    6: "Botnet Simulation"
}

# =======================
# Streamlit UI
# =======================
st.title("🔐 SDN Intrusion Detection Dashboard")
st.write("Upload a CSV file with flow records to classify them into Normal/Attack types.")

uploaded_file = st.file_uploader("Upload CSV", type=["csv"])

if uploaded_file is not None:
    # Load CSV
    new_data_df = pd.read_csv(uploaded_file)

    st.subheader("📄 Uploaded Data Preview")
    st.dataframe(new_data_df.head())

    # Drop unnecessary columns if they exist
    for col in ["FlowID", "StartTime", "Label"]:
        if col in new_data_df.columns:
            new_data_df = new_data_df.drop(columns=[col])

    # Convert IPs to integers
    if 'SrcIP' in new_data_df.columns:
        new_data_df['SrcIP'] = new_data_df['SrcIP'].apply(ip_to_int)
    if 'DstIP' in new_data_df.columns:
        new_data_df['DstIP'] = new_data_df['DstIP'].apply(ip_to_int)

    # Scale features
    new_data_scaled = loaded_scaler.transform(new_data_df)

    # Reshape for LSTM
    new_data_scaled = new_data_scaled.reshape((new_data_scaled.shape[0], 1, new_data_scaled.shape[1]))

    # Predictions
    predictions = loaded_model.predict(new_data_scaled)
    predicted_classes_indices = np.argmax(predictions, axis=1)
    predicted_labels = loaded_label_encoder.inverse_transform(predicted_classes_indices)

    # Map to attack names
    attack_names = [attack_mapping.get(lbl, "Unknown") for lbl in predicted_labels]

    # Show results
    result_df = pd.DataFrame({
        "Predicted Label": predicted_labels,
        "Attack Type": attack_names
    })

    st.subheader("✅ Prediction Results")
    st.dataframe(result_df)

    # Optionally allow CSV download
    csv = result_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        "📥 Download Predictions as CSV",
        csv,
        "predictions.csv",
        "text/csv",
        key="download-csv"
    )
