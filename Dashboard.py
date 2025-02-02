import streamlit as st
import pandas as pd
import numpy as np

st.set_page_config(
    page_title="DDOS Detection System",
    # layout="wide",
    # initial_sidebar_state="expanded"
)

SOURCE_PATH = 'dataset/dataset_sdn.csv'
data = pd.read_csv(SOURCE_PATH)
offset = 1728929700000
data['timestamp'] = pd.to_datetime((data['dt'] * 1000) + offset, unit='ms')
data['label'] = data['label'].map({1: 'Malicious', 0: 'Benign'})
data['date'] = data['timestamp'].dt.floor('H')

st.header('DDOS Detection System')

latest_data = data.iloc[-1]
col1, col2, col3 = st.columns(3)
with col1:
    st.metric(label="Total Bandwidth (kbps)", value=f"{latest_data['tot_kbps']} kbps")
with col2:
    st.metric(label="Transmitted Bandwidth (kbps)", value=f"{latest_data['tx_kbps']} kbps")
with col3:
    st.metric(label="Received Bandwidth (kbps)", value=f"{latest_data['rx_kbps']} kbps")

# Label Distribution
st.subheader("Label Distribution")
label_counts = data.groupby('label').size().reset_index(name='count')
st.bar_chart(label_counts.set_index('label'))

# Traffic Volume Over Time
st.subheader("Traffic Volume Over Time")
st.write("Visualize traffic trends over time to identify unusual spikes in packet or byte count.")
hourly_traffic = data.groupby('date').agg({'pktcount': 'sum', 'bytecount': 'sum'}).reset_index()
hourly_traffic['bytecount'] = hourly_traffic['bytecount'] / 1024

st.line_chart(
    hourly_traffic,
    x="date",
    y=["pktcount", "bytecount"],
    color=["#FF0000", "#0000FF"], 
)

# Protocol Distribution
st.subheader("Protocol Distribution")
st.write("Determine which protocols are predominantly used in attacks.")
label_counts = data.groupby('Protocol').size().reset_index(name='count')
st.bar_chart(label_counts.set_index('Protocol'))

# Switch-Wise Malicious Traffic
switch_label_df = data.groupby(['switch', 'label']).size().unstack(fill_value=0)
st.subheader("Switch-Wise Malicious Traffic")
st.write("Identify which switches are most frequently targeted by attacks.")
st.bar_chart(switch_label_df, color= ["#0000FF", "#FF0000"])

# Bandwidth Analysis
st.subheader("Bandwidth Analysis")
st.write("Identify bandwidth surges that may indicate DDoS attacks.")
hourly_traffic = data.groupby('date').agg({'tx_kbps': 'sum', 'rx_kbps': 'sum', 'tot_kbps': 'sum'}).reset_index()
hourly_traffic.set_index('date', inplace=True)
st.area_chart(hourly_traffic[['tx_kbps', 'rx_kbps', 'tot_kbps']])
