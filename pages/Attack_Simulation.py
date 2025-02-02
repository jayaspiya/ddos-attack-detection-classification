import streamlit as st
import pandas as pd
from sklearn.preprocessing import StandardScaler
import pickle

SOURCE_PATH = 'dataset/dataset_sdn.csv'
server = pd.read_csv(SOURCE_PATH)

with open('./dataset/random_forest_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

st.set_page_config(
    page_title="DDOS Detection System",
)

st.header('DDOS Detection System')
st.subheader("Attack Simulation")

dt_input = 11425
switch_input = 1
src_input = st.text_input('Source','10.0.0.1')
dst_input = st.text_input('Destination','10.0.0.8')
Protocol_input = st.selectbox("Protocal", [ "TCP", "UDP", "ICMP",])

if st.button("Predict"):
    fetched_df =server[
        (server['src'] == src_input) *
        (server['dst'] == dst_input) *
        (server['Protocol'] == Protocol_input)
    ]
    random_row = fetched_df.sample(n=1)
    random_row = random_row.to_dict(orient="records")[0]
    
    data = {
        'dt': random_row['dt'],
        'switch': random_row['switch'],
        'src': random_row['src'],
        'dst': random_row['dst'],
        'pktcount': random_row['pktcount'],
        'bytecount': random_row['bytecount'],
        'dur': random_row['dur'],
        'dur_nsec': random_row['dur_nsec'],
        'tot_dur': random_row['tot_dur'],
        'flows': random_row['flows'],
        'packetins': random_row['packetins'],
        'pktperflow': random_row['pktperflow'],
        'byteperflow': random_row['byteperflow'],
        'pktrate': random_row['pktrate'],
        'Pairflow': random_row['Pairflow'],
        'port_no': random_row['port_no'],
        'tx_bytes': random_row['tx_bytes'],
        'rx_bytes': random_row['rx_bytes'],
        'tx_kbps': random_row['tx_kbps'],
        'rx_kbps': random_row['rx_kbps'],
        'tot_kbps': random_row['tot_kbps'],
        "Protocol_ICMP": True if random_row['Protocol'] == 'ICMP' else False,
        "Protocol_TCP": True if random_row['Protocol'] == 'TCP' else False,
        "Protocol_UDP": True if random_row['Protocol'] == 'UDP' else False,
    }
    df = pd.DataFrame([data])
    df['src'] = df['src'].apply(lambda ip: int(''.join([bin(int(x)+256)[3:] for x in ip.split('.')]), 2))
    df['dst'] = df['dst'].apply(lambda ip: int(''.join([bin(int(x)+256)[3:] for x in ip.split('.')]), 2))

    scaler = StandardScaler()
    df[['bytecount', 'pktcount', 'dur', 'dur_nsec', 'tot_dur', 'tx_bytes', 'rx_bytes']] = scaler.fit_transform(df[['bytecount', 'pktcount', 'dur', 'dur_nsec', 'tot_dur', 'tx_bytes', 'rx_bytes']])
    
    predictions = 'Malicious' if model.predict(df)[0] == 1 else 'Benign'
    st.text('Result:' + predictions)

    st.text("Input Variables")
    st.json(random_row)