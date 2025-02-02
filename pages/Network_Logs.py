import streamlit as st
import pandas as pd

SOURCE_PATH = 'dataset/dataset_sdn.csv'
server = pd.read_csv(SOURCE_PATH)


st.set_page_config(
    page_title="DDOS Detection System",
)

st.header('DDOS Detection System')
st.subheader("Network Logs")

src_input = st.text_input('Source','10.0.0.1')
dst_input = st.text_input('Destination','10.0.0.8')

if st.button("Search"):
    st.table(server[
        (server['src'] == src_input) *
        (server['dst'] == dst_input)
    ].head(10))
