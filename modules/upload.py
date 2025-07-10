import streamlit as st

def cargar_archivo():
    return st.sidebar.file_uploader("Sube un archivo PCAP", type=["pcap", "pcapng"])
