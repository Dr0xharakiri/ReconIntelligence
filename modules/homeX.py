# homeX.py
import streamlit as st
import base64
import os

def render_logo_and_title():
    logo_path = os.path.join("images", "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            img_bytes = f.read()
            encoded = base64.b64encode(img_bytes).decode()

        st.markdown(f"""
            <div style="text-align: center; margin-top: 50px;">
                <img src="data:image/png;base64,{encoded}" width="180" />
                <h1 style="font-family: 'Inter', sans-serif; color: #8ef0f4; margin-top: 20px;">
                    ReconIntelligence
                </h1>
                <p style="font-family: 'Share Tech Mono', monospace; color: #e0fdfd; font-size: 18px; max-width: 700px; margin: auto;">
                    ReconIntelligence es una plataforma de análisis forense y de inteligencia cibernética que permite visualizar, inspeccionar y correlacionar tráfico de red a partir de archivos PCAP. 
                    Incluye capacidades avanzadas como detección de protocolos sensibles, payloads marcados, integración con OTX, reglas YARA, e incluso simulación en tiempo real de ciberataques.
                </p>
            </div>
        """, unsafe_allow_html=True)
    else:
        st.warning("No se encontró el logo en la ruta especificada.")

st.set_page_config(
    page_title="Inicio | ReconIntelligence",
    page_icon="🧠",
    layout="centered",
    initial_sidebar_state="expanded"
)

st.markdown("""
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@600&display=swap" rel="stylesheet">
<style>
html, body, [class*="css"] {
    font-family: 'Share Tech Mono', monospace;
    background-color: #0f1111;
    color: #e0fdfd;
}
</style>
""", unsafe_allow_html=True)

render_logo_and_title()
