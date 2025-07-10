import streamlit as st
from modules.upload import cargar_archivo
from modules.analisis_basico import process_pcap, show_dashboard
from modules.analisis_avanzado import dashboard_analisis_protocolo_ip
from modules.detalle_paquetes import mostrar_paquetes_con_detalle
from modules.payloads import mostrar_payloads_marcados
from modules.threat_intel import threat_intelligence_otx
from modules.live import simulador_ataques_live
from modules.dns_queries_otx import dns_queries_con_otx

import base64
import os

# ------------ HOME PRESENTACIÓN ------------
def mostrar_home():
    logo_path = os.path.join("images", "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            img_bytes = f.read()
            encoded = base64.b64encode(img_bytes).decode()
        st.markdown(
            f"""
            <div style="text-align: center; margin-bottom: 20px;">
                <img src="data:image/png;base64,{encoded}" width="160" />
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("""
        <style>
        .cyber-title {
            text-align: center;
            font-family: 'Inter', sans-serif;
            font-size: 42px;
            font-weight: 700;
            background: linear-gradient(90deg, #00f7ff, #8ef0f4, #00f7ff);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-shadow: 0 0 6px rgba(0, 255, 255, 0.2);
            margin-bottom: 10px;
        }

        .cyber-subtitle {
            color: #00f7ff;
            font-family: 'Inter', sans-serif;
            font-size: 26px;
            font-weight: 600;
            text-shadow: 0 0 4px rgba(0, 255, 255, 0.2);
            margin-top: 40px;
        }

        .cyber-p {
            text-align: center;
            font-family: 'Share Tech Mono', monospace;
            color: #e0fdfd;
            font-size: 16px;
        }

        .cyber-ul {
            font-family: 'Share Tech Mono', monospace;
            font-size: 15px;
            color: #e0fdfd;
            line-height: 1.8em;
        }
        </style>

        <div class="cyber-title">ReconIntelligence</div>

        <p class="cyber-p">
            Plataforma de análisis de tráfico de red avanzada enfocada en la inteligencia de amenazas.<br><br>
            Carga archivos PCAP para visualizar e interpretar el comportamiento de red a través de gráficos interactivos, métricas clave y detección de protocolos sensibles.
        </p>

        <hr style="margin: 30px 0; border: 1px solid #1f1f1f;">

        <div class="cyber-subtitle">🚀 Funcionalidades principales:</div>
        <ul class="cyber-ul">
            <li>🔍 Análisis de paquetes con extracción de IPs, protocolos y puertos.</li>
            <li>📊 Dashboards interactivos con gráficas Plotly para tráfico, DNS y protocolos.</li>
            <li>📦 Inspección de payloads y detección de protocolos sensibles como Telnet, FTP o SMB.</li>
            <li>🧬 Gráfico de interacciones entre IPs para identificar nodos dominantes y gateways.</li>
            <li>🧠 Integración con <strong>YARA</strong> para escaneo de patrones maliciosos en payloads.</li>
            <li>🌐 <strong>Threat Intelligence</strong> vía API pública de <strong>AlienVault OTX</strong> para enriquecer las IPs detectadas.</li>
            <li>💥 Visualización simulada de ataques en vivo con animaciones tipo SOC.</li>
        </ul>

        <div class="cyber-subtitle">🌐 ¿Qué es AlienVault OTX?</div>
        <p class="cyber-p">
            La API de <strong>AlienVault Open Threat Exchange (OTX)</strong> permite consultar datos de inteligencia sobre IPs, dominios y hashes relacionados con campañas maliciosas.
            <br><br>
            ReconIntelligence usa esta API para identificar conexiones con indicadores de compromiso (IoCs), malware, APTs, botnets y más.
        </p>

        <hr style="margin: 30px 0; border: 1px solid #1f1f1f;">

        <p class="cyber-p" style="font-size: 13px; color: #888;">
            Desarrollado para analistas de ciberseguridad, pentesters y equipos de respuesta a incidentes.
            <br>
            <em>Do it for: dr0xharakiri</em>
        </p>
    """, unsafe_allow_html=True)


# ------------ LOGO EN SIDEBAR ------------
def render_sidebar_logo():
    logo_path = os.path.join("images", "logo.png")
    if os.path.exists(logo_path):
        with open(logo_path, "rb") as f:
            img_bytes = f.read()
            encoded = base64.b64encode(img_bytes).decode()

        st.sidebar.markdown(
            f"""
            <div style="text-align: center; margin-bottom: 20px;">
                <div style="font-family: 'Share Tech Mono', monospace; font-size: 20px; color: #8ef0f4; margin-bottom: 10px;">
                    ReconIntelligence
                </div>
                <img src="data:image/png;base64,{encoded}" width="150" />
            </div>
            """,
            unsafe_allow_html=True
        )


# ------------ SESIÓN Y CONFIG VISUAL ------------
if "favoritos" not in st.session_state:
    st.session_state.favoritos = []

st.set_page_config(
    page_title="PCAP Intelligence Dashboard",
    page_icon="🧩",
    layout="wide",
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
[data-testid="stAppViewContainer"] { background-color: #0f1111; }
[data-testid="stSidebar"] { background-color: #101414; }
h1, h2, h3, h4 {
    font-family: 'Inter', sans-serif;
    color: #8ef0f4;
    letter-spacing: 0.5px;
    font-weight: 600;
    text-shadow: none;
}
[data-testid="stMetric"] {
    background-color: #161b1b;
    color: #e0fdfd;
    border-radius: 6px;
    border: 1px solid #0affff33;
    box-shadow: none;
    padding: 8px;
}
</style>
""", unsafe_allow_html=True)

# ------------ SIDEBAR ------------
render_sidebar_logo()

option = st.sidebar.selectbox(
    "Selecciona qué deseas visualizar:",
    (
        "Home / Presentación",
        "Listado de IPs",
        "Cantidad de paquetes por IP",
        "DNS Queries",
        "Protocolos",
        "Interacción entre IPs",
        "Explorar paquetes",
        "📦 Payloads marcados",
        "Dashboard Protocolos/IPs (Avanzado)",
        "Threat Intelligence OTX",
        "Live Cyber Attack Map ",
        "DNS Queries con OTX",
    )
)

# ------------ CONTROL PRINCIPAL ------------
if option == "Live Cyber Attack Map":
    simulador_ataques_live()
    st.stop()

if option == "Home / Presentación":
    mostrar_home()
    st.stop()

# ------------ CARGA Y RUTEO ------------
uploaded_file = cargar_archivo()

if uploaded_file is not None:
    with st.spinner("Procesando archivo PCAP..."):
        try:
            ip_data, traffic_data, dns_queries, protocol_counts, gateway_ip, total_packets = process_pcap(uploaded_file)
            st.success("Archivo procesado exitosamente")

            if option == "Dashboard Protocolos/IPs (Avanzado)":
                dashboard_analisis_protocolo_ip(uploaded_file)
            elif option == "Threat Intelligence OTX":
                threat_intelligence_otx(traffic_data)
            elif option == "📦 Payloads marcados":
                mostrar_payloads_marcados()
            elif option == "Explorar paquetes":
                mostrar_paquetes_con_detalle(uploaded_file)
            elif option == "DNS Queries con OTX":
                dns_queries_con_otx(uploaded_file)
            else:
                show_dashboard(ip_data, traffic_data, dns_queries, protocol_counts, gateway_ip, total_packets, option)
        except Exception as e:
            st.error(f"Error al procesar el archivo: {e}")
else:
    st.info("Por favor, sube un archivo PCAP para comenzar el análisis.")
