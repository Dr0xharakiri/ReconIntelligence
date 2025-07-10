import streamlit as st
from scapy.all import rdpcap, DNSQR, UDP, IP
import pandas as pd
import requests
import tempfile

OTX_API_KEY = "4f950adf4d47055874e13499a930b9a302e45bbd6a7d6dc9ccd9ab18eef5474e"

def consultar_otx_detallado(dominio):
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{dominio}/general"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            geo_info = data.get("geo", {})
            return {
                "pulsos": pulse_info.get("count", 0),
                "categoria": ", ".join(pulse_info.get("threat_hunting_tags", [])) or "No categorizado",
                "ips": [i.get("address") for i in geo_info.get("ipv4", [])] if geo_info else [],
                "pais": geo_info.get("country_code", "Desconocido"),
                "descripcion": pulse_info.get("description", "Sin descripción")[:180] + "..."
            }
    except Exception:
        pass
    return {
        "pulsos": 0,
        "categoria": "N/A",
        "ips": [],
        "pais": "N/A",
        "descripcion": "N/A"
    }

def dns_queries_con_otx(uploaded_file):
    st.markdown("""
    <style>
    .otx-title {
        font-family: 'Inter', sans-serif;
        font-size: 28px;
        color: #0ff;
        text-shadow: 0 0 6px rgba(0, 255, 255, 0.2);
        font-weight: 600;
    }
    .otx-sub {
        font-family: 'Share Tech Mono', monospace;
        font-size: 16px;
        color: #e0fdfd;
        margin-top: 6px;
    }
    .otx-box {
        background-color: #151919;
        padding: 20px;
        border-radius: 8px;
        border: 1px solid #0affff44;
        margin-top: 20px;
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("<div class='otx-title'>🧠 DNS Queries enriquecidas con AlienVault OTX</div>", unsafe_allow_html=True)

    try:
        uploaded_file.seek(0)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name
        paquetes = rdpcap(tmp_path)
    except Exception as e:
        st.error(f"❌ Error al procesar el archivo: {e}")
        return

    dominios = {}
    dominio_to_ips = {}

    for pkt in paquetes:
        if pkt.haslayer(DNSQR) and UDP in pkt:
            try:
                dominio = pkt[DNSQR].qname.decode("utf-8").rstrip('.')
                dominios[dominio] = dominios.get(dominio, 0) + 1

                if pkt.haslayer(IP):
                    ip_dst = pkt[IP].dst
                    if dominio not in dominio_to_ips:
                        dominio_to_ips[dominio] = set()
                    dominio_to_ips[dominio].add(ip_dst)
            except Exception:
                continue

    resultados = []
    for dominio in dominios:
        info = consultar_otx_detallado(dominio)
        resultados.append({
            "Dominio": dominio,
            "Consultas": dominios[dominio],
            "Pulsos OTX": info["pulsos"]
        })

    df = pd.DataFrame(resultados).sort_values(by="Pulsos OTX", ascending=False)
    st.dataframe(df, use_container_width=True)

    dominio_seleccionado = st.selectbox("🔍 Selecciona un dominio para ver detalles OTX:", df["Dominio"].tolist())

    if dominio_seleccionado:
        info = consultar_otx_detallado(dominio_seleccionado)
        ips_otx = info["ips"]
        if not ips_otx and dominio_seleccionado in dominio_to_ips:
            ips_otx = list(dominio_to_ips[dominio_seleccionado])

        st.markdown(f"""
        <div class="otx-box">
            <div class="otx-sub"><strong>🌐 Dominio:</strong> {dominio_seleccionado}</div>
            <div class="otx-sub"><strong>📌 País:</strong> {info['pais']}</div>
            <div class="otx-sub"><strong>🧠 Categoría:</strong> {info['categoria']}</div>
            <div class="otx-sub"><strong>📡 IPs Relacionadas:</strong> {', '.join(ips_otx) if ips_otx else 'No disponibles'}</div>
            <div class="otx-sub"><strong>📝 Descripción:</strong> {info['descripcion']}</div>
        </div>
        """, unsafe_allow_html=True)
