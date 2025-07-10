import streamlit as st
import requests
import datetime
import base64
from pathlib import Path

# Define logos por grupo APT conocido
APT_LOGOS = {
    "APT28": "assets/apt28.png",
    "Lazarus": "assets/lazarus.png",
    "APT29": "assets/apt29.png",
    "OceanLotus": "assets/oceanlotus.png",
    "FIN7": "assets/fin7.png"
}

# Carga imagen como base64 para visualización en HTML
def get_base64_image(image_path):
    try:
        with open(image_path, "rb") as f:
            data = f.read()
        return base64.b64encode(data).decode()
    except:
        return None

# Fallback visual
def get_fallback_svg():
    return base64.b64encode(b'''
    <svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
      <rect width="100" height="100" fill="#0ff"/>
      <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="#000" font-size="14">APT</text>
    </svg>
    ''').decode()

def simulador_ataques_live():
    st.title("🧠 APT Threat Catalog (últimos pulsos de OTX)")

    OTX_API_KEY = "4f950adf4d47055874e13499a930b9a302e45bbd6a7d6dc9ccd9ab18eef5474e"
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"limit": 10}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        pulses = response.json().get("results", [])
    except Exception as e:
        st.error(f"❌ Error al obtener datos de OTX: {e}")
        return

    if not pulses:
        st.info("No se encontraron pulsos recientes.")
        return

    st.markdown("""
    <style>
    .apt-card {
        background: #101417;
        border: 1px solid #00ffff55;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 1.2rem;
        display: flex;
        box-shadow: 0 0 8px #00ffff44;
        transition: 0.3s;
    }
    .apt-card:hover {
        box-shadow: 0 0 16px #00ffffaa;
    }
    .apt-content {
        flex: 1;
        margin-left: 1rem;
    }
    .apt-title {
        color: #0ff;
        font-weight: bold;
        font-size: 1.1rem;
    }
    .apt-tags {
        font-size: 0.8rem;
        color: #aaa;
    }
    </style>
    """, unsafe_allow_html=True)

    for pulse in pulses:
        name = pulse.get("name", "Sin nombre")
        adversary = pulse.get("adversary", "Desconocido")
        description = pulse.get("description", "")[:250] + "..."
        tags = ", ".join(pulse.get("tags", []))
        created = pulse.get("created", "N/A")

        try:
            fecha = datetime.datetime.fromisoformat(created).strftime("%Y-%m-%d")
        except:
            fecha = created

        # Detectar si tiene logo
        logo_path = None
        for known_apt in APT_LOGOS:
            if known_apt.lower() in adversary.lower() or known_apt.lower() in name.lower():
                logo_path = APT_LOGOS[known_apt]
                break

        if logo_path:
            logo_base64 = get_base64_image(logo_path)
        else:
            logo_base64 = get_fallback_svg()

        st.markdown(f"""
        <div class="apt-card">
            <div>
                <img src="data:image/png;base64,{logo_base64}" width="80" height="80" style="border-radius:6px;" />
            </div>
            <div class="apt-content">
                <div class="apt-title">{name}</div>
                <div style="color:#888; font-size:0.8rem;">APT: {adversary} | Fecha: {fecha}</div>
                <div style="color:#ccc; font-size:0.9rem; margin:0.4rem 0;">{description}</div>
                <div class="apt-tags">Tags: {tags}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
