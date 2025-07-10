import streamlit as st
import requests

OTX_API_KEY = "4f950adf4d47055874e13499a930b9a302e45bbd6a7d6dc9ccd9ab18eef5474e"  # <-- Sustituir por variable de entorno o archivo seguro

def consulta_otx_ip(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def threat_intelligence_otx(traffic_data):
    st.markdown("""
    <style>
    html, body, [class*="css"] {
        font-family: 'Share Tech Mono', monospace;
        background-color: #0f1111;
        color: #e0fdfd;
    }
    h1, h2, h3, h4 {
        font-family: 'Inter', sans-serif;
        color: #8ef0f4;
        font-weight: 600;
    }
    </style>
    """, unsafe_allow_html=True)

    st.header("🔎 Threat Intelligence con OTX (AlienVault)")
    top_ips = list(traffic_data.sort_values("Paquetes", ascending=False)["IP"].head(10))
    ip_select = st.selectbox("Selecciona una IP para consultar en OTX", top_ips)
    ip_manual = st.text_input("O consulta cualquier otra IP manualmente", "")
    ip_to_query = ip_manual if ip_manual else ip_select

    if st.button(f"Consultar Threat Intelligence para {ip_to_query}"):
        with st.spinner(f"Consultando OTX para {ip_to_query}..."):
            info = consulta_otx_ip(ip_to_query)
            if info:
                st.markdown(f"### Resultados para IP: `{ip_to_query}`")
                st.write(f"**País:** {info.get('country_name', 'N/A')}")
                st.write(f"**ASN:** {info.get('asn', 'N/A')}")
                st.write(f"**Organización:** {info.get('organization', 'N/A')}")
                st.write(f"**Número de pulses (campañas):** {len(info.get('pulse_info', {}).get('pulses', []))}")

                if info.get('pulse_info', {}).get('pulses', []):
                    st.markdown("#### Pulses relacionados:")
                    for pulse in info['pulse_info']['pulses']:
                        st.markdown(f"- **{pulse['name']}** ({pulse['created'][:10]}) - {pulse.get('description','')[:200]}...")

                st.write(f"**Etiquetas:** {', '.join(info.get('tags', [])) if info.get('tags', []) else 'N/A'}")
                st.write(f"**Primera vez visto:** {info.get('first_seen', 'N/A')}")
                st.write(f"**Última vez visto:** {info.get('last_seen', 'N/A')}")
                st.write(f"**Reputación de la IP:** {info.get('reputation', 'N/A')}")
                st.write(f"**Número de Reportes:** {info.get('count', 'N/A')}")

                asn_info = info.get('asn_info', {})
                if asn_info:
                    st.markdown("#### Información ASN Adicional:")
                    st.write(f"**Nombre ASN:** {asn_info.get('name', 'N/A')}")
                    st.write(f"**Descripción:** {asn_info.get('description', 'N/A')}")
                    st.write(f"**País:** {asn_info.get('country_code', 'N/A')}")
            else:
                st.warning("No se encontró información en OTX para esta IP, o hubo un error de API.")
