import streamlit as st
import pandas as pd
from scapy.all import IP, Raw

def agregar_a_favoritos(pkt_idx, pkt):
    if Raw in pkt:
        ip_src = pkt[IP].src if IP in pkt else "Desconocida"
        ip_dst = pkt[IP].dst if IP in pkt else "Desconocida"
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_num = pkt[IP].proto if IP in pkt else None
        proto_name = proto_map.get(proto_num, str(proto_num)) if proto_num else "Desconocido"
        payload = bytes(pkt[Raw].load)
        st.session_state.favoritos.append({
            "Índice": pkt_idx,
            "IP Origen": ip_src,
            "IP Destino": ip_dst,
            "Protocolo": proto_name,
            "Payload": payload
        })
        st.success(f"Paquete #{pkt_idx} marcado.")
    else:
        st.warning("Este paquete no tiene payload.")

def mostrar_payloads_marcados():
    st.subheader("📦 Payloads marcados como sospechosos")
    if not st.session_state.favoritos:
        st.info("No has marcado ningún paquete aún.")
        return
    df = pd.DataFrame([{
        "Índice": f["Índice"],
        "IP Origen": f["IP Origen"],
        "IP Destino": f["IP Destino"],
        "Protocolo": f["Protocolo"],
        "Tamaño Payload": len(f["Payload"])
    } for f in st.session_state.favoritos])
    st.dataframe(df, use_container_width=True, height=400)
    for f in st.session_state.favoritos:
        st.markdown(f"#### 🔍 Paquete #{f['Índice']}")
        st.write(f"IP Origen: {f['IP Origen']} | IP Destino: {f['IP Destino']} | Protocolo: {f['Protocolo']}")
        st.dow
