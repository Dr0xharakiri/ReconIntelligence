import streamlit as st
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw

from modules.payloads import agregar_a_favoritos

def mostrar_paquetes_con_detalle(uploaded_file):
    st.subheader("📦 Todos los paquetes analizados")

    try:
        uploaded_file.seek(0)
        paquetes = rdpcap(uploaded_file)
    except Exception as e:
        st.error(f"❌ Error al procesar el archivo: {e}")
        return

    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    tabla = []
    for i, pkt in enumerate(paquetes):
        proto_num = pkt[IP].proto if IP in pkt else None
        proto_name = proto_map.get(proto_num, str(proto_num)) if proto_num else "N/A"
        tabla.append({
            "Índice": i,
            "IP Origen": pkt[IP].src if IP in pkt else "N/A",
            "IP Destino": pkt[IP].dst if IP in pkt else "N/A",
            "Protocolo": proto_name,
            "Tamaño": len(pkt)
        })

    df = pd.DataFrame(tabla)
    st.dataframe(df, use_container_width=True, height=400)

    idx = st.selectbox("Selecciona un paquete para inspección:", df["Índice"])
    if st.button("🔍 Inspeccionar paquete seleccionado"):
        pkt = paquetes[idx]
        st.markdown(f"### Detalles técnicos del paquete #{idx}")
        st.code(pkt.show(dump=True))

    if st.button("⭐ Marcar como sospechoso"):
        pkt = paquetes[idx]
        agregar_a_favoritos(idx, pkt)
        if Raw in pkt:
            st.markdown("#### Payload (bruto):")
            try:
                st.text(pkt[Raw].load.decode("utf-8", errors="ignore"))
            except:
                st.text("Payload no decodificable como texto.")
        else:
            st.info("Este paquete no tiene capa Raw.")
