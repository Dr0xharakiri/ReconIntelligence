import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import plotly.io as pio
import tempfile
from scapy.all import rdpcap, IP, TCP, UDP, ARP, Ether
import networkx as nx

pio.templates["recon_theme"] = go.layout.Template(
    layout=go.Layout(
        font=dict(family="Share Tech Mono", size=14, color="#e0fdfd"),
        title=dict(font=dict(family="Inter", size=20, color="#8ef0f4")),
        paper_bgcolor="#0f1111",
        plot_bgcolor="#0f1111",
        xaxis=dict(color="#e0fdfd", gridcolor="#222222", zerolinecolor="#333333"),
        yaxis=dict(color="#e0fdfd", gridcolor="#222222", zerolinecolor="#333333"),
        legend=dict(font=dict(color="#e0fdfd"), bgcolor="#101414")
    )
)

def detectar_protocolo_aplicacion(pkt):
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if 80 in [sport, dport]: return "HTTP"
        elif 443 in [sport, dport]: return "HTTPS"
        elif 21 in [sport, dport]: return "FTP"
        elif 23 in [sport, dport]: return "Telnet"
        elif 22 in [sport, dport]: return "SSH"
        elif 25 in [sport, dport]: return "SMTP"
        elif 445 in [sport, dport]: return "SMB"
        elif 139 in [sport, dport]: return "NetBIOS"
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if 53 in [sport, dport]: return "DNS"
    return "Otro"

def dashboard_analisis_protocolo_ip(uploaded_file):
    st.header("📊 Dashboard de Análisis de Protocolos e IPs (Avanzado)")

    try:
        uploaded_file.seek(0)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
            tmp.write(uploaded_file.read())
            tmp_path = tmp.name
        paquetes = rdpcap(tmp_path)
    except Exception as e:
        st.error(f"❌ Error al procesar el archivo: {e}")
        return

    data = []
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
    for pkt in paquetes:
        if IP in pkt:
            proto_num = pkt[IP].proto
            proto = proto_map.get(proto_num, f"Desconocido ({proto_num})")
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
        elif ARP in pkt:
            proto = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            src_port = None
            dst_port = None
        elif Ether in pkt:
            proto = "Ethernet"
            src_ip = pkt[Ether].src
            dst_ip = pkt[Ether].dst
            src_port = None
            dst_port = None
        else:
            proto = "Otros"
            src_ip = None
            dst_ip = None
            src_port = None
            dst_port = None

        proto_aplicacion = detectar_protocolo_aplicacion(pkt)

        data.append({
            "Tiempo": pkt.time,
            "Protocolo": proto,
            "Protocolo Aplicación": proto_aplicacion,
            "IP Origen": src_ip,
            "IP Destino": dst_ip,
            "Puerto Origen": src_port,
            "Puerto Destino": dst_port,
            "Tamaño": len(pkt)
        })

    df = pd.DataFrame(data)

    protocolos_sospechosos = ["SMB", "Telnet", "NetBIOS", "FTP"]
    detecciones = df[df["Protocolo Aplicación"].isin(protocolos_sospechosos)]
    if not detecciones.empty:
        st.error("⚠️ Se detectó tráfico potencialmente sensible o vulnerable:")
        for p in protocolos_sospechosos:
            count = detecciones[detecciones["Protocolo Aplicación"] == p].shape[0]
            if count > 0:
                st.markdown(f"- **{p}** → {count} paquetes detectados")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📦 Total Paquetes", len(df))
    col2.metric("🌐 IPs Origen únicas", df["IP Origen"].nunique())
    col3.metric("🎯 IPs Destino únicas", df["IP Destino"].nunique())
    col4.metric("🧬 Protocolos detectados", df["Protocolo"].nunique())

    st.subheader("Protocolos detectados")
    proto_count = df["Protocolo"].value_counts().reset_index()
    proto_count.columns = ["Protocolo", "Cantidad"]
    fig_proto = px.bar(proto_count, x="Protocolo", y="Cantidad", color="Protocolo", title="Cantidad de paquetes por protocolo", template="recon_theme")
    st.plotly_chart(fig_proto, use_container_width=True)

    st.subheader("Protocolos de Aplicación detectados")
    app_proto_count = df["Protocolo Aplicación"].value_counts().reset_index()
    app_proto_count.columns = ["Protocolo Aplicación", "Cantidad"]
    fig_app_proto = px.bar(app_proto_count, x="Protocolo Aplicación", y="Cantidad", color="Protocolo Aplicación",
                           title="Cantidad de paquetes por protocolo de aplicación", template="recon_theme")
    st.plotly_chart(fig_app_proto, use_container_width=True)

    st.subheader("Top 10 IPs Origen y Destino")
    colA, colB = st.columns(2)
    top_src = df["IP Origen"].value_counts().head(10).reset_index()
    top_src.columns = ["IP Origen", "Cantidad"]
    colA.plotly_chart(px.bar(top_src, x="IP Origen", y="Cantidad", title="Top IPs Origen", template="recon_theme"), use_container_width=True)
    top_dst = df["IP Destino"].value_counts().head(10).reset_index()
    top_dst.columns = ["IP Destino", "Cantidad"]
    colB.plotly_chart(px.bar(top_dst, x="IP Destino", y="Cantidad", title="Top IPs Destino", template="recon_theme"), use_container_width=True)

    st.subheader("Distribución de Tamaños de Paquetes")
    fig_size = px.histogram(df, x="Tamaño", nbins=30, title="Histograma de tamaños de paquetes", template="recon_theme")
    st.plotly_chart(fig_size, use_container_width=True)

    st.subheader("Mapa de Interacciones IP")
    G = nx.DiGraph()
    for _, row in df.iterrows():
        if row["IP Origen"] and row["IP Destino"]:
            G.add_edge(row["IP Origen"], row["IP Destino"])
    pos = nx.spring_layout(G, k=0.5, iterations=20, seed=42)
    fig_inter = px.scatter(
        x=[pos[n][0] for n in G.nodes()],
        y=[pos[n][1] for n in G.nodes()],
        text=list(G.nodes()),
        labels={'x': "X", 'y': "Y"},
        title="Interacciones entre IPs",
        template="recon_theme"
    )
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        fig_inter.add_shape(
            type="line",
            x0=x0, y0=y0, x1=x1, y1=y1,
            line=dict(width=1, color="blue"),
            opacity=0.5
        )
    fig_inter.update_traces(textposition='top center')
    st.plotly_chart(fig_inter, use_container_width=True)

    st.subheader("Tabla de Paquetes (filtros avanzados)")
    with st.expander("Mostrar/ocultar tabla completa de paquetes"):
        st.dataframe(df, use_container_width=True, height=400)
