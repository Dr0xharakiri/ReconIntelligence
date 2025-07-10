import pandas as pd
import scapy.all as scapy
from collections import Counter
import tempfile

def analyze_pcap(temp_file_path):
    packets = scapy.rdpcap(temp_file_path)
    ip_data = []
    traffic_counter = {}
    dns_queries = []
    protocol_counts = Counter()
    gateway_ip = None
    for packet in packets:
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            if gateway_ip is None:
                gateway_ip = src_ip
            ip_data.append({"IP Fuente": src_ip, "IP Destino": dst_ip})
            traffic_counter[src_ip] = traffic_counter.get(src_ip, 0) + 1
            traffic_counter[dst_ip] = traffic_counter.get(dst_ip, 0) + 1
        if packet.haslayer(scapy.DNSRR):
            dns_queries.append(packet[scapy.DNSRR].rrname.decode())
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport in [80, 443, 21] or packet[scapy.TCP].sport in [80, 443, 21]:
                protocol_counts['TCP'] += 1
        elif packet.haslayer(scapy.ICMP):
            protocol_counts['ICMP'] += 1

    ip_data_df = pd.DataFrame(ip_data)
    traffic_data_df = pd.DataFrame([{"IP": ip, "Paquetes": count} for ip, count in traffic_counter.items()])
    dns_queries_df = pd.DataFrame(Counter(dns_queries).most_common(), columns=["DNS Query", "Frecuencia"])
    return ip_data_df, traffic_data_df, dns_queries_df, protocol_counts, gateway_ip, len(packets)

def process_pcap(file_buffer):
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file_buffer.read())
        temp_file_path = temp_file.name
    return analyze_pcap(temp_file_path)

def show_dashboard(ip_data, traffic_data, dns_queries, protocol_counts, gateway_ip, total_packets, option):
    import streamlit as st
    import plotly.express as px
    st.title("PCAP Intelligence Dashboard")
    st.subheader("Estadísticas Generales")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total de Paquetes Capturados", total_packets)
    col2.metric("Total de IPs Detectadas", len(traffic_data))
    col3.metric("Total de DNS Queries", len(dns_queries))
    col4.metric("Protocolo Principal", max(protocol_counts, key=protocol_counts.get) if protocol_counts else "N/A")

    if option == "Listado de IPs":
        st.dataframe(ip_data, use_container_width=True)
    elif option == "Cantidad de paquetes por IP":
        chart = px.bar(traffic_data, x="IP", y="Paquetes", title="Tráfico por IP")
        st.plotly_chart(chart)
    elif option == "DNS Queries":
        st.dataframe(dns_queries, use_container_width=True)
    elif option == "Protocolos":
        protocol_df = pd.DataFrame(protocol_counts.items(), columns=["Protocolo", "Conteo"])
        chart = px.bar(protocol_df, x="Protocolo", y="Conteo", title="Cantidad de Paquetes por Protocolo")
        st.plotly_chart(chart)
    elif option == "Interacción entre IPs":
        import networkx as nx
        from pyvis.network import Network
        import os
        if ip_data.empty:
            st.warning("No se encontraron conexiones IP para mostrar.")
        else:
            try:
                G = nx.Graph()
                conexiones = list(zip(ip_data["IP Fuente"], ip_data["IP Destino"]))
                G.add_edges_from(conexiones)
                if G.number_of_edges() == 0:
                    st.warning("No se encontraron suficientes interacciones entre IPs para graficar.")
                else:
                    net = Network(height='700px', width='100%', bgcolor='#222222', font_color='white')
                    net.from_nx(G)
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
                        net.save_graph(tmp_file.name)
                        html_content = open(tmp_file.name, 'r', encoding='utf-8').read()
                        st.components.v1.html(html_content, height=700)
                        os.unlink(tmp_file.name)
            except Exception as e:
                st.error(f"Ocurrió un error al generar el grafo: {e}")
