# modules/modulo_yara.py

import yara
import streamlit as st

def cargar_reglas_yara(ruta_archivo):
    try:
        reglas = yara.compile(filepath=ruta_archivo)
        return reglas
    except Exception as e:
        st.error(f"❌ Error al cargar reglas YARA: {e}")
        return None

def escanear_payloads(favoritos, reglas):
    resultados = []
    for item in favoritos:
        payload = item["Payload"]
        matches = reglas.match(data=payload)
        if matches:
            resultados.append({
                "Índice": item["Índice"],
                "IP Origen": item["IP Origen"],
                "IP Destino": item["IP Destino"],
                "Protocolo": item["Protocolo"],
                "Reglas detectadas": [m.rule for m in matches]
            })
    return resultados

def mostrar_resultados_yara(resultados):
    if not resultados:
        st.info("✅ No se detectaron coincidencias YARA.")
        return
    st.warning("⚠️ Se encontraron coincidencias con reglas YARA.")
    for r in resultados:
        st.markdown(f"**Paquete #{r['Índice']}**")
        st.write(f"- IP Origen: {r['IP Origen']}")
        st.write(f"- IP Destino: {r['IP Destino']}")
        st.write(f"- Protocolo: {r['Protocolo']}")
        st.write(f"- Reglas detectadas: {', '.join(r['Reglas detectadas'])}")
