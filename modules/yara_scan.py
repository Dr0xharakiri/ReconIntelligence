import streamlit as st
from modules.modulo_yara import cargar_reglas_yara, escanear_payloads, mostrar_resultados_yara

def escanear_con_yara():
    st.markdown("## 🔬 Análisis con Reglas YARA")
    archivo_yara = st.file_uploader("Carga un archivo de reglas YARA (.yar)", type=["yar"])

    if archivo_yara and st.button("🧪 Ejecutar análisis YARA sobre los payloads marcados"):

        # Asegurar que favoritos exista
        if "favoritos" not in st.session_state or not st.session_state.favoritos:
            st.warning("⚠️ No hay payloads marcados para analizar.")
            return

        # Guardar archivo temporal
        with open("reglas_temporales.yar", "wb") as f:
            f.write(archivo_yara.read())

        reglas = cargar_reglas_yara("reglas_temporales.yar")

        if not reglas:
            st.warning("⚠️ No se pudieron cargar las reglas YARA.")
            return

        try:
            resultados = escanear_payloads(st.session_state.favoritos, reglas)
            mostrar_resultados_yara(resultados)
        except Exception as e:
            st.error(f"❌ Error durante el análisis YARA: {e}")
