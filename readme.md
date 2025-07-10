# 🧠 ReconIntelligence

**ReconIntelligence** es una plataforma avanzada de análisis de tráfico de red orientada a la ciberinteligencia. Su propósito es ofrecer una interfaz moderna y funcional para el procesamiento de archivos PCAP, permitiendo identificar amenazas, comportamientos anómalos y patrones sospechosos dentro de redes, todo desde una única herramienta interactiva desarrollada en Python con Streamlit.

---

## 🚀 Características principales

- 📦 Procesamiento automático de archivos `.pcap`
- 🧠 Enriquecimiento de IPs y dominios con inteligencia de amenazas (AlienVault OTX)
- 📍 Geolocalización de IPs mediante base de datos GeoIP y visualización con Folium
- 📊 Visualización interactiva de datos con Altair y Plotly
- 📄 Generación automática de reportes PDF con hallazgos
- 🧬 Escaneo de payloads con reglas YARA personalizadas
- 🌐 Análisis detallado de consultas DNS y eventos sospechosos

---

## 🛠️ Tecnologías utilizadas

- **Lenguaje:** Python 3.8+
- **Framework web:** Streamlit
- **Librerías de red:** Scapy, dpkt, PyShark
- **Visualización:** Plotly, Altair, Matplotlib, Folium
- **Ciberinteligencia:** AlienVault OTX API
- **GeoIP:** geoip2
- **YARA scanning:** yara-python
- **Grafo de comunicación:** NetworkX


```

---

## ⚙️ Instalación y ejecución

### 1. Clonar el repositorio

```bash
git clone https://github.com/Dr0xharakiri/ReconIntelligence.git
cd ReconIntelligence
```

### 2. Crear entorno virtual (opcional pero recomendado)

```bash
python -m venv venv
source venv/bin/activate      # En Linux/macOS
venv\Scripts\activate.bat     # En Windows
```

### 3. Instalar dependencias

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Contenido sugerido para `requirements.txt`:

```
streamlit
scapy
pyshark
plotly
altair
matplotlib
folium
yara-python
networkx
geoip2
reportlab
requests
```

### 4. Ejecutar la aplicación

```bash
streamlit run main.py
```

La aplicación se abrirá en tu navegador predeterminado. Si no lo hace, visita [http://localhost:8501](http://localhost:8501)

---

## ✅ Requisitos previos

- Python 3.8 o superior
- Acceso a Internet para uso de AlienVault OTX
- Base de datos GeoLite2 (si deseas geolocalización): https://dev.maxmind.com/geoip/geolite2/
- API key válida de OTX: https://otx.alienvault.com/
- Permisos para cargar o analizar archivos PCAP

---

## 🧪 Modo de uso

1. Carga un archivo `.pcap` desde la interfaz web.
2. Visualiza las conexiones, protocolos y eventos detectados.
3. Revisa dominios/IPs sospechosos enriquecidos con OTX.
4. Visualiza interacciones entre IPs en forma de grafo.
5. Examina los payloads con YARA.
6. Genera un reporte PDF del análisis.

---

## 📌 Roadmap (Próximas mejoras)

- [ ] Detección automática de comportamiento tipo C2
- [ ] Soporte para múltiples archivos simultáneos
- [ ] Integración con VirusTotal
- [ ] Exportación de eventos a JSON/CSV
- [ ] Consola avanzada de búsqueda tipo SIEM

---

## 👤 Autor

**Dr0xharakiri**  
Especialista en Pentesting & Cyber Threat Intelligence  
GitHub: [https://github.com/Dr0xharakiri](https://github.com/Dr0xharakiri)

---

## 🧠 Licencia

Este proyecto se distribuye bajo la Licencia MIT.

```
MIT License

Copyright (c) 2025 Dr0xharakiri

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

> ⚠️ **Aviso**: Este proyecto fue creado con fines educativos y de investigación.  
> El uso indebido para propósitos no éticos o ilegales es responsabilidad exclusiva del usuario.
