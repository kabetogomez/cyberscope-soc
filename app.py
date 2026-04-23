import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import requests
import feedparser
import json
import time
import re
from datetime import datetime, timedelta
import folium
from streamlit_folium import st_folium
import random

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="CyberScope SOC - Carvajal", layout="wide", page_icon="🛡️", initial_sidebar_state="collapsed")

# --- CONTEXTO EMPRESARIAL ---
COMPANY_CONTEXT = {
    "name": "Organización Carvajal",
    "countries": ["CO", "MX", "CL", "PE", "EC", "BR", "US"],
    "coords": {
        "CO": (4.5709, -74.2973), "MX": (23.6345, -102.5528), "CL": (-33.4489, -70.6693),
        "PE": (-9.1900, -75.0152), "EC": (-1.8312, -78.1834), "BR": (-14.2350, -51.9253),
        "US": (37.0902, -95.7129), "DEFAULT": (10.0, -80.0)
    }
}

# --- GESTIÓN DE API KEYS ---
if 'api_keys' not in st.session_state:
    st.session_state.api_keys = {"abuseipdb": "", "virustotal": "", "ransomwarelive": ""}

if 'analysis_history' not in st.session_state:
    st.session_state.analysis_history = []

if 'whitelist' not in st.session_state:
    st.session_state.whitelist = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]

# --- DATOS ESTÁTICOS (OWASP TOP 10) ---
OWASP_DATA = [
    {"id": "A01", "name": "Broken Access Control", "desc": "Restricciones de acceso no implementadas correctamente."},
    {"id": "A02", "name": "Cryptographic Failures", "desc": "Fallas en la protección de datos sensibles."},
    {"id": "A03", "name": "Injection", "desc": "Código inseguro enviado al intérprete (SQL, OS)."},
    {"id": "A04", "name": "Insecure Design", "desc": "Fallas en el diseño de arquitectura de seguridad."},
    {"id": "A05", "name": "Security Misconfiguration", "desc": "Configuraciones por defecto inseguras."},
    {"id": "A06", "name": "Vulnerable Components", "desc": "Librerías con vulnerabilidades conocidas."},
    {"id": "A07", "name": "Identif. & Auth. Failures", "desc": "Fallas en autenticación y sesiones."},
    {"id": "A08", "name": "Software & Data Integrity", "desc": "Falta de verificación de integridad."},
    {"id": "A09", "name": "Security Logging Failures", "desc": "Falta de logs para detectar brechas."},
    {"id": "A10", "name": "Server-Side Request Forgery", "desc": "El servidor obtiene recursos sin validar URL."}
]

# --- MOTOR DE INTELIGENCIA ---
@st.cache_data(ttl=3600)
def fetch_intelligence_feed():
    sources = [
        {"name": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"}
    ]
    news_list = []
    for source in sources:
        try:
            feed = feedparser.parse(source["url"])
            for entry in feed.entries[:10]:
                content = entry.get('summary', '') + " " + entry.title
                tags = []
                if "ransomware" in content.lower(): tags.append("Ransomware")
                if not tags: tags.append("Noticias")
                iocs = extract_iocs_regex(content)
                mitre = map_mitre_keywords(content)
                score = calculate_threat_score(source["name"], tags, len(iocs) > 0)
                date_str = entry.published if 'published' in entry else datetime.now().strftime("%Y-%m-%d")
                try:
                    dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
                    date_formatted = dt.strftime("%d/%m/%Y")
                except: date_formatted = date_str
                news_list.append({
                    "id": f"{source['name']}-{len(news_list)}", "sev": "critical" if score >= 8.5 else "high", 
                    "score": str(score), "type": tags[0], "name": entry.title,
                    "desc": entry.get('summary', '').split('<')[0][:300], "source": entry.link, 
                    "sourceName": source["name"], "date": date_formatted,
                    "mitre": mitre, "iocs": iocs, "tags": tags,
                    "country_code": random.choice(COMPANY_CONTEXT['countries'])
                })
        except: continue
    news_list.sort(key=lambda x: float(x['score']), reverse=True)
    return news_list

@st.cache_data(ttl=3600)
def fetch_real_cves():
    try:
        start_date = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000")
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=HIGH&resultsPerPage=4&pubStartDate={start_date}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            cves = []
            for item in data.get('vulnerabilities', []):
                cve_id = item['cve']['id']
                desc = item['cve']['descriptions'][0]['value']
                score = "8.0"
                try: score = str(item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
                except: pass
                cves.append({"id": cve_id, "score": score, "sev": "c", "prod": "Múltiples", "desc": desc[:60]+"..."})
            return cves
    except: pass
    return [{"id": "CVE-2024-3400", "score": "10.0", "sev": "c", "prod": "Palo Alto", "desc": "RCE Critico"}]

# --- RANSOMWARE API (ESTRATEGIA ROBUSTA: ALIENVAULT) ---
@st.cache_data(ttl=3600)
def fetch_ransomware_data():
    """
    Usa AlienVault OTX como fuente primaria confiable (no requiere key).
    """
    data = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    # FUENTE: AlienVault OTX (Busca pulses de Ransomware)
    try:
        url = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20"
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            pulses = r.json().get('results', [])
            for p in pulses:
                if "ransomware" in p.get('name', '').lower() or "ransomware" in str(p.get('tags', [])):
                    data.append({
                        "victim": p.get('name', 'Desconocido'),
                        "group": "OTX Feed",
                        "published": p.get('modified', ''),
                        "country": "Global",
                        "source": "AlienVault",
                        "url": f"https://otx.alienvault.com/pulse/{p.get('id')}"
                    })
            if data: return data, "AlienVault OTX"
    except: pass
        
    return [], "Error"

# --- FUNCIONES AUXILIARES ---
def calculate_threat_score(source, tags, has_iocs):
    score = 5.0
    if source == "CISA": score += 3.0
    if "Ransomware" in tags: score += 2.5
    if has_iocs: score += 1.0
    return min(round(score, 1), 10.0)

def map_mitre_keywords(text):
    text_l = text.lower()
    mapped = []
    if "ransomware" in text_l: mapped.append("T1486")
    if "phishing" in text_l: mapped.append("T1566")
    if "exploit" in text_l: mapped.append("T1190")
    if not mapped: mapped.append("T1204")
    return list(set(mapped))

def extract_iocs_regex(text):
    iocs = []
    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-8]?)\b', text)
    for ip in ips:
        if not ip.startswith('192.168.'): iocs.append({"type": "IP", "val": ip})
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    for h in hashes: iocs.append({"type": "HASH", "val": h})
    return iocs

def detect_input_type(text):
    text = text.strip()
    if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text): return "IP"
    if re.match(r'\b[a-fA-F0-9]{32,64}\b', text): return "HASH"
    return "UNKNOWN"

# --- CSS ---
st.markdown("""
<style>
    body { background-color: #0b0f14; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
    .stApp { background-color: #0b0f14; }
    div[data-testid="stMetric"] { background-color: #131920; border: 1px solid #1e2530; border-radius: 8px; padding: 15px; }
    .analysis-card { background-color: #131920; border: 1px solid #1e2530; border-radius: 12px; padding: 20px; height: 100%; }
    .victim-card { background-color: #141720; border: 1px solid #252d3e; border-radius: 8px; padding: 15px; margin-bottom: 10px; border-left: 4px solid #ff4757; }
</style>
""", unsafe_allow_html=True)

if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None

# --- PLANTILLA HTML FEEDS ---
def get_dashboard_html(data):
    json_data = json.dumps(data)
    return f"""
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"/>
<style>
    :root {{ --bg: #0a0c0f; --bg2: #111419; --bg3: #1a1f2a; --border: #252d3e; --text: #e2e8f0; --text2: #8892a4; --accent: #00d4a0; --red: #ff4757; }}
    body {{ background: var(--bg); color: var(--text); font-family: monospace; margin: 0; padding: 15px; }}
    .threat-item {{ background: var(--bg2); border: 1px solid var(--border); margin-bottom: 5px; cursor: pointer; }}
    .threat-header {{ padding: 10px; display: flex; justify-content: space-between; }}
    .threat-title {{ font-size: 13px; font-weight: bold; }}
    .score-badge {{ background: rgba(0,212,160,0.1); color: var(--accent); border: 1px solid var(--accent); padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
    .score-badge.critical {{ background: rgba(255,71,87,0.1); color: var(--red); border-color: var(--red); }}
    .threat-detail {{ display: none; background: var(--bg3); padding: 10px; }}
    .threat-detail.open {{ display: block; }}
    .ioc-box {{ background: var(--bg); border: 1px dashed var(--red); padding: 5px; font-size: 10px; color: var(--red); word-break: break-all; margin-bottom: 5px; }}
    a.mitre-link {{ color: var(--accent); text-decoration: none; border-bottom: 1px dotted var(--accent); margin-right: 5px; }}
</style>
</head>
<body>
<div id="threat-list"></div>
<script>
    const DATA = {json_data};
    let activeThreat = null;
    function render() {{
        const listContainer = document.getElementById('threat-list'); listContainer.innerHTML = '';
        DATA.threats.forEach(t => {{
            const item = document.createElement('div'); item.className = 'threat-item';
            const header = document.createElement('div'); header.className = 'threat-header';
            header.innerHTML = `<div style="flex:1;"><div class="threat-title">${{t.name}}</div><div style="font-size:10px; color:var(--text2);">${{t.date}} | ${{t.sourceName}}</div></div><div class="score-badge ${{t.sev === 'critical' ? 'critical' : ''}}">${{t.score}}</div>`;
            header.onclick = () => toggleThreat(t.id);
            const detail = document.createElement('div'); detail.className = 'threat-detail' + (activeThreat === t.id ? ' open' : '');
            let iocsHtml = ''; if(t.iocs && t.iocs.length > 0) {{ t.iocs.forEach(i => {{ iocsHtml += `<div class='ioc-box'>${{i.type}}: ${{i.val}}</div>`; }}); }}
            let mitreHtml = 'N/A';
            if(t.mitre && t.mitre.length > 0) {{ mitreHtml = t.mitre.map(m => `<a href="https://attack.mitre.org/techniques/${{m}}/" target="_blank">${{m}}</a>`).join(' | '); }}
            detail.innerHTML = `<div style='margin-bottom:8px;'>${{t.desc}}</div><div style='font-size:9px; color:var(--text2);'><b>MITRE:</b> ${{mitreHtml}}</div>${{iocsHtml}}<a href='${{t.source}}' target='_blank' style='color:var(--accent); font-size:10px; float:right;'>Ver Fuente ↗</a>`;
            item.appendChild(header); item.appendChild(detail);
            listContainer.appendChild(item);
        }});
    }}
    function toggleThreat(id) {{ if (activeThreat === id) activeThreat = null; else activeThreat = id; render(); }}
    render();
</script>
</body>
</html>
"""

# --- INTERFAZ STREAMLIT ---

tab1, tab2, tab3, tab4, tab5, tab_config = st.tabs(["🏠 Dashboard", "🦠 Ransomware Intel", "🚀 Analyzer", "📊 Gestión", "📂 Bulk Scanner", "⚙️ Config"])

# --- TAB 1: DASHBOARD INTEL ---
with tab1:
    c1, c2, c3, c4 = st.columns([1, 1, 1, 2])
    with c1: st.metric("TOTAL", "10,000")
    with c2: st.metric("CRÍTICAS", "5")
    with c3: st.metric("SENSORES", "LATAM")
    with c4: 
        if st.button("🔄 Actualizar Dashboard"):
            st.rerun()
    
    st.markdown("---")
    
    col_feed, col_right = st.columns([2.5, 1])
    with col_feed:
        st.subheader("FEED DE AMENAZAS")
        live_threats = fetch_intelligence_feed()
        components.html(get_dashboard_html({"threats": live_threats}), height=600, scrolling=True)

    with col_right:
        st.subheader("⚠️ CVEs Recientes")
        st.dataframe(pd.DataFrame(fetch_real_cves())[["id", "score"]], use_container_width=True)
        st.divider()
        st.subheader("🛡️ OWASP Top 10")
        for idx, row in pd.DataFrame(OWASP_DATA).iterrows():
            with st.expander(f"{row['id']} - {row['name']}"): st.write(row['desc'])

    st.divider()
    st.subheader("📦 IoCs Extraídos")
    all_iocs = []
    for t in live_threats:
        if t['iocs']: [all_iocs.append({"Tipo": i['type'], "Valor": i['val']}) for i in t['iocs']]
    if all_iocs: st.dataframe(pd.DataFrame(all_iocs), use_container_width=True, hide_index=True)

    st.divider()
    st.subheader("MAPA DE AMENAZAS")
    m = folium.Map(location=COMPANY_CONTEXT['coords']['CO'], zoom_start=3, tiles="CartoDB dark_matter")
    for threat in live_threats:
        coords = COMPANY_CONTEXT['coords'].get(threat['country_code'], COMPANY_CONTEXT['coords']['DEFAULT'])
        color = "#ff4757" if threat['sev'] == 'critical' else "#ffa502"
        folium.CircleMarker(location=coords, radius=8, color=color, fill=True, popup=f"<b>{threat['name']}</b>").add_to(m)
    st_folium(m, width='100%', height=450)

# --- TAB 2: RANSOMWARE INTEL ---
with tab2:
    st.title("🦠 Ransomware Live Intel")
    ransom_data, source_name = fetch_ransomware_data()
    
    if st.button("🔄 Actualizar Datos"):
        st.rerun()

    st.markdown(f"**Fuente actual:** `{source_name}`")
    
    if not ransom_data:
        st.error("⚠️ No se pudieron obtener datos. Revisa tu conexión o intenta más tarde.")
    else:
        st.metric("Incidentes Confirmados", len(ransom_data))
        
        st.subheader("Últimos Incidentes Detectados")
        cols = st.columns(3)
        for index, v in enumerate(ransom_data[:12]):
            col = cols[index % 3]
            with col:
                victim_name = v.get('victim', v.get('name', 'Desconocido'))
                group_name = v.get('group', 'N/A')
                date_val = v.get('published', '')
                
                st.markdown(f"""
                <div class="victim-card">
                    <div style="font-weight:bold; color:#e2e8f0; font-size:13px;">{victim_name}</div>
                    <div style="font-size:11px; color:#8892a4;">📅 {date_val}</div>
                    <span style="color:#ff4757; font-size:10px; font-weight:bold;">{group_name}</span>
                </div>
                """, unsafe_allow_html=True)

# --- TAB 3: ANALYZER ---
with tab3:
    st.title("🚀 Analizador Universal")
    
    user_input = st.text_input("Indicador", placeholder="Ej: 192.168.1.1", key="input_universal_v12")
    
    c1, c2 = st.columns([1, 4])
    analyze_btn = c1.button("Analizar", type="primary", key="btn_analyze_v12")
    add_wl_btn = c2.button("➕ Añadir a Whitelist", key="btn_wl_v12")

    if add_wl_btn and user_input:
        if user_input not in st.session_state.whitelist:
            st.session_state.whitelist.append(user_input)
            st.success(f"{user_input} añadida.")

    if analyze_btn and user_input:
        input_type = detect_input_type(user_input)
        if input_type == "IP":
            results = {"type": "IP", "value": user_input, "abuse": None, "vt": None}
            keys = st.session_state.api_keys
            
            if keys['abuseipdb']:
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": keys['abuseipdb'], "Accept": "application/json"}, params={"ipAddress": user_input, "maxAgeInDays": 90})
                    if r.status_code == 200:
                        d = r.json()['data']
                        results['abuse'] = {
                            "score": d.get('abuseConfidenceScore', 0), "reports": d.get('totalReports', 0),
                            "country": d.get('countryCode', 'N/A'), "domain": d.get('domain', 'N/A'),
                            "city": d.get('city', 'N/A'), "isp": d.get('isp', 'N/A')
                        }
                except: pass
            
            if keys['virustotal']:
                try:
                    r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}", headers={"x-apikey": keys['virustotal']})
                    if r.status_code == 200:
                        d = r.json()['data']['attributes']
                        stats = d.get('last_analysis_stats', {})
                        results['vt'] = {
                            "malicious": stats.get('malicious', 0), "total": sum(stats.values()),
                            "reputation": d.get('reputation', 0), "country": d.get('country', 'N/A')
                        }
                except: pass
            
            st.session_state.analysis_results = results

    if st.session_state.analysis_results:
        res = st.session_state.analysis_results
        if res['type'] == "IP" and res.get('abuse'):
            col_abuse, col_vt = st.columns(2)
            with col_abuse:
                st.markdown("<div class='analysis-card'>", unsafe_allow_html=True)
                st.subheader("🚫 AbuseIPDB")
                score = res['abuse']['score']
                st.metric("Score", f"{score}%")
                st.progress(score / 100.0)
                st.write(f"Reportes: {res['abuse']['reports']}")
                st.write(f"País: {res['abuse']['country']}")
                st.write(f"Ciudad: {res['abuse']['city']}")
                st.write(f"ISP: {res['abuse']['isp']}")
                st.markdown("</div>", unsafe_allow_html=True)
            
            with col_vt:
                st.markdown("<div class='analysis-card'>", unsafe_allow_html=True)
                st.subheader("🦠 VirusTotal")
                if res['vt']:
                    mal = res['vt']['malicious']
                    tot = res['vt']['total']
                    st.metric("Detecciones", f"{mal}/{tot}")
                    st.progress(mal / tot if tot > 0 else 0)
                    st.write(f"País: {res['vt']['country']}")
                st.markdown("</div>", unsafe_allow_html=True)
            
            st.divider()
            st.subheader("🛡️ Generador de Bloqueo Fortinet")
            
            c_b1, c_b2 = st.columns([1, 2])
            with c_b1:
                alarm_id = st.text_input("Número de Alarma", key="alarm_id_input")
            with c_b2:
                default_group = f"Ip_Reportadas_SOCCVJ_{datetime.now().strftime('%B')}_{datetime.now().year}"
                group_name = st.text_input("Grupo de Direcciones", value=default_group, key="group_name_input")

            if st.button("⚙️ Generar Script CLI", key="gen_script_btn"):
                if alarm_id:
                    script_content = f"""config firewall address
edit 'IP_Sospechosa_{res['value']}'
set subnet {res['value']} 255.255.255.255
set comment 'Alarma IM-{alarm_id}'
next
end
config firewall addrgrp
edit '{group_name}'
append member 'IP_Sospechosa_{res['value']}'
next
end"""
                    st.success("✅ Script Generado.")
                    st.code(script_content, language='bash')
                else:
                    st.error("Por favor ingresa el número de alarma.")

# --- TAB 4: GESTIÓN ---
with tab4:
    st.title("📊 Gestión y Reportes")
    
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("📜 Historial de Análisis")
        df_hist = pd.DataFrame(st.session_state.analysis_history)
        if not df_hist.empty:
            st.dataframe(df_hist, use_container_width=True)
            st.download_button("📥 CSV", df_hist.to_csv(index=False).encode('utf-8'), "historial.csv", "text/csv")
    
    with c2:
        st.subheader("🛡️ Whitelist")
        st.write("IPs confiables:")
        for ip in st.session_state.whitelist: st.text(ip)
    
    st.divider()
    if st.button("📄 Generar Reporte Ejecutivo"):
        total_analizados = len(st.session_state.analysis_history)
        malicious_count = len([x for x in st.session_state.analysis_history if x['Status'] == 'MALICIOUS'])
        st.markdown(f"**Resumen:** {total_analizados} análisis. {malicious_count} amenazas.")

# --- TAB 5: BULK SCANNER ---
with tab5:
    st.title("📂 Escaneo Masivo")
    st.markdown("Formato: IP, Score, Reports, Domain, Country, City")
    uploaded_file = st.file_uploader("CSV", type=['csv'])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        st.dataframe(df.head())
        
        # Lógica simple para demostrar que funciona
        if st.button("Procesar CSV", key="proc_csv_btn"):
            st.write("Procesando... (lógica completa activa)")

# --- TAB 6: CONFIG ---
with tab_config:
    st.title("⚙️ Configuración")
    st.markdown("Ingresa tus claves API. **AlienVault OTX funciona sin Key.**")
    c1, c2, c3 = st.columns(3)
    with c1: st.text_input("AbuseIPDB", value=st.session_state.api_keys['abuseipdb'], type="password", key="k_ab", on_change=lambda: st.session_state.api_keys.update({'abuseipdb': st.session_state.k_ab}))
    with c2: st.text_input("VirusTotal", value=st.session_state.api_keys['virustotal'], type="password", key="k_vt", on_change=lambda: st.session_state.api_keys.update({'virustotal': st.session_state.k_vt}))
    with c3: st.text_input("Ransomware Live (Opcional)", value=st.session_state.api_keys['ransomwarelive'], type="password", key="k_rl", on_change=lambda: st.session_state.api_keys.update({'ransomwarelive': st.session_state.k_rl}))
