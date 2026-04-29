import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import requests
import feedparser
import json
import time
import re
import base64
import html as html_module
from datetime import datetime, timedelta
import folium
from streamlit_folium import st_folium
import random

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(page_title="CyberScopeCG Pro", layout="wide", page_icon="🛡️", initial_sidebar_state="collapsed")

# --- 1. SISTEMA DE LOGIN ---
def check_password(username, password):
    if username == "admin" and password == "soc123": return True
    if username == "analista" and password == "analista123": return True
    return False

def login_screen():
    st.title("🔒 Acceso a CyberScopeCG Pro")
    st.markdown("### Plataforma de Inteligencia y Respuesta")
    with st.form(key='login_form'):
        username = st.text_input("Usuario", value="admin")
        password = st.text_input("Contraseña", type="password", value="soc123")
        submit = st.form_submit_button("Ingresar")
        if submit:
            if check_password(username, password):
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.rerun()
            else:
                st.error("❌ Credenciales incorrectas")

if 'logged_in' not in st.session_state: st.session_state.logged_in = False

if not st.session_state.logged_in:
    login_screen()
    st.stop()

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

# --- DATOS ESTÁTICOS (OWASP TOP 10) ---
# --- DATOS ESTÁTICOS (OWASP TOP 10 - ENRIQUECIDO) ---
OWASP_DATA = [
    {
        "id": "A01", "name": "Broken Access Control", 
        "desc": "Restricciones de acceso no implementadas correctamente.",
        "keywords": ["access control", "idor", "broken access", "privilege escalation", "bypass"],
        "mitigation": "Implementar control de acceso basado en roles (RBAC) y negar por defecto.",
        "cwe": "CWE-284"
    },
    {
        "id": "A02", "name": "Cryptographic Failures", 
        "desc": "Fallas en la protección de datos sensibles.",
        "keywords": ["crypto", "encryption", "ssl", "tls", "sensitive data", "password dump"],
        "mitigation": "Cifrar datos en reposo y tránsito. No almacenar secretos en código.",
        "cwe": "CWE-311"
    },
    {
        "id": "A03", "name": "Injection", 
        "desc": "Código inseguro enviado al intérprete (SQL, OS).",
        "keywords": ["sql injection", "xss", "command injection", "rce", "nosql", "ldap injection"],
        "mitigation": "Usar sentencias preparadas (Parameterized Queries) y validar entradas.",
        "cwe": "CWE-78"
    },
    {
        "id": "A04", "name": "Insecure Design", 
        "desc": "Fallas en el diseño de arquitectura de seguridad.",
        "keywords": ["design flaw", "architecture", "threat modeling", "logic flaw"],
        "mitigation": "Implementar modelado de amenazas en el ciclo de desarrollo.",
        "cwe": "CWE-1059"
    },
    {
        "id": "A05", "name": "Security Misconfiguration", 
        "desc": "Configuraciones por defecto inseguras.",
        "keywords": ["misconfiguration", "default password", "open port", "directory listing", "s3 bucket"],
        "mitigation": "Hardening de servidores y revisiones de configuración automatizadas.",
        "cwe": "CWE-16"
    },
    {
        "id": "A06", "name": "Vulnerable Components", 
        "desc": "Librerías con vulnerabilidades conocidas.",
        "keywords": ["vulnerable library", "outdated", "cve-", "dependency", "log4j"],
        "mitigation": "Inventario de dependencias (SBOM) y escaneo automatizado.",
        "cwe": "CWE-1104"
    },
    {
        "id": "A07", "name": "Identif. & Auth. Failures", 
        "desc": "Fallas en autenticación y sesiones.",
        "keywords": ["authentication", "credential stuffing", "brute force", "session hijacking", "mfa"],
        "mitigation": "Implementar MFA y gestión segura de sesiones.",
        "cwe": "CWE-287"
    },
    {
        "id": "A08", "name": "Software & Data Integrity", 
        "desc": "Falta de verificación de integridad.",
        "keywords": ["supply chain", "ci/cd", "integrity", "update", "malicious package"],
        "mitigation": "Firmar digitalmente los despliegues y verificar sumas de verificación.",
        "cwe": "CWE-353"
    },
    {
        "id": "A09", "name": "Security Logging Failures", 
        "desc": "Falta de logs para detectar brechas.",
        "keywords": ["logging", "audit", "monitoring", "detection gap", "log injection"],
        "mitigation": "Centralizar logs en SIEM y alertar sobre eventos críticos.",
        "cwe": "CWE-778"
    },
    {
        "id": "A10", "name": "Server-Side Request Forgery", 
        "desc": "El servidor obtiene recursos sin validar URL.",
        "keywords": ["ssrf", "server side request", "fetch url", "internal network"],
        "mitigation": "Validar y sanitizar todas las URLs de entrada. Bloquear puertos internos.",
        "cwe": "CWE-918"
    }
]

# Estado para los checkboxes
if 'owasp_checks' not in st.session_state:
    st.session_state.owasp_checks = {item['id']: False for item in OWASP_DATA}

# --- GESTIÓN DE ESTADO Y TEMA ---
if 'api_keys' not in st.session_state: st.session_state.api_keys = {"abuseipdb": "", "virustotal": "", "vuldb": ""}
if 'dark_mode' not in st.session_state: st.session_state.dark_mode = True
if 'analysis_history' not in st.session_state: st.session_state.analysis_history = []
if 'whitelist' not in st.session_state: st.session_state.whitelist = ["8.8.8.8", "8.8.4.4"]
if 'watcher_assets' not in st.session_state: st.session_state.watcher_assets = []
if 'analysis_results' not in st.session_state: st.session_state.analysis_results = None
if 'input_ip_val' not in st.session_state: st.session_state.input_ip_val = ""
if 'input_hash_val' not in st.session_state: st.session_state.input_hash_val = ""
if 'input_url_val' not in st.session_state: st.session_state.input_url_val = ""

MESES_ES = {1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"}

# --- CSS DINÁMICO ---
def inject_css():
    dark = st.session_state.dark_mode
    bg_color = "#0b0f14" if dark else "#f8f9fa"
    bg_secondary = "#131920" if dark else "#ffffff"
    text_color = "#e2e8f0" if dark else "#212529"
    text_secondary = "#8892a4" if dark else "#495057"
    border_color = "#1e2530" if dark else "#dee2e6"
    accent_color = "#00d4a0" if dark else "#0d6efd"
    
    st.markdown(f"""
    <style>
        body, .stApp, .main .block-container {{ background-color: {bg_color}; color: {text_color}; transition: all 0.3s ease; }}
        p, span, div, label, .stMarkdown {{ color: {text_color} !important; }}
        div[data-testid="stMetric"], .analysis-card, .evidence-card {{ background-color: {bg_secondary}; border: 1px solid {border_color}; border-radius: 8px; padding: 20px; }}
        .evidence-card {{ border-left: 5px solid {accent_color}; margin-bottom: 20px; }}
        .evidence-header {{ font-size: 20px; font-weight: bold; color: {accent_color}; border-bottom: 1px solid {border_color}; padding-bottom: 10px; margin-bottom: 15px; }}
        .data-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid {border_color}; }}
        .data-label {{ color: {text_secondary}; font-size: 14px; }}
        .data-value {{ color: {text_color}; font-weight: bold; text-align: right; }}
        .stTextInput > div > div > input, .stTextArea textarea {{ background-color: {bg_secondary} !important; color: {text_color} !important; border: 1px solid {border_color}; }}
        .stButton > button {{ background-color: {accent_color}; color: white; border-radius: 5px; border: none; }}
        .step-box {{ background-color: {bg_secondary}; border-left: 4px solid {accent_color}; padding: 10px; margin-bottom: 10px; }}
        /* Estilo para el Título Principal Centrado */
        .main-title {{ text-align: center; padding: 10px 0 20px 0; }}
        .main-title h1 {{ color: {accent_color}; margin: 0; font-size: 2.5rem; letter-spacing: 2px; }}
        .main-title h4 {{ color: {text_secondary}; margin: 5px 0 0 0; font-weight: normal; }}
    </style>
    """, unsafe_allow_html=True)

inject_css()

# --- TÍTULO GLOBAL (VISIBLE EN TODAS LAS PESTAÑAS) ---
st.markdown("""
<div class="main-title">
    <h1>CyberScopeCG</h1>
    <h4>Threat Intelligence & Response Platform</h4>
</div>
""", unsafe_allow_html=True)

# --- FUNCIONES AUXILIARES ---

def calculate_owasp_relevance(threats, owasp_data):
    # Diccionario para guardar conteos
    relevance = {item['id']: 0 for item in owasp_data}
    
    for threat in threats:
        content = (threat.get('name', '') + " " + threat.get('desc', '')).lower()
        for item in owasp_data:
            for keyword in item['keywords']:
                if keyword in content:
                    relevance[item['id']] += 1
                    break # Contar solo una vez por noticia
    
    return relevance

def is_private_ip(ip):
    priv_lo = re.compile("^127\.")
    priv_24 = re.compile("^10\.")
    priv_20 = re.compile("^192\.168\.")
    priv_16 = re.compile("^172.(1[6-9]|2[0-9]|3[0-1])\.")
    return any([priv_lo.match(ip), priv_24.match(ip), priv_20.match(ip), priv_16.match(ip)])

def calculate_threat_score(source, tags, has_iocs):
    score = 5.0
    if source == "CISA": score += 3.0
    if "Ransomware" in tags: score += 2.5
    if "0-day" in tags: score += 3.0
    if has_iocs: score += 1.5
    return min(round(score, 1), 10.0)

def classify_threat(text):
    t = text.lower()
    if "zero-day" in t or "0-day" in t: return "0-Day"
    if "ransomware" in t: return "Ransomware"
    if "apt" in t: return "APT"
    if "exploit" in t: return "Exploit"
    if "vulnerability" in t or "cve" in t: return "Vulnerability"
    return "General"

def map_mitre_keywords(text):
    text_l = text.lower()
    mapped = []
    if "ransomware" in text_l: mapped.append("T1486")
    if "phishing" in text_l: mapped.append("T1566")
    if "exploit" in text_l: mapped.append("T1190")
    return list(set(mapped)) if mapped else ["T1204"]

def extract_iocs_regex(text):
    iocs = []
    if not text: return iocs
    text = html_module.unescape(text)
    text = re.sub('<[^<]+?>', ' ', text)

    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-8]?)\b', text)
    for ip in ips:
        if not is_private_ip(ip): 
            iocs.append({"type": "IP", "val": ip})
    
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    for h in hashes: iocs.append({"type": "HASH", "val": h})
    
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    for c in cves: iocs.append({"type": "CVE", "val": c.upper()})
    
    return iocs

# --- MOTORES DE API ---
def get_vt_hash_report(hash_val):
    url = f"https://www.virustotal.com/api/v3/files/{hash_val}"
    headers = {"x-apikey": st.session_state.api_keys['virustotal']}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200: return r.json()
    except: pass
    return None

def get_vt_url_report(url_target):
    url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": st.session_state.api_keys['virustotal']}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200: return r.json()
    except: pass
    return None

# --- FEEDS DE INTELIGENCIA (VULDB INCLUIDO SIN NECESIDAD DE KEY) ---
@st.cache_data(ttl=3600)
def fetch_intelligence_feed():
    sources = [
        {"name": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "VulDB", "url": "https://vuldb.com/?rss"}, # Fuente activa (RSS Gratuito)
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"}
    ]
    news_list = []
    for source in sources:
        try:
            feed = feedparser.parse(source["url"])
            for entry in feed.entries[:15]:
                content = entry.get('summary', '') + " " + entry.title
                iocs = extract_iocs_regex(content)
                threat_type = classify_threat(content)
                tags = [threat_type]
                score = calculate_threat_score(source["name"], tags, len(iocs) > 0)
                date_str = entry.get('published', datetime.now().strftime("%Y-%m-%d"))
                try:
                    dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
                    date_formatted = dt.strftime("%d/%m/%Y")
                except: date_formatted = date_str[:10]

                news_list.append({
                    "id": f"{source['name']}-{len(news_list)}", "sev": "critical" if score >= 8.0 else "high",
                    "score": str(score), "type": threat_type, "name": entry.title,
                    "desc": entry.get('summary', '').split('<')[0][:400], "source": entry.link,
                    "sourceName": source["name"], "date": date_formatted,
                    "mitre": map_mitre_keywords(content), "iocs": iocs, "tags": tags,
                    "country_code": random.choice(COMPANY_CONTEXT['countries'])
                })
        except: continue
    news_list.sort(key=lambda x: float(x['score']), reverse=True)
    return news_list

# --- PLANTILLA HTML DASHBOARD ---
def get_dashboard_html(data):
    json_data = json.dumps(data)
    return f"""
<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
    :root {{ --bg: #111419; --border: #252d3e; --text: #e2e8f0; --accent: #00d4a0; --red: #ff4757; --orange: #ffa502; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 10px; font-size: 12px; }}
    .threat-item {{ border: 1px solid var(--border); margin-bottom: 8px; border-radius: 4px; cursor: pointer; overflow: hidden; }}
    .threat-header {{ padding: 10px; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02); }}
    .t-title {{ font-weight: bold; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-right: 10px; }}
    .threat-detail {{ display: none; padding: 15px; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2); line-height: 1.5; }}
    .threat-detail.open {{ display: block; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; margin-right: 5px; text-decoration: none; }}
    .badge-mitre {{ background: rgba(0,212,160,0.15); color: var(--accent); border: 1px solid var(--accent); }}
    .badge-cve {{ background: rgba(255,71,87,0.15); color: var(--red); border: 1px solid var(--red); }}
    .badge-ioc {{ background: rgba(255,165,2,0.15); color: var(--orange); border: 1px solid var(--orange); }}
    .section-title {{ font-size: 11px; color: #8892a4; text-transform: uppercase; margin-top: 10px; margin-bottom: 5px; font-weight: bold; }}
    .source-link {{ display: block; text-align: right; color: var(--accent); font-size: 11px; margin-top: 10px; text-decoration: none; font-weight: bold;}}
</style>
</head>
<body><div id="root"></div>
<script>
    const DATA = {json_data}; let openId = null;
    function escapeHtml(t) {{ return t ? t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : ""; }}
    function render() {{
        const root = document.getElementById('root');
        root.innerHTML = DATA.threats.map(t => `
            <div class="threat-item">
                <div class="threat-header" onclick="toggle('${{t.id}}')">
                    <div class="t-title">${{escapeHtml(t.name)}}</div>
                    <div style="font-family:monospace; font-weight:bold; color:${{t.sev === 'critical' ? 'var(--red)' : 'var(--accent)'}}">${{t.score}}</div>
                </div>
                <div class="threat-detail ${{openId === t.id ? 'open' : ''}}" id="det-${{t.id}}">
                    <div style="color:#aaa; font-size:11px; margin-bottom:8px;">📅 ${{t.date}} | 🗞️ ${{t.sourceName}}</div>
                    <div style="margin-bottom:10px;">${{escapeHtml(t.desc)}}</div>
                    ${{t.mitre.length > 0 ? `<div class="section-title">🎯 Técnicas MITRE ATT&CK</div><div style="margin-bottom:8px;">${{t.mitre.map(m => `<a href="https://attack.mitre.org/techniques/${{m}}/" target="_blank" class="badge badge-mitre">${{m}}</a>`).join('')}}</div>` : ''}}
                    ${{t.iocs.length > 0 ? `<div class="section-title">🚨 Indicadores (IOCs)</div><div style="margin-bottom:8px;">${{t.iocs.map(i => {{ if(i.type === 'CVE') return `<a href="https://nvd.nist.gov/vuln/detail/${{i.val}}" target="_blank" class="badge badge-cve">${{i.val}}</a>`; return `<span class="badge badge-ioc">${{i.type}}: ${{i.val}}</span>`; }}).join(' ')}}</div>` : ''}}
                    <a href="${{t.source}}" target="_blank" class="source-link">Ver Fuente Original ↗</a>
                </div>
            </div>
        `).join('');
    }}
    function toggle(id) {{ openId = (openId === id) ? null : id; render(); }}
    render();
</script>
</body>
</html>
"""

# --- INTERFAZ PRINCIPAL ---
tabs = st.tabs(["🏠 Dashboard", "🔎 Analizar IP", "#️⃣ Hash", "🌐 URL", "📂 MasivoIps", "📚 Playbooks", "🚨 Watcher", "⚙️ Config"])

# --- TAB 1: DASHBOARD (CON DATOS DINÁMICOS) ---
with tabs[0]:
    # 1. Obtenemos los datos primero para calcular métricas reales
    live_threats = fetch_intelligence_feed()
    
    # Cálculo de métricas reales
    total_events = len(live_threats)
    critical_count = sum(1 for t in live_threats if t['sev'] == 'critical')
    active_sources = 4 # CISA, The Hacker News, VulDB, BleepingComputer

    # 2. Mostramos métricas
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("🛡️ Eventos (Feed)", f"{total_events}")
    with c2: st.metric("🔥 Críticas", f"{critical_count}")
    with c3: st.metric("📡 Fuentes", f"{active_sources}")
    with c4:
        if st.button("🔄 Sync", key="btn_sync_dash"):
            st.cache_data.clear()
            st.rerun()

    # 3. Layout del Dashboard
    
    col_feed, col_right = st.columns([2.5, 1])
    
    with col_feed:
        st.subheader("🌍 Feed de Amenazas")
        components.html(get_dashboard_html({"threats": live_threats}), height=800, scrolling=True)

    # CORRECCIÓN: Este bloque debe empezar aquí, sin sangría extra
    with col_right:
        st.subheader("🛡️ OWASP Top 10 (Dinámico)")
        st.caption("Mide la relevancia de riesgos hoy basada en el feed de noticias.")
        
        # 1. Calcular relevancia basada en el feed actual
        owasp_counts = calculate_owasp_relevance(live_threats, OWASP_DATA)
        
        # 2. Mostrar tarjetas interactivas
        for item in OWASP_DATA:
            count = owasp_counts.get(item['id'], 0)
            
            # Lógica de color y badge
            if count > 0:
                status_color = "#ff4757" # Rojo si hay amenazas activas
                badge = f"🔥 {count} Alerta(s)"
            else:
                status_color = "#00d4a0" if st.session_state.dark_mode else "#0d6efd"
                badge = "✅ Estable"
            
            # Expander con título enriquecido
            with st.expander(f"**{item['id']} - {item['name']}** | {badge}"):
                
                # Contenido dinámico
                if count > 0:
                    st.warning(f"⚠️ **Alto Riesgo:** Se detectaron {count} noticias relacionadas con esta categoría hoy.")
                
                st.markdown(f"**Descripción:** {item['desc']}")
                st.markdown(f"**CWE Principal:** `{item['cwe']}`")
                
                st.divider()
                st.markdown(f"🛡️ **Remediación:** {item['mitigation']}")
                
                # Funcionalidad: Checklist de auditoría
                st.divider()
                checked = st.checkbox(f"✅ Control de seguridad verificado ({item['id']})", 
                                      value=st.session_state.owasp_checks.get(item['id'], False),
                                      key=f"check_{item['id']}")
                st.session_state.owasp_checks[item['id']] = checked
                
                if checked:
                    st.success("Cumplimiento verificado para hoy.")
                    
                # Link a OWASP oficial
                st.markdown(f"[📖 Leer más en OWASP.org](https://owasp.org/Top10/{item['id']}-{item['name'].replace(' ', '-')}/)")

    # 4. Tabla de IOCs
    st.divider()
    st.subheader("📦 IoCs Extraídos")
    all_iocs = []
    for t in live_threats:
        if t['iocs']: 
            for i in t['iocs']:
                if i and i.get('type') and i.get('val'):
                    all_iocs.append({"Tipo": i['type'], "Valor": i['val'], "Fuente": t['sourceName']})
    
    if all_iocs:
        df_iocs = pd.DataFrame(all_iocs).drop_duplicates()
        st.dataframe(df_iocs, use_container_width=True, hide_index=True)
        csv_iocs = df_iocs.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Descargar IOCs", csv_iocs, "iocs.csv", "text/csv", key="dl_iocs_dash")
    else:
        st.info("No se detectaron IOCs públicos válidos en los feeds actuales.")

    # 5. Mapa al Final
    st.divider()
    st.subheader("🗺️ Mapa de Amenazas Global")
    m = folium.Map(location=COMPANY_CONTEXT['coords']['CO'], zoom_start=3, tiles="CartoDB dark_matter")
    for threat in live_threats:
        coords = COMPANY_CONTEXT['coords'].get(threat['country_code'], COMPANY_CONTEXT['coords']['DEFAULT'])
        color = "#ff4757" if threat['sev'] == 'critical' else "#ffa502"
        folium.CircleMarker(location=coords, radius=8, color=color, fill=True, popup=f"<b>{threat['name']}</b>").add_to(m)
    st_folium(m, width='100%', height=450)
    
# --- TAB 2: ANALIZAR IP ---
with tabs[1]:
    st.title("🔎 Análisis de Dirección IP")
    
    if st.session_state.get('clear_ip'):
        st.session_state.analysis_results = None
        st.session_state.input_ip_val = ""
        st.session_state.clear_ip = False

    user_input = st.text_input("Ingrese IP:", placeholder="Ej: 192.168.1.1", key="input_ip_val")
    
    c1, c2, c3 = st.columns([1, 1, 3])
    analyze_btn = c1.button("Analizar", type="primary", key="btn_analyze_ip")
    clear_btn = c2.button("🧹 Nueva Consulta", key="btn_clear_ip")

    if clear_btn:
        st.session_state.clear_ip = True
        st.rerun()

    if analyze_btn and user_input:
        if not st.session_state.api_keys['abuseipdb']:
            st.error("Configure API Key de AbuseIPDB en Config.")
        else:
            with st.spinner("Consultando fuentes..."):
                results = {"type": "IP", "value": user_input, "abuse": None, "vt": None}
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                        headers={"Key": st.session_state.api_keys['abuseipdb'], "Accept": "application/json"}, 
                        params={"ipAddress": user_input, "maxAgeInDays": 90})
                    if r.status_code == 200:
                        results['abuse'] = r.json()['data']
                except: pass
                
                if st.session_state.api_keys['virustotal']:
                    try:
                        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}", 
                            headers={"x-apikey": st.session_state.api_keys['virustotal']})
                        if r.status_code == 200:
                            results['vt'] = r.json()['data']['attributes']
                    except: pass
                
                st.session_state.analysis_results = results

    if st.session_state.analysis_results and not clear_btn:
        res = st.session_state.analysis_results
        st.markdown("---")
        
        if res.get('abuse'):
            abuse_data = res['abuse']
            score = abuse_data.get('abuseConfidenceScore', 0)
            color_score = "#ff4757" if score > 80 else "#ffa502" if score > 30 else "#2ed573"
            
            vt_data = res.get('vt')
            vt_stats = vt_data.get('last_analysis_stats', {}) if vt_data else {}
            malicious = vt_stats.get('malicious', 0)
            total = sum(vt_stats.values()) if vt_stats else 0
            vt_color = "#ff4757" if malicious > 0 else "#2ed573"
            
            last_analysis = "N/A"
            if vt_data and 'last_analysis_date' in vt_data:
                last_analysis = datetime.fromtimestamp(vt_data['last_analysis_date']).strftime('%Y-%m-%d %H:%M')

            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"""
                <div class="evidence-card">
                    <div class="evidence-header">🚫 AbuseIPDB Report</div>
                    <div style="text-align:center; margin-bottom:20px;">
                        <div style="font-size:40px; font-weight:bold; color:{color_score};">{score}%</div>
                        <div style="color:#888;">Abuse Confidence Score</div>
                    </div>
                    <div class="data-row"><div class="data-label">Número de Reportes</div><div class="data-value">{abuse_data.get('totalReports', 0)}</div></div>
                    <div class="data-row"><div class="data-label">Número de Fuentes</div><div class="data-value">{abuse_data.get('numDistinctUsers', 0)}</div></div>
                    <div class="data-row"><div class="data-label">ISP</div><div class="data-value">{abuse_data.get('isp', 'N/A')}</div></div>
                    <div class="data-row"><div class="data-label">Hostname</div><div class="data-value">{abuse_data.get('domain', 'N/A')}</div></div>
                    <div class="data-row"><div class="data-label">Country</div><div class="data-value">{abuse_data.get('countryCode', 'N/A')}</div></div>
                    <div class="data-row"><div class="data-label">City</div><div class="data-value">{abuse_data.get('city', 'N/A')}</div></div>
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                <div class="evidence-card">
                    <div class="evidence-header">🦠 VirusTotal Report</div>
                    <div style="text-align:center; margin-bottom:20px;">
                        <div style="font-size:40px; font-weight:bold; color:{vt_color};">{malicious}/{total}</div>
                        <div style="color:#888;">Detection Ratio</div>
                    </div>
                    <div class="data-row"><div class="data-label">Country</div><div class="data-value">{vt_data.get('country', 'N/A') if vt_data else 'N/A'}</div></div>
                    <div class="data-row"><div class="data-label">Last Analysis</div><div class="data-value">{last_analysis}</div></div>
                    <div class="data-row"><div class="data-label">ISP / AS Owner</div><div class="data-value">{vt_data.get('as_owner', 'N/A') if vt_data else 'N/A'}</div></div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("---")
            st.subheader("🛡️ Generador de Bloqueo Fortinet")
            
            c_b1, c_b2 = st.columns([1, 2])
            with c_b1:
                alarm_id = st.text_input("Número de Alarma", key="input_alarm_id")
            with c_b2:
                current_month_name = MESES_ES[datetime.now().month]
                default_group = f"Ip_Reportadas_SOCCVJ_{current_month_name}_{datetime.now().year}"
                group_name = st.text_input("Grupo de Direcciones", value=default_group, key="input_group_name")

            if st.button("⚙️ Generar Script CLI", key="btn_gen_forti"):
                if alarm_id and user_input:
                    script_content = f"""config firewall address
edit "IP_Sospechosa_{user_input}"
set subnet {user_input} 255.255.255.255
set comment "Alarma {alarm_id}"
next
end
config firewall addrgrp
edit "{group_name}"
append member "IP_Sospechosa_{user_input}"
next
end"""
                    st.success("✅ Script Generado.")
                    st.code(script_content, language='bash')
                else:
                    st.error("Ingrese número de alarma.")

# --- TAB 3: HASH ---
with tabs[2]:
    st.title("#️⃣ Análisis de Hash")
    
    if st.session_state.get('clear_hash'):
        st.session_state.analysis_results = None
        st.session_state.input_hash_val = ""
        st.session_state.clear_hash = False

    hash_input = st.text_input("Ingrese Hash", placeholder="SHA256, MD5...", key="input_hash_val")
    c1, c2, c3 = st.columns([1, 1, 3])
    
    if c1.button("Analizar Hash", type="primary", key="btn_analyze_hash"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Buscando..."):
                res = get_vt_hash_report(hash_input)
                if res:
                    st.session_state.analysis_results = res
                else:
                    st.error("No encontrado.")
        else:
            st.error("Configure VT API Key.")
    
    if c2.button("🧹 Nueva Consulta", key="btn_clear_hash"):
        st.session_state.clear_hash = True
        st.rerun()

    if st.session_state.analysis_results and isinstance(st.session_state.analysis_results, dict) and 'data' in st.session_state.analysis_results:
        res = st.session_state.analysis_results
        attrs = res['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        mal = stats.get('malicious', 0)
        st.markdown(f"""
        <div class="evidence-card">
            <div class="evidence-header">🦠 Reporte de Malware</div>
            <div style="text-align:center; padding:20px;">
                <div style="font-size:40px; font-weight:bold; color:{"#ff4757" if mal > 0 else "#2ed573"};">{mal}/{sum(stats.values())}</div>
                <div>Detecciones</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# --- TAB 4: URL ---
with tabs[3]:
    st.title("🌐 Análisis de URL")
    
    if st.session_state.get('clear_url'):
        st.session_state.analysis_results = None
        st.session_state.input_url_val = ""
        st.session_state.clear_url = False

    url_input = st.text_input("Ingrese URL", placeholder="https://...", key="input_url_val")
    c1, c2, c3 = st.columns([1, 1, 3])
    
    if c1.button("Analizar URL", type="primary", key="btn_analyze_url"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Analizando..."):
                res = get_vt_url_report(url_input)
                if res:
                    st.session_state.analysis_results = res
                else:
                    st.error("Error al analizar.")
        else:
            st.error("Configure VT API Key.")
            
    if c2.button("🧹 Nueva Consulta", key="btn_clear_url"):
        st.session_state.clear_url = True
        st.rerun()

    if st.session_state.analysis_results and isinstance(st.session_state.analysis_results, dict) and 'data' in st.session_state.analysis_results:
        res = st.session_state.analysis_results
        stats = res['data']['attributes'].get('last_analysis_stats', {})
        mal = stats.get('malicious', 0)
        st.markdown(f"""
        <div class="evidence-card">
            <div class="evidence-header">🌍 Reporte URL</div>
            <div style="text-align:center; padding:20px;">
                <div style="font-size:30px; font-weight:bold; color:{"#ff4757" if mal > 0 else "#2ed573"};">{"MALICIOSA" if mal > 0 else "LIMPIA"}</div>
                <div>Detecciones: {mal}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# --- TAB 5: MASIVO IPS (ANTES BULK) ---
with tabs[4]:
    st.title("📂 MasivoIps") # Título cambiado
    
    if st.session_state.get('clear_bulk'):
        if 'bulk_results_df' in st.session_state:
            del st.session_state.bulk_results_df
        st.session_state.clear_bulk = False
        st.rerun()
        
    if st.button("🧹 Limpiar Resultados Masivos", key="btn_clear_bulk"):
        st.session_state.clear_bulk = True
        st.rerun()
        
    st.markdown("⚠️ **Nota:** El sistema detectará automáticamente IPs privadas y las omitirá.")
    uploaded_file = st.file_uploader("Cargar archivo CSV o TXT", type=['csv', 'txt'])
    
    if uploaded_file:
        try:
            try:
                df = pd.read_csv(uploaded_file)
            except:
                df = pd.read_csv(uploaded_file, header=None, names=['ip'])
            
            st.write("Vista previa:", df.head(3))
            
            target_column = None
            possible_cols = [col for col in df.columns if 'ip' in col.lower()]
            if possible_cols:
                target_column = possible_cols[0]
            else:
                target_column = df.columns[0]
            
            st.info(f"Se usará la columna: **{target_column}**")

            if st.button("Iniciar Análisis Masivo", type="primary", key="btn_bulk_scan"):
                if not st.session_state.api_keys['abuseipdb']:
                    st.error("Configure la API Key de AbuseIPDB.")
                else:
                    progress_bar = st.progress(0)
                    status_text = st.empty()
                    results = []
                    ips = df[target_column].dropna().astype(str).unique().tolist()
                    
                    for i, ip in enumerate(ips):
                        ip = ip.strip()
                        if is_private_ip(ip):
                            results.append({"IP": ip, "Score": "PRIVATE", "Reports": 0, "Domain": "N/A", "Country": "N/A", "City": "N/A", "Status": "Omitida (Privada)"})
                            progress_bar.progress((i+1)/len(ips))
                            continue
                            
                        if ip in st.session_state.whitelist:
                            results.append({"IP": ip, "Score": "WHITELIST", "Reports": 0, "Domain": "N/A", "Country": "N/A", "City": "N/A", "Status": "Omitida (Whitelist)"})
                        else:
                            data = {"IP": ip, "Score": "N/A", "Reports": 0, "Domain": "N/A", "Country": "N/A", "City": "N/A", "Status": "Analizada"}
                            try:
                                r = requests.get(
                                    "https://api.abuseipdb.com/api/v2/check", 
                                    headers={"Key": st.session_state.api_keys['abuseipdb'], "Accept": "application/json"}, 
                                    params={"ipAddress": ip, "maxAgeInDays": 90}
                                )
                                if r.status_code == 200:
                                    d = r.json()['data']
                                    sc = d.get('abuseConfidenceScore', 0)
                                    data["Score"] = f"{sc}%"
                                    data["Reports"] = d.get('totalReports', 0)
                                    data["Domain"] = d.get('domain', 'N/A')
                                    data["Country"] = d.get('countryCode', 'N/A')
                                    data["City"] = d.get('city', 'N/A')
                            except: data["Status"] = "Error API"
                            
                            results.append(data)
                            time.sleep(1.1)
                        
                        progress_bar.progress((i+1)/len(ips))
                        status_text.text(f"Procesado {i+1}/{len(ips)}")

                    status_text.text("¡Análisis completado!")
                    res_df = pd.DataFrame(results)
                    st.session_state.bulk_results_df = res_df
                    
        except Exception as e:
            st.error(f"Error procesando archivo: {e}")

    if 'bulk_results_df' in st.session_state:
        res_df = st.session_state.bulk_results_df
        def highlight_malicious(s):
            return ['background-color: #ff4757; color: white' if v and '%' in str(v) and int(str(v).replace('%','')) > 80 else '' for v in s]
        st.dataframe(res_df.style.apply(highlight_malicious, subset=['Score']), use_container_width=True)
        csv = res_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Descargar Reporte CSV", csv, "reporte_masivo.csv", "text/csv", key="dl_bulk")

# --- TAB 6: PLAYBOOKS (MOTOR DE REGLAS: GLOBAL + ESPECÍFICOS) ---
with tabs[5]:
    st.title("📚 Playbooks de Respuesta (Motor Híbrido)")
    st.markdown("Detecta amenazas globales (Ransomware, Phishing) y alarmas específicas de la organización (Scanners, SQLi, Botnets).")
    
    alert_text = st.text_area("Descripción de la Alarma / Incidente", height=150, key="input_playbook", 
                              placeholder="Ej: Se detectó 'AGrab.Scanner' y tráfico hacia un C2 de 'SystemBC'.")
    
    # --- BASE DE CONOCIMIENTO UNIFICADA ---
    PLAYBOOK_RULES = {
        
        # === BLOQUE 1: AMENAZAS GLOBALES CRÍTICAS ===
        "Ransomware / Cifrado de Datos": {
            "keywords": ["ransomware", "encriptado", "archivo bloqueado", ".lock", "nota de rescate", "wannacry", "crypto", "extorsion", "lockbit", "blackcat", "cl0p"],
            "severity": "🔴 CRÍTICO",
            "impact": "Disponibilidad e Integridad de Datos Críticos.",
            "steps": [
                {"fase": "1. Aislamiento Inmediato", "desc": "Desconectar el host de la red (física o VLAN de cuarentena).", "tool": "Switch Port / FortiOS NAC"},
                {"fase": "2. Preservación Forense", "desc": "Capturar imagen de memoria RAM antes de apagar. No modificar el sistema.", "tool": "Magnet RAM Capture"},
                {"fase": "3. Identificación", "desc": "Identificar familia de Ransomware y el 'Entry Point' inicial.", "tool": "ID Ransomware"},
                {"fase": "4. Contención de Red", "desc": "Bloquear IPs de C2 y dominios conocidos en Firewall y DNS.", "tool": "Firewall / DNS Sinkhole"},
                {"fase": "5. Recuperación", "desc": "Restaurar desde backups inmutables verificados.", "tool": "Veeam / Commvault"}
            ]
        },
        "Phishing / Compromiso de Credenciales": {
            "keywords": ["phishing", "correo sospechoso", "credential harvesting", "url maliciosa", "password", "spoofing", "business email compromise", "bec"],
            "severity": "🟠 ALTO",
            "impact": "Pérdida de credenciales y acceso a cuentas corporativas.",
            "steps": [
                {"fase": "1. Análisis del Artefacto", "desc": "Analizar headers, enlaces y adjuntos en sandbox.", "tool": "VirusTotal / AnyRun"},
                {"fase": "2. Bloqueo de IoCs", "desc": "Bloquear URLs y dominios en Gateway de Email y Proxy.", "tool": "M365 Defender / Mimecast"},
                {"fase": "3. Búsqueda de Impacto", "desc": "Buscar correos similares en la organización.", "tool": "eDiscovery"},
                {"fase": "4. Reset de Credenciales", "desc": "Forzar cambio de contraseña MFA y revisar reglas de reenvío.", "tool": "Azure AD"},
                {"fase": "5. Concientización", "desc": "Notificar al usuario sobre la técnica utilizada.", "tool": "Email"}
            ]
        },
        "Explotación de Vulnerabilidad Crítica (Zero-Day)": {
            "keywords": ["vulnerability", "exploit", "cve-", "remote code execution", "rce", "log4j", "proxyshell", "zerologon", "zero-day"],
            "severity": "🔴 CRÍTICO",
            "impact": "Acceso no autorizado y ejecución de código remoto.",
            "steps": [
                {"fase": "1. Verificación de Patch", "desc": "Confirmar si el sistema tiene el parche de seguridad.", "tool": "Nessus / Qualys"},
                {"fase": "2. Mitigación Temporal", "desc": "Aplicar reglas WAF o deshabilitar componente vulnerable.", "tool": "WAF"},
                {"fase": "3. Análisis de Logs", "desc": "Buscar patrones de exploit en logs de servidor.", "tool": "SIEM / Splunk"},
                {"fase": "4. Webshell Hunt", "desc": "Buscar archivos webshells dejados por el atacante.", "tool": "CrowdStrike"},
                {"fase": "5. Parcheo", "desc": "Aplicar actualización de seguridad oficial.", "tool": "WSUS"}
            ]
        },
        "Fuerza Bruta / Ataque de Contraseñas": {
            "keywords": ["brute force", "fuerza bruta", "login fail", "intentos fallidos", "password spraying", "account lockout", "rdp brute force"],
            "severity": "🟠 ALTO",
            "impact": "Compromiso de cuentas.",
            "steps": [
                {"fase": "1. Validación de Origen", "desc": "Geolocalizar IP de origen.", "tool": "AbuseIPDB"},
                {"fase": "2. Bloqueo", "desc": "Bloquear IP en Firewall perimetral.", "tool": "Firewall"},
                {"fase": "3. Verificación de Éxito", "desc": "Revisar logs de 'Login Success' posteriores.", "tool": "Event Viewer"},
                {"fase": "4. Hardening", "desc": "Activar MFA si no está presente.", "tool": "Azure AD / Duo"}
            ]
        },
        "Ingeniería Social / Fraude al CEO": {
            "keywords": ["fraude", "transferencia", "cambio de cuenta", "urgente", "ceo fraud", "whaling"],
            "severity": "🔴 CRÍTICO (Financiero)",
            "impact": "Pérdidas económicas directas.",
            "steps": [
                {"fase": "1. Detención de Transacción", "desc": "CONTACTAR INMEDIATAMENTE a Tesorería para detener la transferencia.", "tool": "Teléfono / Banco"},
                {"fase": "2. Verificación de Identidad", "desc": "Verificar con el remitente por canal alternativo.", "tool": "Teléfono fijo"},
                {"fase": "3. Análisis", "desc": "Revisar si el dominio es suplantado.", "tool": "Inspección Manual"},
                {"fase": "4. Denuncia", "desc": "Reportar a policía cibernética.", "tool": "Policía Nacional"}
            ]
        },

        # === BLOQUE 2: ALARMAS ESPECÍFICAS DE LA ORGANIZACIÓN ===
        "Reconocimiento / Escaneo de Puertos (Específico)": {
            "keywords": ["port scan", "nmap", "masscan", "censys.io.scanner", "agrab.scanner", "scanner"],
            "severity": "🟢 BAJO / INFORMATIVO",
            "impact": "Reconocimiento pasivo de superficie de ataque.",
            "steps": [
                {"fase": "1. Verificación de Origen", "desc": "Verificar reputación de IP. ¿Es proveedor legítimo?", "tool": "AbuseIPDB"},
                {"fase": "2. Filtrado", "desc": "Si es maliciosa, bloquear en Firewall.", "tool": "Firewall (FortiGate)"},
                {"fase": "3. Contexto", "desc": "¿Fue seguido de intento de explotación?", "tool": "SIEM"},
                {"fase": "4. Cierre", "desc": "Cerrar ticket como 'Reconocimiento' si es aislado.", "tool": "Ticketing"}
            ]
        },
        "Ataque a Aplicaciones Web (SQLi / RFI / Path Traversal)": {
            "keywords": ["sql injection", "rfi/srf", "cross site request forgery", "apache http server cgi path traversal", "comtred vr3033", "web attack"],
            "severity": "🔴 CRÍTICO",
            "impact": "RCE o robo de datos.",
            "steps": [
                {"fase": "1. Bloqueo", "desc": "Bloquear IP en WAF.", "tool": "WAF / FortiWeb"},
                {"fase": "2. Éxito del Ataque", "desc": "¿Código HTTP 200 o 403?", "tool": "Apache Logs"},
                {"fase": "3. Webshell Check", "desc": "Buscar archivos nuevos en servidor.", "tool": "FIM"},
                {"fase": "4. Parcheo", "desc": "Actualizar servidor afectado.", "tool": "Update Manager"}
            ]
        },
        "Detección de Botnet / Malware Específico": {
            "keywords": ["miari botnet", "systembc.botner", "androxghost.malware", "botnet", "malware", "posible infeccion"],
            "severity": "🔴 CRÍTICO",
            "impact": "Equipo comprometido y C2 activo.",
            "steps": [
                {"fase": "1. Aislamiento", "desc": "Desconectar equipo de la red.", "tool": "EDR / NAC"},
                {"fase": "2. Bloqueo C2", "desc": "Bloquear IP de Command & Control.", "tool": "Firewall"},
                {"fase": "3. Proceso", "desc": "Identificar proceso malicioso.", "tool": "Process Hacker"},
                {"fase": "4. Limpieza", "desc": "Escaneo completo o reimplementación.", "tool": "CrowdStrike"}
            ]
        },
        "Exfiltración de Datos / DLP": {
            "keywords": ["data exfiltraton", "data exfiltration", "data lost prevention", "dlp", "folder access violation", "posible data lost"],
            "severity": "🟠 ALTO",
            "impact": "Pérdida de información sensible.",
            "steps": [
                {"fase": "1. Validación", "desc": "¿Es tráfico legítimo del usuario?", "tool": "DLP Console"},
                {"fase": "2. Bloqueo", "desc": "Bloquear destino si es sospechoso.", "tool": "Proxy"},
                {"fase": "3. Revisión", "desc": "Revisar logs de acceso a carpetas.", "tool": "File Server Logs"},
                {"fase": "4. Entrevista", "desc": "Contactar al usuario.", "tool": "Teams"}
            ]
        },
        "Anomalías de Protocolo / VPN": {
            "keywords": ["http rfc violation", "intento fallido de negociacion vpn", "vpn fail", "rfc violation"],
            "severity": "🟡 MEDIO",
            "impact": "Posible escaneo de servicios o errores de config.",
            "steps": [
                {"fase": "1. Diagnóstico VPN", "desc": "¿Usuario legítimo o fuerza bruta?", "tool": "VPN Logs"},
                {"fase": "2. Tráfico", "desc": "Capturar paquetes para analizar anomalía.", "tool": "Wireshark"},
                {"fase": "3. Bloqueo", "desc": "Bloquear IP si es externa y persiste.", "tool": "Firewall"}
            ]
        }
    }
    
    # --- MOTOR DE EJECUCIÓN MULTI-MATCH ---
    if st.button("🚀 Ejecutar Triaje Automático", type="primary", key="btn_playbook"):
        if alert_text:
            detected_playbooks = [] 
            
            # Buscar TODAS las coincidencias
            for name, rule in PLAYBOOK_RULES.items():
                for kw in rule["keywords"]:
                    if kw in alert_text.lower():
                        detected_playbooks.append((name, rule))
                        break # Pasar al siguiente playbook una vez encontrado el keyword
            
            st.markdown("---")
            
            if detected_playbooks:
                st.success(f"✅ Se detectaron **{len(detected_playbooks)}** procedimientos aplicables.")
                
                for name, data in detected_playbooks:
                    st.markdown(f"### 🔍 Playbook: **{name}**")
                    st.markdown(f"**Severidad:** `{data['severity']}` | **Impacto:** {data['impact']}")
                    
                    st.markdown("#### 📋 Procedimiento Operativo")
                    
                    for step in data['steps']:
                        st.markdown(f"""
                        <div class="step-box">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                                <div style="font-weight:bold; color:#00d4a0; font-size:16px;">{step['fase']}</div>
                                <div style="font-size:11px; background:rgba(0,212,160,0.2); padding:4px 10px; border-radius:4px; color:white;">🛠️ {step['tool']}</div>
                            </div>
                            <div style="font-size:14px; color:#e2e8f0;">{step['desc']}</div>
                        </div>
                        """, unsafe_allow_html=True)
                    st.markdown("") 
            else:
                st.warning("⚠️ No se detectó un patrón específico.")
                st.info("Recomendación: Realizar triaje general.")
        else:
            st.error("Por favor ingrese una descripción.")
# --- TAB 7: WATCHER ---
with tabs[6]:
    st.title("🚨 Watcher")
    assets = st.text_area("Activos (separados por coma)", placeholder="FortiOS, Windows", key="input_watcher")
    if st.button("Vigilar", key="btn_watcher"):
        st.session_state.watcher_assets = [a.strip().lower() for a in assets.split(",")]
    
    if st.session_state.watcher_assets:
        threats = fetch_intelligence_feed()
        found = False
        for t in threats:
            content = (t['name'] + t['desc']).lower()
            for a in st.session_state.watcher_assets:
                if a in content:
                    found = True
                    st.error(f"⚠️ Alerta para **{a}**: {t['name']}")
        if not found:
            st.success("Sin alertas recientes.")

# --- TAB 8: CONFIG ---
with tabs[7]:
    st.title("⚙️ Configuración")
    
    st.subheader("🎨 Tema")
    mode = st.toggle("Modo Oscuro", value=st.session_state.dark_mode)
    if mode != st.session_state.dark_mode:
        st.session_state.dark_mode = mode
        st.rerun()
        
    st.divider()
    st.subheader("🔑 API Keys")
    c1, c2 = st.columns(2)
    with c1: st.text_input("AbuseIPDB", type="password", key="k_ab", on_change=lambda: st.session_state.api_keys.update({'abuseipdb': st.session_state.k_ab}))
    with c2: st.text_input("VirusTotal", type="password", key="k_vt", on_change=lambda: st.session_state.api_keys.update({'virustotal': st.session_state.k_vt}))

    if st.button("Cerrar Sesión", key="btn_logout"):
        st.session_state.logged_in = False
        st.rerun()
