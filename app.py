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
OWASP_DATA = [
    {"id": "A01", "name": "Broken Access Control", "desc": "Restricciones de acceso no implementadas correctamente.", "keywords": ["access control", "idor", "broken access", "privilege escalation", "bypass"], "mitigation": "Implementar RBAC.", "cwe": "CWE-284"},
    {"id": "A02", "name": "Cryptographic Failures", "desc": "Fallas en la protección de datos sensibles.", "keywords": ["crypto", "encryption", "ssl", "tls", "sensitive data", "password dump"], "mitigation": "Cifrar datos.", "cwe": "CWE-311"},
    {"id": "A03", "name": "Injection", "desc": "Código inseguro enviado al intérprete.", "keywords": ["sql injection", "xss", "command injection", "rce", "nosql", "ldap injection"], "mitigation": "Sentencias preparadas.", "cwe": "CWE-78"},
    {"id": "A04", "name": "Insecure Design", "desc": "Fallas en diseño.", "keywords": ["design flaw", "architecture", "threat modeling", "logic flaw"], "mitigation": "Modelado de amenazas.", "cwe": "CWE-1059"},
    {"id": "A05", "name": "Security Misconfiguration", "desc": "Configuraciones por defecto inseguras.", "keywords": ["misconfiguration", "default password", "open port", "directory listing", "s3 bucket"], "mitigation": "Hardening.", "cwe": "CWE-16"},
    {"id": "A06", "name": "Vulnerable Components", "desc": "Librerías vulnerables.", "keywords": ["vulnerable library", "outdated", "cve-", "dependency", "log4j"], "mitigation": "SBOM.", "cwe": "CWE-1104"},
    {"id": "A07", "name": "Identif. & Auth. Failures", "desc": "Fallas en autenticación.", "keywords": ["authentication", "credential stuffing", "brute force", "session hijacking", "mfa"], "mitigation": "MFA.", "cwe": "CWE-287"},
    {"id": "A08", "name": "Software & Data Integrity", "desc": "Falta de verificación de integridad.", "keywords": ["supply chain", "ci/cd", "integrity", "update", "malicious package"], "mitigation": "Firmas digitales.", "cwe": "CWE-353"},
    {"id": "A09", "name": "Security Logging Failures", "desc": "Falta de logs.", "keywords": ["logging", "audit", "monitoring", "detection gap", "log injection"], "mitigation": "SIEM.", "cwe": "CWE-778"},
    {"id": "A10", "name": "Server-Side Request Forgery", "desc": "El servidor obtiene recursos sin validar URL.", "keywords": ["ssrf", "server side request", "fetch url", "internal network"], "mitigation": "Validar URLs.", "cwe": "CWE-918"}
]

if 'owasp_checks' not in st.session_state: st.session_state.owasp_checks = {item['id']: False for item in OWASP_DATA}

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
if 'input_playbook_val' not in st.session_state: st.session_state.input_playbook_val = ""
if 'input_watcher_val' not in st.session_state: st.session_state.input_watcher_val = ""

MESES_ES = {1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio", 7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"}

# --- CSS DINÁMICO (CORREGIDO PARA TABLAS) ---
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
        /* Base */
        body, .stApp {{ background-color: {bg_color}; color: {text_color}; transition: all 0.3s ease; }}
        p, span, div, label, .stMarkdown {{ color: {text_color} !important; }}
        
        /* Métricas y Tarjetas */
        div[data-testid="stMetric"], .analysis-card, .evidence-card {{ background-color: {bg_secondary}; border: 1px solid {border_color}; border-radius: 8px; padding: 20px; }}
        
        /* TABLAS (SOLUCIÓN DEFINITIVA) */
        div[data-testid="stDataFrame"] {{ background-color: {bg_secondary}; border: 1px solid {border_color}; border-radius: 8px; }}
        /* Cabecera de tabla */
        div[data-testid="stDataFrame"] th {{ background-color: {bg_color} !important; color: {accent_color} !important; }}
        /* Celdas de tabla */
        div[data-testid="stDataFrame"] td {{ background-color: transparent !important; color: {text_color} !important; }}
        /* Contenedor interno */
        .stDataFrame {{ border: none !important; }}
        
        /* Inputs */
        .stTextInput > div > div > input, .stTextArea textarea {{ background-color: {bg_secondary} !important; color: {text_color} !important; border: 1px solid {border_color}; }}
        
        /* Botones */
        .stButton > button, .stDownloadButton > button {{ background-color: {accent_color}; color: white; border-radius: 5px; border: none; }}
        
        /* Otros */
        .step-box {{ background-color: {bg_secondary}; border-left: 4px solid {accent_color}; padding: 10px; margin-bottom: 10px; }}
        .main-title {{ text-align: center; padding: 10px 0 20px 0; }}
        .main-title h1 {{ color: {accent_color}; margin: 0; font-size: 2.5rem; letter-spacing: 2px; }}
        .main-title h4 {{ color: {text_secondary}; margin: 5px 0 0 0; font-weight: normal; }}
    </style>
    """, unsafe_allow_html=True)

inject_css()

# --- TÍTULO GLOBAL ---
st.markdown("""<div class="main-title"><h1>CyberScopeCG</h1><h4>Threat Intelligence & Response Platform</h4></div>""", unsafe_allow_html=True)

# --- FUNCIONES AUXILIARES ---
def calculate_owasp_relevance(threats, owasp_data):
    relevance = {item['id']: 0 for item in owasp_data}
    for threat in threats:
        content = (threat.get('name', '') + " " + threat.get('desc', '')).lower()
        for item in owasp_data:
            for keyword in item['keywords']:
                if keyword in content: relevance[item['id']] += 1; break
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
    text_l = text.lower(); mapped = []
    if "ransomware" in text_l: mapped.append("T1486")
    if "phishing" in text_l: mapped.append("T1566")
    if "exploit" in text_l: mapped.append("T1190")
    return list(set(mapped)) if mapped else ["T1204"]

# --- FUNCIONES AUXILIARES (ACTUALIZADO) ---
def extract_observables(text):
    """
    Extrae y separa IOCs (IPs, Hashes) de CVEs (Vulnerabilidades).
    Retorna: dict con 'iocs' y 'cves'
    """
    iocs = []
    cves = []
    if not text: return {"iocs": iocs, "cves": cves}
    
    text = html_module.unescape(text); text = re.sub('<[^<]+?>', ' ', text)

    # 1. Extraer CVEs (Vulnerabilidades)
    found_cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
    for c in found_cves:
        cves.append({"type": "CVE", "val": c.upper()})

    # 2. Extraer IOCs (Indicadores de Compromiso)
    # IPs
    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-8]?)\b', text)
    for ip in ips:
        if not is_private_ip(ip): 
            iocs.append({"type": "IP", "val": ip})
    # Hashes
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    for h in hashes: iocs.append({"type": "HASH", "val": h})
    
    return {"iocs": iocs, "cves": cves}

# --- MOTORES DE API ---
def get_vt_hash_report(hash_val):
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{hash_val}", headers={"x-apikey": st.session_state.api_keys['virustotal']}, timeout=10)
        if r.status_code == 200: return r.json()
    except: pass
    return None

def get_vt_url_report(url_target):
    try:
        url_id = base64.urlsafe_b64encode(url_target.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": st.session_state.api_keys['virustotal']}, timeout=10)
        if r.status_code == 200: return r.json()
    except: pass
    return None

# --- FEEDS DE INTELIGENCIA ---
@st.cache_data(ttl=3600)
def fetch_intelligence_feed():
    sources = [
        {"name": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "VulDB", "url": "https://vuldb.com/?rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"}
    ]
    news_list = []
    for source in sources:
        try:
            feed = feedparser.parse(source["url"])
            for entry in feed.entries[:15]:
                content = entry.get('summary', '') + " " + entry.title
                
                # Extraemos todo usando la función correcta: extract_observables
                extracted_data = extract_observables(content)
                
                # Obtenemos las listas ya separadas que retorna la función
                real_iocs = extracted_data.get('iocs', [])
                found_cves = extracted_data.get('cves', [])
                
                threat_type = classify_threat(content)
                tags = [threat_type]
                score = calculate_threat_score(source["name"], tags, len(real_iocs) > 0)
                date_str = entry.get('published', datetime.now().strftime("%Y-%m-%d"))
                try: date_formatted = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z").strftime("%d/%m/%Y")
                except: date_formatted = date_str[:10]

                news_list.append({
                    "id": f"{source['name']}-{len(news_list)}", "sev": "critical" if score >= 8.0 else "high",
                    "score": str(score), "type": threat_type, "name": entry.title,
                    "desc": entry.get('summary', '').split('<')[0][:400], "source": entry.link,
                    "sourceName": source["name"], "date": date_formatted,
                    "mitre": map_mitre_keywords(content), 
                    "iocs": real_iocs,      # Solo IPs y Hashes
                    "cves": found_cves,     # Solo CVEs
                    "tags": tags,
                    "country_code": random.choice(COMPANY_CONTEXT['countries'])
                })
        except: continue
    news_list.sort(key=lambda x: float(x['score']), reverse=True)
    return news_list

# --- FUNCIÓN RANSOMWARE FEED (VÍA RSS) ---
@st.cache_data(ttl=1800)
def fetch_ransomware_feed():
    # Usamos el feed RSS oficial que es más accesible
    url = "https://ransomware.live/rss"
    
    try:
        feed = feedparser.parse(url)
        formatted_data = []
        
        # Verificamos si el feed se parseó correctamente
        if feed.bozo and not feed.entries:
            # Si hay error de red o parseo, retornamos vacío
            return []

        for entry in feed.entries:
            # 1. Extraer Título (Nombre de la víctima)
            victim_name = entry.get('title', 'Desconocido')
            
            # 2. Extraer Grupo y País del resumen (Summary a menudo contiene HTML con datos)
            # En RSS suele venir todo mezclado, haremos una limpieza básica
            summary = entry.get('summary', '')
            group_name = "Desconocido"
            country_code = "Global" # Por defecto si no encontramos país
            
            # Intento simple de extracción de texto (limpiar HTML)
            clean_summary = re.sub('<[^<]+?>', '', summary).lower()
            
            # Intentar detectar grupo (a veces está en el título o resumen)
            # Nota: Esto es heurístico, la API estructurada es mejor pero RSS es más seguro
            if "lockbit" in clean_summary or "lockbit" in victim_name.lower(): group_name = "LockBit"
            elif "blackcat" in clean_summary or "alphv" in clean_summary: group_name = "BlackCat/ALPHV"
            elif "cl0p" in clean_summary or "clop" in clean_summary: group_name = "Cl0p"
            elif "play" in clean_summary: group_name = "Play"
            elif "ransomhub" in clean_summary: group_name = "RansomHub"
            
            # 3. Fecha
            date_str = entry.get('published', datetime.now().strftime("%Y-%m-%d"))
            try:
                # Normalizar fecha
                date_formatted = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z").strftime("%d/%m/%Y")
            except:
                date_formatted = date_str[:10]

            formatted_data.append({
                "victim": victim_name,
                "group": group_name,
                "country": country_code, # En RSS es difícil obtener el código ISO sin parsear complejo
                "published": date_formatted,
                "sev": "critical",
                "source": entry.get('link', ''),
                "desc": clean_summary[:300] + "..."
            })
            
        return formatted_data
        
    except Exception as e:
        print(f"Error en RSS Feed: {e}")
        return []

# --- PLANTILLA HTML DASHBOARD (CORREGIDA) ---
def get_dashboard_html(data):
    json_data = json.dumps(data)
    return f"""
<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<style>
    :root {{ --bg: #111419; --border: #252d3e; --text: #e2e8f0; --accent: #00d4a0; --red: #ff4757; --orange: #ffa502; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 10px; font-size: 12px; }}
    .threat-item {{ border: 1px solid var(--border); margin-bottom: 8px; border-radius: 4px; cursor: pointer; overflow: hidden; }}
    .threat-header {{ padding: 10px; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02); }}
    .t-title {{ font-weight: bold; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-right: 10px; }}
    .threat-detail {{ display: none; padding: 15px; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2); line-height: 1.5; }}
    .threat-detail.open {{ display: block; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; margin: 2px; text-decoration: none; }}
    .badge-mitre {{ background: rgba(0,212,160,0.15); color: var(--accent); border: 1px solid var(--accent); }}
    .badge-cve {{ background: rgba(255,71,87,0.15); color: var(--red); border: 1px solid var(--red); }}
    .badge-ioc {{ background: rgba(255,165,2,0.15); color: var(--orange); border: 1px solid var(--orange); }}
    .section-title {{ font-size: 11px; color: #8892a4; text-transform: uppercase; margin-top: 10px; margin-bottom: 5px; font-weight: bold; }}
    .source-link {{ display: block; text-align: right; color: var(--accent); font-size: 11px; margin-top: 10px; text-decoration: none; font-weight: bold;}}
</style></head>
<body><div id="root"></div>
<script>
    const DATA = {json_data}; 
    let openId = null;
    
    function escapeHtml(t) {{ return t ? t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : ""; }}
    
    function render() {{
        const root = document.getElementById('root');
        if (!DATA.threats || DATA.threats.length === 0) {{
            root.innerHTML = '<div style="text-align:center;padding:20px;color:#888;">Sin datos disponibles</div>';
            return;
        }}
        
        root.innerHTML = DATA.threats.map(function(t) {{
            // 1. MITRE (Verificación segura)
            let mitreHtml = '';
            if(t.mitre && t.mitre.length > 0) {{
                mitreHtml = '<div class="section-title">🎯 MITRE</div><div>';
                t.mitre.forEach(function(m) {{ mitreHtml += '<a href="https://attack.mitre.org/techniques/' + m + '/" target="_blank" class="badge badge-mitre">' + m + '</a>'; }});
                mitreHtml += '</div>';
            }}
            
            // 2. IOCs y CVEs (Verificación segura y distinción de colores)
            let iocsHtml = '';
            if(t.iocs && t.iocs.length > 0) {{
                iocsHtml = '<div class="section-title">🚨 Indicadores</div><div>';
                t.iocs.forEach(function(i) {{
                    // Si el tipo es CVE, usamos estilo rojo, sino naranja
                    let badgeClass = (i.type === 'CVE') ? 'badge-cve' : 'badge-ioc';
                    iocsHtml += '<span class="badge ' + badgeClass + '">' + i.type + ': ' + i.val + '</span>';
                }});
                iocsHtml += '</div>';
            }}
            
            return '<div class="threat-item">' +
                '<div class="threat-header" onclick="toggle(\\'' + t.id + '\\')">' +
                    '<div class="t-title">' + escapeHtml(t.name) + '</div>' +
                    '<div style="font-family:monospace; font-weight:bold; color:' + (t.sev === 'critical' ? 'var(--red)' : 'var(--accent)') + '">' + t.score + '</div>' +
                '</div>' +
                '<div class="threat-detail ' + (openId === t.id ? 'open' : '') + '" id="det-' + t.id + '">' +
                    '<div style="color:#aaa; font-size:11px; margin-bottom:8px;">📅 ' + t.date + ' | 🗞️ ' + t.sourceName + '</div>' +
                    '<div style="margin-bottom:10px;">' + escapeHtml(t.desc) + '</div>' +
                    mitreHtml + iocsHtml +
                    '<a href="' + t.source + '" target="_blank" class="source-link">Ver Fuente ↗</a>' +
                '</div>' +
            '</div>';
        }}).join('');
    }}
    
    function toggle(id) {{ openId = (openId === id) ? null : id; render(); }}
    render();
</script></body></html>
"""

# --- INTERFAZ PRINCIPAL ---
tabs = st.tabs(["🏠 Dashboard", "🦠 Ransomware", "🔎 Analizar IP", "#️⃣ Hash", "🌐 URL", "📂 MasivoIps", "📚 Playbooks", "🚨 Watcher", "⚙️ Config"])

# --- TAB 0: DASHBOARD ---
with tabs[0]:
    # 1. Carga y Métricas
    live_threats = fetch_intelligence_feed()
    total_events = len(live_threats)
    critical_count = sum(1 for t in live_threats if t['sev'] == 'critical')
    
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("🛡️ Eventos", f"{total_events}")
    with c2: st.metric("🔥 Críticas", f"{critical_count}")
    with c3: st.metric("📡 Fuentes", "4")
    with c4:
        if st.button("🔄 Sync", key="btn_sync_dash"): st.cache_data.clear(); st.rerun()

    # 2. Layout Principal
    col_feed, col_right = st.columns([2.5, 1])
    with col_feed:
        st.subheader("🌍 Feed de Amenazas")
        components.html(get_dashboard_html({"threats": live_threats}), height=800, scrolling=True)

    with col_right:
        st.subheader("🛡️ OWASP Top 10")
        owasp_counts = calculate_owasp_relevance(live_threats, OWASP_DATA)
        for item in OWASP_DATA:
            count = owasp_counts.get(item['id'], 0)
            badge = f"🔥 {count}" if count > 0 else "✅"
            with st.expander(f"**{item['id']} - {item['name']}** | {badge}"):
                if count > 0: st.warning(f"⚠️ {count} noticias relacionadas.")
                st.markdown(f"**Desc:** {item['desc']}")
                checked = st.checkbox(f"Control OK", value=st.session_state.owasp_checks.get(item['id'], False), key=f"check_{item['id']}")
                st.session_state.owasp_checks[item['id']] = checked

         # 3. Separación de IOCs y CVEs (CÓDIGO MEJORADO)
    st.divider()
    
    col_ioc, col_vuln = st.columns(2)
    
    iocs_list = [] 
    cves_list = [] 
    
    # NOTA: El 'for' debe estar a la misma altura que las variables anteriores
    for t in live_threats:
        # 1. Procesar IOCs (IPs, Hashes)
        threat_iocs = t.get('iocs', [])
        if threat_iocs: 
            for i in threat_iocs:
                if i and isinstance(i, dict) and 'val' in i:
                    iocs_list.append({
                        "Tipo": i.get('type', 'N/A'), 
                        "Indicador": i['val'], 
                        "Fuente": t.get('sourceName', 'N/A')
                    })

        # 2. Procesar CVEs (Vulnerabilidades)
        threat_cves = t.get('cves', [])
        if threat_cves:
            for c in threat_cves:
                if c and isinstance(c, dict) and 'val' in c:
                    cves_list.append({
                        "CVE ID": c['val'], 
                        "Contexto": t['name'][:40]+"...", 
                        "Fuente": t.get('sourceName', 'N/A')
                    })

        # 2. Procesar CVEs (Vulnerabilidades) - Leemos la lista separada
        threat_cves = t.get('cves', [])
        if threat_cves:
            for c in threat_cves:
                if c and isinstance(c, dict) and 'val' in c:
                    cves_list.append({
                        "CVE ID": c['val'], 
                        "Contexto": t['name'][:40]+"...", 
                        "Fuente": t.get('sourceName', 'N/A')
                    })
    # Columna IOCs
    with col_ioc:
        st.subheader("📦 IOCs Extraídos")
        st.caption("Indicadores de Compromiso (IPs, Hashes, Dominios)")
        if iocs_list:
            df_iocs = pd.DataFrame(iocs_list).drop_duplicates()
            st.dataframe(df_iocs, use_container_width=True, hide_index=True)
            csv_iocs = df_iocs.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Descargar IOCs", csv_iocs, "iocs.csv", "text/csv", key="dl_iocs_dash")
        else: 
            st.info("Sin IOCs activos en este feed.")

    # Columna Vulnerabilidades
    with col_vuln:
        st.subheader("⚠️ Vulnerabilidades")
        st.caption("Debilidades de software detectadas (CVEs)")
        if cves_list:
            df_cves = pd.DataFrame(cves_list).drop_duplicates()
            st.dataframe(df_cves, use_container_width=True, hide_index=True)
        else:
            st.info("Sin CVEs recientes en este feed.")

    # 4. Mapa
    st.divider()
    st.subheader("🗺️ Mapa de Amenazas")
    m = folium.Map(location=COMPANY_CONTEXT['coords']['CO'], zoom_start=3, tiles="CartoDB dark_matter")
    for threat in live_threats:
        coords = COMPANY_CONTEXT['coords'].get(threat['country_code'], COMPANY_CONTEXT['coords']['DEFAULT'])
        color = "#ff4757" if threat['sev'] == 'critical' else "#ffa502"
        folium.CircleMarker(location=coords, radius=8, color=color, fill=True, popup=threat['name']).add_to(m)
    st_folium(m, width='100%', height=450)

# --- TAB 1: RANSOMWARE TRACKER ---
with tabs[1]: 
    st.title("🦠 Ransomware World Tracker")
    st.markdown("Monitoreo en tiempo real vía RSS. Se detecta país por palabras clave y se extraen IOCs del contenido.")

    # Botón de sincronización
    if st.button("🔄 Sincronizar Ransomware Feed", key="btn_sync_ransom"):
        st.cache_data.clear()
        st.rerun()

    # 1. Diccionario de Detección de Países (Heurística)
    COUNTRY_KEYWORDS = {
        "CO": ["colombia", "bogotá", "medellín", "cali", "barranquilla", "colombiana"],
        "MX": ["méxico", "mexico", "cdmx", "monterrey", "guadalajara", "mexicana"],
        "BR": ["brasil", "brazil", "são paulo", "sao paulo", "rio de janeiro", "brasileña"],
        "AR": ["argentina", "buenos aires", "argentina"],
        "CL": ["chile", "santiago", "chilena"],
        "PE": ["perú", "peru", "lima", "peruana"],
        "EC": ["ecuador", "quito", "guayaquil", "ecuatoriana"],
        "VE": ["venezuela", "caracas", "venezolana"],
        "PA": ["panamá", "panama", "panameña"],
        "CR": ["costa rica", "san josé", "costarricense"]
    }
    LATAM_CODES = list(COUNTRY_KEYWORDS.keys())

    # 2. Función interna para detectar país
    def detect_country(text):
        text_lower = text.lower()
        for code, keywords in COUNTRY_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    return code
        return "GLOBAL"

    # 3. Obtener y Procesar Datos
    ransom_data = fetch_ransomware_feed() # Esta es tu función RSS corregida anterior
    processed_data = []

    if ransom_data:
        for item in ransom_data:
            # Unimos título y descripción para buscar el país
            full_text = item.get('victim', '') + " " + item.get('desc', '')
            detected_country = detect_country(full_text)
            
            # Extraemos IOCs usando tu función existente
            iocs_found = []
            # Asumimos que tienes extract_observables o extract_iocs_regex disponible
            # Si no, omite este bloque o usa una regex simple
            try:
                if 'extract_observables' in globals():
                    obs = extract_observables(full_text)
                    iocs_found = obs.get('iocs', [])
            except:
                pass

            processed_data.append({
                "Organización": item.get('victim', 'N/A'),
                "Grupo": item.get('group', 'Desconocido'),
                "País": detected_country,
                "Fecha": item.get('published', 'N/A'),
                "Fuente": item.get('source', '#'),
                "Descripción": item.get('desc', ''),
                "IOCs": iocs_found
            })

    # 4. Filtros
    col_f1, col_f2 = st.columns([1, 2])
    view_mode = col_f1.radio("Vista:", ["🌍 Mundial", "🌎 Latinoamérica"], horizontal=True, key="radio_ransom_view")

    if "Latinoamérica" in view_mode:
        final_data = [r for r in processed_data if r['País'] in LATAM_CODES]
        if not final_data:
            st.warning("⚠️ No se detectaron víctimas con palabras clave de LATAM en este lote. Prueba con 'Mundial'.")
    else:
        final_data = processed_data

    # 5. Métricas
    c1, c2 = st.columns(2)
    with c1: st.metric("Victimas Recientes", len(final_data))
    with c2: st.metric("Grupos Detectados", len(set([r['Grupo'] for r in final_data])))

    st.divider()

    # 6. Visualización
    if final_data:
        # Crear DataFrame para la tabla principal
        df_display = pd.DataFrame(final_data)
        
        # Configuración de columnas para hacer clickeable la fuente
        st.dataframe(
            df_display[["Organización", "Grupo", "País", "Fecha"]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Organización": st.column_config.TextColumn("Víctima", width="large"),
                "Grupo": st.column_config.TextColumn("Actor", width="medium"),
                "País": st.column_config.TextColumn("País", width="small"),
            }
        )

        st.subheader("🔎 Detalle y Evidencia")
        selected_victim = st.selectbox(
            "Selecciona una víctima para ver detalles y IOCs:", 
            df_display['Organización'].unique(),
            key="select_ransom_victim"
        )

        if selected_victim:
            details = next((item for item in final_data if item['Organización'] == selected_victim), None)
            if details:
                c1_det, c2_det = st.columns([2, 1])
                
                with c1_det:
                    st.markdown(f"**📝 Descripción:**")
                    st.info(details['Descripción'])
                    
                    # Enlace a la fuente
                    st.markdown(f"🔗 **[Ir a la Fuente Original / Leak Site]({details['Fuente']})**")
                    st.caption("⚠️ Advertencia: Acceder a sitios de ransomware puede ser peligroso. Use navegación aislada.")

                with c2_det:
                    st.markdown(f"**🚨 IOCs Extraídos:**")
                    if details['IOCs']:
                        for ioc in details['IOCs']:
                            st.code(f"{ioc['type']}: {ioc['val']}", language="text")
                    else:
                        st.success("Sin indicadores técnicos en el resumen.")
    else:
        st.info("Esperando datos o sincronizando...")

# --- TAB 2: ANALIZAR IP ---
with tabs[2]:
    st.title("🔎 Análisis IP")
    if st.session_state.get('clear_ip'): st.session_state.analysis_results = None; st.session_state.input_ip_val = ""; st.session_state.clear_ip = False
    user_input = st.text_input("IP:", key="input_ip_val")
    c1, c2, c3 = st.columns([1, 1, 3])
    # KEYS ÚNICOS PARA TAB 2
    if c2.button("🧹 Limpiar", key="btn_clean_ip_tab2"): st.session_state.clear_ip = True; st.rerun()
    if c1.button("Analizar", type="primary", key="btn_analyze_ip_tab2") and user_input:
        if not st.session_state.api_keys['abuseipdb']: st.error("Configure API.")
        else:
            with st.spinner("Consultando..."):
                results = {"type": "IP", "value": user_input, "abuse": None, "vt": None}
                try:
                    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": st.session_state.api_keys['abuseipdb']}, params={"ipAddress": user_input, "maxAgeInDays": 90})
                    if r.status_code == 200: results['abuse'] = r.json()['data']
                except: pass
                if st.session_state.api_keys['virustotal']:
                    try:
                        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}", headers={"x-apikey": st.session_state.api_keys['virustotal']})
                        if r.status_code == 200: results['vt'] = r.json()['data']['attributes']
                    except: pass
                st.session_state.analysis_results = results
                ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                sc = results['abuse'].get('abuseConfidenceScore', 0) if results.get('abuse') else 0
                st.session_state.analysis_history.append({"Fecha": ts, "IP": user_input, "Score": f"{sc}%", "Status": "Malo" if sc>50 else "OK"})

    if st.session_state.analysis_results:
        res = st.session_state.analysis_results
        if res.get('abuse'):
            st.metric("Score", f"{res['abuse'].get('abuseConfidenceScore', 0)}%")
            st.json(res['abuse'])

# --- TAB 3: HASH ---
with tabs[3]:
    st.title("#️⃣ Análisis de Hash")
    if st.session_state.get('clear_hash'): st.session_state.analysis_results = None; st.session_state.input_hash_val = ""; st.session_state.clear_hash = False
    hash_input = st.text_input("Ingrese Hash", key="input_hash_val")
    c1, c2, c3 = st.columns([1, 1, 3])
    # KEYS ÚNICOS PARA TAB 3
    if c1.button("Analizar Hash", type="primary", key="btn_analyze_hash_tab3"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Buscando..."):
                res = get_vt_hash_report(hash_input)
                if res: st.session_state.analysis_results = res
                else: st.error("No encontrado.")
        else: st.error("Configure VT API Key.")
    if c2.button("🧹 Nueva Consulta", key="btn_clear_hash_tab3"): st.session_state.clear_hash = True; st.rerun()
    if st.session_state.analysis_results and isinstance(st.session_state.analysis_results, dict) and 'data' in st.session_state.analysis_results:
        res = st.session_state.analysis_results; stats = res['data']['attributes'].get('last_analysis_stats', {}); mal = stats.get('malicious', 0)
        st.markdown(f"<div class='evidence-card'><div class='evidence-header'>🦠 Reporte de Malware</div><div style='text-align:center; padding:20px;'><div style='font-size:40px; font-weight:bold; color:{"#ff4757" if mal > 0 else "#2ed573"};'>{mal}/{sum(stats.values())}</div></div></div>", unsafe_allow_html=True)

# --- TAB 4: URL ---
with tabs[4]:
    st.title("🌐 Análisis de URL")
    if st.session_state.get('clear_url'): st.session_state.analysis_results = None; st.session_state.input_url_val = ""; st.session_state.clear_url = False
    url_input = st.text_input("Ingrese URL", key="input_url_val")
    c1, c2, c3 = st.columns([1, 1, 3])
    # KEYS ÚNICOS PARA TAB 4
    if c1.button("Analizar URL", type="primary", key="btn_analyze_url_tab4"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Analizando..."):
                res = get_vt_url_report(url_input)
                if res: st.session_state.analysis_results = res
                else: st.error("Error al analizar.")
        else: st.error("Configure VT API Key.")
    if c2.button("🧹 Nueva Consulta", key="btn_clear_url_tab4"): st.session_state.clear_url = True; st.rerun()
    if st.session_state.analysis_results and isinstance(st.session_state.analysis_results, dict) and 'data' in st.session_state.analysis_results:
        res = st.session_state.analysis_results; stats = res['data']['attributes'].get('last_analysis_stats', {}); mal = stats.get('malicious', 0)
        st.markdown(f"<div class='evidence-card'><div class='evidence-header'>🌍 Reporte URL</div><div style='text-align:center; padding:20px;'><div style='font-size:30px; font-weight:bold; color:{"#ff4757" if mal > 0 else "#2ed573"};'>{"MALICIOSA" if mal > 0 else "LIMPIA"}</div></div></div>", unsafe_allow_html=True)

# --- TAB 5: MASIVO IPS ---
with tabs[5]:
    st.title("📂 MasivoIps")
    if st.session_state.get('clear_bulk'):
        if 'bulk_results_df' in st.session_state: del st.session_state.bulk_results_df
        st.session_state.clear_bulk = False; st.rerun()
    # KEY ÚNICO PARA TAB 5
    if st.button("🧹 Limpiar Resultados", key="btn_clear_bulk_tab5"): st.session_state.clear_bulk = True; st.rerun()
    st.markdown("⚠️ **Nota:** Se omitirán IPs privadas.")
    uploaded_file = st.file_uploader("Cargar archivo CSV o TXT", type=['csv', 'txt'])
    if uploaded_file:
        try:
            try: df = pd.read_csv(uploaded_file)
            except: df = pd.read_csv(uploaded_file, header=None, names=['ip'])
            st.write("Vista previa:", df.head(3))
            target_column = [col for col in df.columns if 'ip' in col.lower()] or [df.columns[0]]
            st.info(f"Se usará la columna: **{target_column[0]}**")
            # KEY ÚNICO PARA TAB 5
            if st.button("Iniciar Análisis Masivo", type="primary", key="btn_bulk_scan_tab5"):
                if not st.session_state.api_keys['abuseipdb']: st.error("Configure API Key.")
                else:
                    progress_bar = st.progress(0); status_text = st.empty(); results = []; ips = df[target_column[0]].dropna().astype(str).unique().tolist()
                    for i, ip in enumerate(ips):
                        ip = ip.strip()
                        if is_private_ip(ip): results.append({"IP": ip, "Score": "PRIVATE", "Status": "Omitida"})
                        else:
                            data = {"IP": ip, "Score": "N/A", "Status": "Analizada"}
                            try:
                                r = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": st.session_state.api_keys['abuseipdb'], "Accept": "application/json"}, params={"ipAddress": ip, "maxAgeInDays": 90})
                                if r.status_code == 200: d = r.json()['data']; data["Score"] = f"{d.get('abuseConfidenceScore', 0)}%"
                            except: pass
                            results.append(data); time.sleep(1.1)
                        progress_bar.progress((i+1)/len(ips)); status_text.text(f"Procesado {i+1}/{len(ips)}")
                    st.session_state.bulk_results_df = pd.DataFrame(results)
        except Exception as e: st.error(f"Error: {e}")
    if 'bulk_results_df' in st.session_state:
        res_df = st.session_state.bulk_results_df
        st.dataframe(res_df, use_container_width=True)
        st.download_button("📥 CSV", res_df.to_csv(index=False).encode('utf-8'), "reporte_masivo.csv", "text/csv", key="dl_bulk_tab5")

# --- TAB 6: PLAYBOOKS (MOTOR DE REGLAS: GLOBAL + ESPECÍFICOS) ---
with tabs[6]:
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
with tabs[7]:
    st.title("🚨 Watcher")
    st.caption("Monitorea activos específicos (Ej: 'linux', 'cisco', 'apache') y recibe alertas detalladas.")
    
    if st.session_state.get('clear_watcher'): 
        st.session_state.input_watcher_val = ""
        st.session_state.watcher_assets = []
        st.session_state.clear_watcher = False
        
    assets = st.text_area("Activos a vigilar (separados por coma)", key="input_watcher_val", placeholder="linux, cisco, windows, apache")
    c1, c2, c3 = st.columns([1, 1, 3])
    
    # KEYS ÚNICOS PARA TAB 7
    if c1.button("Vigilar", type="primary", key="btn_vigilar_watcher_tab7") and assets: 
        st.session_state.watcher_assets = [a.strip().lower() for a in assets.split(",")]
        
    if c2.button("🧹 Limpiar", key="btn_clean_watcher_tab7"): 
        st.session_state.clear_watcher = True
        st.rerun()
        
    # Lógica de Monitoreo Mejorada
    if st.session_state.watcher_assets:
        alertas_encontradas = 0
        
        for t in fetch_intelligence_feed():
            txt = (t['name'] + t['desc']).lower()
            # Verificamos si algún activo coincide en el texto
            match_found = False
            matched_asset = ""
            
            for a in st.session_state.watcher_assets:
                if a in txt:
                    match_found = True
                    matched_asset = a
                    break # Si encuentra uno, basta para mostrar la alerta
            
            if match_found:
                alertas_encontradas += 1
                
                # -- TARJETA DE ALERTA DETALLADA --
                st.error(f"🚨 **Alerta para activo:** `{matched_asset.upper()}`")
                
                # 1. Título y Fuente
                st.markdown(f"**{t['name']}**")
                st.caption(f"🗓️ {t['date']} | 🗞️ Fuente: {t['sourceName']}")
                
                # 2. Enlace Directo
                st.markdown(f"🔗 [Ir a la Noticia Original]({t['source']})")
                
                # 3. Mostrar CVEs si existen
                if t.get('cves'):
                    st.warning("🛠️ **CVEs Relacionados:**")
                    cves_string = " | ".join([f"`{c['val']}`" for c in t['cves']])
                    st.markdown(cves_string)
                
                # 4. Mostrar IOCs si existen
                if t.get('iocs'):
                    with st.expander("🚨 Ver Indicadores de Compromiso (IOCs)"):
                        # Creamos columnas para mostrar ordenado
                        for i in t['iocs']:
                            st.code(f"{i.get('type')}: {i.get('val')}", language="text")
                
                st.divider()

        if alertas_encontradas == 0:
            st.success("✅ No se detectaron amenazas recientes para los activos configurados.")
# --- TAB 8: CONFIG & REPORTES ---
with tabs[8]:
    st.title("⚙️ Centro de Administración")
    
    # Config
    mode = st.toggle("Modo Oscuro", value=st.session_state.dark_mode)
    if mode != st.session_state.dark_mode: st.session_state.dark_mode = mode; st.rerun()
    st.divider()
    c1, c2 = st.columns(2)
    with c1: st.text_input("AbuseIPDB Key", type="password", key="k_ab", on_change=lambda: st.session_state.api_keys.update({'abuseipdb': st.session_state.k_ab}))
    with c2: st.text_input("VirusTotal Key", type="password", key="k_vt", on_change=lambda: st.session_state.api_keys.update({'virustotal': st.session_state.k_vt}))
    
    # REPORTES
    st.divider()
    st.subheader("📊 Reportes Gerenciales")
    c_rep1, c_rep2, c_rep3 = st.columns(3)
    
    with c_rep1:
        st.markdown("### 📄 Lista Blanca")
        if st.session_state.whitelist:
            df_wl = pd.DataFrame(st.session_state.whitelist, columns=["IP"])
            st.dataframe(df_wl, use_container_width=True, hide_index=True)
            st.download_button("📥 CSV", df_wl.to_csv(index=False).encode('utf-8'), "wl.csv", "text/csv", key="dl_wl_tab8")
        else: st.info("Vacía")

    with c_rep2:
        st.markdown("### 📄 Historial Análisis")
        if st.session_state.analysis_history:
            df_hist = pd.DataFrame(st.session_state.analysis_history)
            st.dataframe(df_hist, use_container_width=True, hide_index=True)
            st.download_button("📥 CSV", df_hist.to_csv(index=False).encode('utf-8'), "hist.csv", "text/csv", key="dl_hist_tab8")
        else: st.info("Vacío")

    with c_rep3:
        st.markdown("### 📄 IOCs Detectados")
        ioc_list = []
        for t in fetch_intelligence_feed():
            if t['iocs']:
                for i in t['iocs']:
                    if i and i.get('val'): ioc_list.append({"Fecha": t['date'], "Tipo": i['type'], "Valor": i['val'], "Fuente": t['sourceName']})
        if ioc_list:
            df_iocs = pd.DataFrame(ioc_list).drop_duplicates()
            st.dataframe(df_iocs, use_container_width=True, hide_index=True)
            st.download_button("📥 CSV", df_iocs.to_csv(index=False).encode('utf-8'), "iocs.csv", "text/csv", key="dl_iocs_tab8")
        else:
            st.info("Sin IOCs.")
