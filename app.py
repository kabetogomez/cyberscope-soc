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

# --- GESTIÓN DE ESTADO Y TEMA ---
if 'api_keys' not in st.session_state: st.session_state.api_keys = {"abuseipdb": "", "virustotal": "", "vuldb": ""}
if 'dark_mode' not in st.session_state: st.session_state.dark_mode = True
if 'analysis_history' not in st.session_state: st.session_state.analysis_history = []
if 'whitelist' not in st.session_state: st.session_state.whitelist = ["8.8.8.8", "8.8.4.4"]
if 'watcher_assets' not in st.session_state: st.session_state.watcher_assets = []
if 'analysis_results' not in st.session_state: st.session_state.analysis_results = None

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
        .high-score {{ background-color: rgba(255, 71, 87, 0.1) !important; color: white !important; }}
    </style>
    """, unsafe_allow_html=True)

inject_css()

# --- FUNCIONES AUXILIARES ---
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

# --- PLANTILLA HTML DASHBOARD (ACTUALIZADA) ---
def get_dashboard_html(data):
    json_data = json.dumps(data)
    return f"""
<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
    :root {{ --bg: #111419; --border: #252d3e; --text: #e2e8f0; --accent: #00d4a0; --red: #ff4757; --orange: #ffa502; }}
    body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', sans-serif; margin: 0; padding: 10px; font-size: 12px; }}
    
    /* Tarjeta principal */
    .threat-item {{ border: 1px solid var(--border); margin-bottom: 8px; border-radius: 4px; cursor: pointer; overflow: hidden; }}
    .threat-header {{ padding: 10px; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02); }}
    .t-title {{ font-weight: bold; flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-right: 10px; }}
    
    /* Detalles */
    .threat-detail {{ display: none; padding: 15px; border-top: 1px solid var(--border); background: rgba(0,0,0,0.2); line-height: 1.5; }}
    .threat-detail.open {{ display: block; }}
    
    /* Etiquetas */
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; margin-right: 5px; text-decoration: none; }}
    .badge-mitre {{ background: rgba(0,212,160,0.15); color: var(--accent); border: 1px solid var(--accent); }}
    .badge-cve {{ background: rgba(255,71,87,0.15); color: var(--red); border: 1px solid var(--red); }}
    .badge-ioc {{ background: rgba(255,165,2,0.15); color: var(--orange); border: 1px solid var(--orange); }}
    
    .section-title {{ font-size: 11px; color: #8892a4; text-transform: uppercase; margin-top: 10px; margin-bottom: 5px; font-weight: bold; }}
    
    /* Botón fuente */
    .source-link {{ display: block; text-align: right; color: var(--accent); font-size: 11px; margin-top: 10px; text-decoration: none; font-weight: bold;}}
</style>
</head>
<body><div id="root"></div>
<script>
    const DATA = {json_data}; 
    let openId = null;
    
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
                    <!-- Meta Info -->
                    <div style="color:#aaa; font-size:11px; margin-bottom:8px;">📅 ${{t.date}} | 🗞️ ${{t.sourceName}}</div>
                    
                    <!-- Resumen -->
                    <div style="margin-bottom:10px;">${{escapeHtml(t.desc)}}</div>
                    
                    <!-- Clasificación MITRE -->
                    ${{t.mitre.length > 0 ? `
                        <div class="section-title">🎯 Técnicas MITRE ATT&CK</div>
                        <div style="margin-bottom:8px;">
                            ${{t.mitre.map(m => `<a href="https://attack.mitre.org/techniques/${{m}}/" target="_blank" class="badge badge-mitre">${{m}}</a>`).join('')}}
                        </div>
                    ` : ''}}
                    
                    <!-- IOCs (CVEs, IPs, Hashes) -->
                    ${{t.iocs.length > 0 ? `
                        <div class="section-title">🚨 Indicadores (IOCs)</div>
                        <div style="margin-bottom:8px;">
                            ${{t.iocs.map(i => {{
                                if(i.type === 'CVE') return `<a href="https://nvd.nist.gov/vuln/detail/${{i.val}}" target="_blank" class="badge badge-cve">${{i.val}}</a>`;
                                return `<span class="badge badge-ioc">${{i.type}}: ${{i.val}}</span>`;
                            }}).join(' ')}}
                        </div>
                    ` : ''}}
                    
                    <!-- Link Fuente -->
                    <a href="${{t.source}}" target="_blank" class="source-link">Ver Fuente Original ↗</a>
                </div>
            </div>
        `).join('');
    }}
    
    function toggle(id) {{ 
        openId = (openId === id) ? null : id; 
        render(); 
    }}
    
    render();
</script>
</body>
</html>
"""

# --- INTERFAZ PRINCIPAL ---
tabs = st.tabs(["🏠 Dashboard", "🔎 Analizar IP", "#️⃣ Hash", "🌐 URL", "📂 Bulk", "📚 Playbooks", "🚨 Watcher", "⚙️ Config"])

# --- TAB 1: DASHBOARD ---
with tabs[0]:
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("🛡️ Eventos", "12,450")
    with c2: st.metric("🔥 Críticas", "5")
    with c3: st.metric("📡 Fuentes", "4")
    with c4:
        if st.button("🔄 Sync", key="btn_sync_dash"):
            st.cache_data.clear()
            st.rerun()

    col_feed, col_right = st.columns([2.5, 1])
    with col_feed:
        st.subheader("🌍 Feed de Amenazas")
        live_threats = fetch_intelligence_feed()
        components.html(get_dashboard_html({"threats": live_threats}), height=600, scrolling=True)

    with col_right:
        st.subheader("🗺️ Mapa")
        m = folium.Map(location=COMPANY_CONTEXT['coords']['CO'], zoom_start=3, tiles="CartoDB dark_matter")
        for threat in live_threats:
            coords = COMPANY_CONTEXT['coords'].get(threat['country_code'], COMPANY_CONTEXT['coords']['DEFAULT'])
            color = "#ff4757" if threat['sev'] == 'critical' else "#ffa502"
            folium.CircleMarker(location=coords, radius=6, color=color, fill=True, popup=threat['name'][:20]).add_to(m)
        st_folium(m, width='100%', height=400)

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

# --- TAB 2: ANALIZAR IP ---
with tabs[1]:
    st.title("🔎 Análisis de Dirección IP")
    user_input = st.text_input("Ingrese IP:", placeholder="Ej: 192.168.1.1", key="input_ip_analysis")
    
    c1, c2 = st.columns([1, 4])
    analyze_btn = c1.button("Analizar", type="primary", key="btn_analyze_ip")
    add_wl_btn = c2.button("➕ Añadir a Whitelist", key="btn_add_wl")

    if add_wl_btn and user_input:
        if user_input not in st.session_state.whitelist:
            st.session_state.whitelist.append(user_input)
            st.success(f"✅ {user_input} añadida.")

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

    if st.session_state.analysis_results:
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
    hash_input = st.text_input("Ingrese Hash", placeholder="SHA256, MD5...", key="input_hash")
    if st.button("Analizar Hash", type="primary", key="btn_analyze_hash"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Buscando..."):
                res = get_vt_hash_report(hash_input)
                if res:
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
                else:
                    st.error("No encontrado.")
        else:
            st.error("Configure VT API Key.")

# --- TAB 4: URL ---
with tabs[3]:
    st.title("🌐 Análisis de URL")
    url_input = st.text_input("Ingrese URL", placeholder="https://...", key="input_url")
    if st.button("Analizar URL", type="primary", key="btn_analyze_url"):
        if st.session_state.api_keys['virustotal']:
            with st.spinner("Analizando..."):
                res = get_vt_url_report(url_input)
                if res:
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
        else:
            st.error("Configure VT API Key.")

# --- TAB 5: BULK SCAN ---
with tabs[4]:
    st.title("📂 Escaneo Masivo de IPs")
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
                            except Exception as e:
                                data["Status"] = "Error API"
                            
                            results.append(data)
                            time.sleep(1.1)
                        
                        progress_bar.progress((i+1)/len(ips))
                        status_text.text(f"Procesado {i+1}/{len(ips)}")

                    status_text.text("¡Análisis completado!")
                    res_df = pd.DataFrame(results)
                    
                    def highlight_malicious(s):
                        return ['background-color: #ff4757; color: white' if v and '%' in str(v) and int(str(v).replace('%','')) > 80 else '' for v in s]

                    st.dataframe(res_df.style.apply(highlight_malicious, subset=['Score']), use_container_width=True)
                    
                    csv = res_df.to_csv(index=False).encode('utf-8')
                    st.download_button("📥 Descargar Reporte CSV", csv, "reporte_masivo.csv", "text/csv", key="dl_bulk")

        except Exception as e:
            st.error(f"Error procesando archivo: {e}")

# --- TAB 6: PLAYBOOKS ---
with tabs[5]:
    st.title("📚 Playbooks")
    alert_text = st.text_area("Descripción del Incidente", height=150, key="input_playbook")
    if st.button("Analizar Incidente", type="primary", key="btn_playbook"):
        steps = []
        if "ransomware" in alert_text.lower():
            steps = [{"s": "1. Aislamiento", "d": "Desconectar red."}, {"s": "2. Preservación", "d": "Capturar RAM."}]
        else:
            steps = [{"s": "1. Triage", "d": "Validar alerta."}]
        
        for x in steps:
            st.markdown(f"<div class='step-box'><b>{x['s']}</b><br>{x['d']}</div>", unsafe_allow_html=True)

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
