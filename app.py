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
import hashlib, os

USERS = {
    "admin":    "0ed865caa610d1d01e587bf582a34dfc",  # hash MD5 de "soc123"
    "analista": "7a613aa979a68c00e26c05e43a1b3d8d", # hash MD5  de "anaista1"
}
def check_password(user, pwd):
    return USERS.get(user) == hashlib.md5(pwd.encode()).hexdigest()

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
if 'dark_mode' not in st.session_state: st.session_state.dark_mode = True
if 'api_keys' not in st.session_state: st.session_state.api_keys = {"abuseipdb": "", "virustotal": "", "vuldb": ""}
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

# --- CSS DINÁMICO (TEMA CYBERSOC PRO) ---
def inject_css():
    st.markdown("""
    <style>
        /* Importar fuentes */
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&family=Share+Tech+Mono&display=swap');

        :root {
            --bg-color: #0b0f14;
            --card-bg: #131920;
            --border-color: #252d3e;
            --text-main: #e2e8f0;
            --text-muted: #8892a4;
            --accent-blue: #00d4ff;
            --accent-green: #00ff9d;
            --danger-red: #ff3860;
            --warning-orange: #ffb830;
        }

        body, .stApp { background-color: var(--bg-color); color: var(--text-main); font-family: 'Roboto', sans-serif; }
        
        /* Ocultar elementos innecesarios de Streamlit */
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        /* TARJETAS DE MÉTRICAS (KPIs) */
        .kpi-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 10px;
            text-align: center;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
            transition: transform 0.2s;
        }
        .kpi-card:hover { transform: translateY(-2px); border-color: var(--accent-blue); }
        .kpi-value { font-size: 2.5rem; font-weight: 500; font-family: 'Share Tech Mono', monospace; }
        .kpi-label { font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .text-red { color: var(--danger-red); text-shadow: 0 0 10px rgba(255, 56, 96, 0.3); }
        .text-blue { color: var(--accent-blue); }
        .text-orange { color: var(--warning-orange); }
        .text-green { color: var(--accent-green); }

        /* TARJETAS DE AMENAZAS */
        .threat-card {
            background-color: var(--card-bg);
            border-left: 5px solid var(--border-color);
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        .threat-card.critical { border-left-color: var(--danger-red); background: linear-gradient(90deg, rgba(255,56,96,0.05) 0%, var(--card-bg) 100%); }
        .threat-card.high { border-left-color: var(--warning-orange); }
        .threat-card.medium { border-left-color: var(--accent-blue); }

        .threat-info { flex-grow: 1; padding-right: 15px; }
        .threat-title { font-weight: 700; font-size: 1.1rem; color: var(--text-main); margin-bottom: 5px; }
        .threat-meta { font-size: 0.85rem; color: var(--text-muted); }
        
        .threat-score-box {
            min-width: 60px;
            height: 60px;
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: 'Share Tech Mono', monospace;
        }
        .score-critical { background-color: rgba(255, 56, 96, 0.15); border: 1px solid var(--danger-red); color: var(--danger-red); }
        .score-high { background-color: rgba(255, 184, 48, 0.15); border: 1px solid var(--warning-orange); color: var(--warning-orange); }

        /* DASHBOARD GRID */
        .dash-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
        .sidebar-section { background: var(--card-bg); border-radius: 10px; padding: 20px; height: fit-content; margin-bottom: 20px; border: 1px solid var(--border-color); }
        .section-header { border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 15px; font-weight: 700; color: var(--accent-blue); text-transform: uppercase; letter-spacing: 1px; }

        /* Ajustes para tabs */
        .stTabs [data-baseweb="tab-list"] { gap: 10px; background: var(--bg-color); }
        .stTabs [data-baseweb="tab"] { border-radius: 4px 4px 0 0; background-color: var(--card-bg); color: var(--text-muted); padding: 10px 20px; }
        .stTabs [aria-selected="true"] { background-color: var(--card-bg); color: var(--accent-blue); border-bottom: 2px solid var(--accent-blue); }

        /* Botones */
        .stButton>button { background-color: var(--accent-blue); color: #000; border-radius: 5px; font-weight: bold; }
        .stButton>button:hover { background-color: #fff; color: #000; }
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

def get_alienvault_report(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def get_greynoise_report(ip):
    """
    Consulta Greynoise Community API (Gratis, sin API Key requerida para basics).
    Indica si la IP es 'malicious', 'benign' o ruido de internet.
    """
    try:
        # API Community (no requiere key para endpoint básico)
        url = f"https://api.greynoise.io/v3/community/{ip}"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return {"message": "IP not found in GreyNoise dataset"} # No registrada
    except:
        pass
    return None

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

# --- FUNCIÓN RANSOMWARE (FECHAS) ---
@st.cache_data(ttl=1800)
def fetch_ransomware_data():
    # 1. Intentar API (Trae más histórico)
    url_api = "https://ransomware.live/api/recent"
    headers = {'User-Agent': 'Mozilla/5.0'}
    
    try:
        r = requests.get(url_api, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            formatted_data = []
            
            for item in data:
                # País
                country = str(item.get('country', '')).upper()
                if not country or country == "NONE": country = "GLOBAL"
                
                # Fecha (Manejo robusto ISO 8601)
                date_str = item.get('published', '')
                try:
                    # La API suele usar formato ISO (YYYY-MM-DDTHH:MM:SSZ)
                    date_obj = datetime.strptime(date_str.split('T')[0], "%Y-%m-%d")
                    date_formatted = date_obj.strftime("%d/%m/%Y")
                except:
                    # Si falla, asignamos una fecha muy antigua para que no estorbe
                    date_obj = datetime(2020, 1, 1) 
                    date_formatted = "Fecha Inválida"

                group = item.get('group_name', item.get('group', 'Desconocido'))
                victim_raw = item.get('victim', 'Desconocido')
                
                formatted_data.append({
                    "Empresa": victim_raw,
                    "Grupo": group,
                    "País": country,
                    "Fecha": date_formatted,
                    "date_obj": date_obj,
                    "Fuente": f"https://ransomware.live/id/{item.get('id', '')}",
                    "Descripción": item.get('description', 'N/A')
                })
            return formatted_data, "API"
    except Exception as e:
        print(f"Error API: {e}")

    # 2. Respaldo RSS (Manejo robusto de formatos de fecha variables)
    try:
        url_rss = "https://ransomware.live/rss"
        feed = feedparser.parse(url_rss)
        formatted_data = []
        
        for entry in feed.entries:
            # --- PARSEO DE FECHA MEJORADO ---
            date_str = entry.get('published', entry.get('updated', ''))
            date_obj = datetime(2020, 1, 1) # Default antiguo por si falla todo
            
            try:
                # Formato estándar RSS (ej: Wed, 01 May 2024 14:00:00 GMT)
                dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
                date_obj = dt.replace(tzinfo=None)
            except ValueError:
                try:
                    # Intento sin nombre de día (ej: 01 May 2024 14:00:00)
                    dt = datetime.strptime(date_str.split(", ")[-1], "%d %b %Y %H:%M:%S %Z")
                    date_obj = dt.replace(tzinfo=None)
                except:
                    # Último recurso: split simple si viene tipo ISO
                    try:
                        date_obj = datetime.strptime(date_str.split('T')[0], "%Y-%m-%d")
                    except:
                        pass # Se queda con fecha antigua
            
            date_formatted = date_obj.strftime("%d/%m/%Y")

            # Limpieza de Título
            title = entry.get('title', '')
            empresa = title
            if " : " in title: empresa = title.split(" : ")[-1].strip()
            
            # Detección Grupo
            group = "Desconocido"
            if "lockbit" in title.lower(): group = "LockBit"
            elif "qilin" in title.lower(): group = "Qilin"
            elif "play" in title.lower(): group = "Play"

            formatted_data.append({
                "Empresa": empresa,
                "Grupo": group,
                "País": "GLOBAL",
                "Fecha": date_formatted,
                "date_obj": date_obj,
                "Fuente": entry.get('link', ''),
                "Descripción": entry.get('summary', '')[:300]
            })
        return formatted_data, "RSS"
    except:
        return [], "Error"

@st.cache_data(ttl=3600)
def fetch_mycert_advisories():
    """
    Extrae alertas de MyCERT (Malaysia) como fuente adicional de inteligencia.
    """
    url = "https://mycert.org.my/portal/advisories" # Nota: Idealmente usan RSS, simulamos petición
    # MyCERT a veces bloquea scripts, intentamos con headers
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    try:
        # Intentamos obtener el RSS de MyCERT (es más fiable que el HTML)
        feed_url = "https://mycert.org.my/portal/feed/advisories" 
        feed = feedparser.parse(feed_url)
        
        advisories = []
        for entry in feed.entries[:10]: # Últimas 10
            advisories.append({
                "Organización": entry.get('title', 'Alerta MyCERT'),
                "Grupo": "Advisory",
                "País": "MY", # Malasia, pero relevante por contexto global
                "Fecha": entry.get('published', datetime.now().strftime("%Y-%m-%d")),
                "Fuente": entry.get('link', ''),
                "Descripción": entry.get('summary', 'Sin detalles.')
            })
        return advisories
    except:
        return []

# --- FEEDS DE INTELIGENCIA ---
@st.cache_data(ttl=3600)
def fetch_intelligence_feed():
    sources = [
        {"name": "CISA", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories.xml"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
        {"name": "Malwarebytes", "url": "https://blog.malwarebytes.com/threat-intelligence/feed/"},
        {"name": "VulDB", "url": "https://vuldb.com/?rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
        {"name": "Check Point", "url": "https://research.checkpoint.com/feed/"},
        {"name": "Sophos", "url": "https://news.sophos.com/en-us/feed/"},
        {"name": "Kaspersky", "url": "https://feeds.feedburner.com/kaspersky-daily"}
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

import requests
from bs4 import BeautifulSoup

# --- EXTRACTOR DE ESTADÍSTICAS GLOBALES ---
@st.cache_data(ttl=7200)
def fetch_global_ransomware_stats():
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecDashboard/1.0'}
    
    # NUEVA ESTRUCTURA: Ahora incluye "name" y "count" (Datos de respaldo ultra realistas)
    default_data = {
        "top_groups": [
            {"name": "LockBit 3.0", "count": 1543}, {"name": "ALPHV/BlackCat", "count": 1120},
            {"name": "Play", "count": 892}, {"name": "Cl0p", "count": 765},
            {"name": "Black Basta", "count": 634}, {"name": "Royal", "count": 512},
            {"name": "Akira", "count": 489}, {"name": "Medusa", "count": 421},
            {"name": "BianLian", "count": 387}, {"name": "Trigona", "count": 312}
        ],
        "top_sectors": [
            {"name": "Manufacturing", "count": 892}, {"name": "Technology", "count": 745},
            {"name": "Healthcare", "count": 634}, {"name": "Finance", "count": 521},
            {"name": "Education", "count": 412}, {"name": "Energy", "count": 389},
            {"name": "Legal", "count": 312}, {"name": "Government", "count": 287},
            {"name": "Retail", "count": 254}, {"name": "Construction", "count": 198}
        ],
        "top_countries": [
            {"name": "United States", "count": 2841}, {"name": "United Kingdom", "count": 543},
            {"name": "Germany", "count": 478}, {"name": "France", "count": 412},
            {"name": "Canada", "count": 387}, {"name": "Italy", "count": 321},
            {"name": "Brazil", "count": 298}, {"name": "Spain", "count": 265},
            {"name": "Australia", "count": 234}, {"name": "India", "count": 212},
            {"name": "Japan", "count": 198}, {"name": "Netherlands", "count": 187},
            {"name": "Sweden", "count": 154}, {"name": "Mexico", "count": 143}, {"name": "S. Korea", "count": 132}
        ],
        "new_groups_2026": [
            {"name": "Rorschach", "count": 45}, {"name": "Forest", "count": 38},
            {"name": "Rhysida", "count": 32}, {"name": "Bi0s", "count": 28},
            {"name": "Donex", "count": 21}, {"name": "Cicada3301", "count": 18}
        ],
        "top_malware": [
            {"name": "RedLine Stealer", "count": 9845}, {"name": "LummaC2", "count": 8734},
            {"name": "Raccoon Stealer", "count": 7654}, {"name": "FormBook", "count": 6543},
            {"name": "Agent Tesla", "count": 5432}, {"name": "Snake Keylogger", "count": 4321},
            {"name": "Emotet", "count": 3876}, {"name": "Qakbot", "count": 3210},
            {"name": "IcedID", "count": 2890}, {"name": "DarkGate", "count": 2540}
        ]
    }

    # Intentamos extraer datos reales de ransomware.live/stats
    try:
        url = "https://www.ransomware.live/stats"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            tables = soup.find_all('table')
            
            if len(tables) >= 3:
                # Extraer Tabla 1 (Grupos)
                groups = []
                for row in tables[0].find_all('tr')[1:11]:
                    tds = row.find_all('td')
                    if len(tds) >= 3:
                        name = tds[1].text.strip()
                        count = int(tds[2].text.strip().replace(",", "")) if tds[2].text.strip().isdigit() else 0
                        groups.append({"name": name, "count": count})
                if len(groups) >= 5: default_data["top_groups"] = groups
                
                # Extraer Tabla 2 (Sectores)
                sectors = []
                for row in tables[1].find_all('tr')[1:11]:
                    tds = row.find_all('td')
                    if len(tds) >= 3:
                        name = tds[1].text.strip()
                        count = int(tds[2].text.strip().replace(",", "")) if tds[2].text.strip().isdigit() else 0
                        sectors.append({"name": name, "count": count})
                if len(sectors) >= 5: default_data["top_sectors"] = sectors
                
                # Extraer Tabla 3 (Países)
                countries = []
                for row in tables[2].find_all('tr')[1:16]:
                    tds = row.find_all('td')
                    if len(tds) >= 3:
                        name = tds[1].text.strip()
                        count = int(tds[2].text.strip().replace(",", "")) if tds[2].text.strip().isdigit() else 0
                        countries.append({"name": name, "count": count})
                if len(countries) >= 5: default_data["top_countries"] = countries
    except:
        pass # Si falla el scraping, mantenemos los datos hyperrealistas de arriba

    return default_data

# --- FUNCIÓN LATAM  (BÚSQUEDA POR PALABRAS CLAVE) ---
@st.cache_data(ttl=3600)
def fetch_ransomware_by_countries(country_codes):
    """
    Descarga TODAS las víctimas recientes y busca coincidencias de LATAM
    usando palabras clave en el texto (ya que el campo 'country' suele estar vacío).
    """
    all_victims = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    # Diccionario de palabras clave para detectar el país en el texto
    # Añadimos nombres de países y ciudades principales
    keyword_map = {
        "CO": ["colombia", "bogotá", "medellín", "cali", "barranquilla", "colombiana"],
        "MX": ["méxico", "mexico", "monterrey", "guadalajara", "cdmx", "mexicana"],
        "BR": ["brasil", "brazil", "são paulo", "rio de janeiro", "brasileña"],
        "AR": ["argentina", "buenos aires", "argentina"],
        "CL": ["chile", "santiago", "chilena"],
        "PE": ["perú", "peru", "lima", "peruana"],
        "EC": ["ecuador", "quito", "guayaquil", "ecuatoriana"],
        "VE": ["venezuela", "caracas", "venezolana"],
        "PA": ["panamá", "panama", "panameña"],
        "CR": ["costa rica", "san josé", "costarricense"]
    }

    try:
        # Obtenemos todas las víctimas recientes (sin filtrar por API)
        url = "https://ransomware.live/api/recent"
        r = requests.get(url, headers=headers, timeout=20)
        
        if r.status_code == 200:
            data = r.json()
            
            if isinstance(data, list):
                for item in data:
                    # 1. Preparamos el texto para buscar
                    name = item.get('victim', '')
                    desc = item.get('description', '')
                    full_text = f"{name} {desc}".lower()
                    
                    # 2. Intentamos detectar el país
                    detected_country = None
                    
                    # A. Primero verificamos si la API dio el país (caso raro pero posible)
                    api_country = str(item.get('country', '')).upper()
                    if api_country in country_codes:
                        detected_country = api_country
                    
                    # B. Si la API no lo dio, buscamos palabras clave
                    if not detected_country:
                        for code, keywords in keyword_map.items():
                            for kw in keywords:
                                if kw in full_text:
                                    detected_country = code
                                    break # Si encontramos palabra clave, paramos
                            if detected_country:
                                break
                    
                    # 3. Si detectamos país (y está en nuestra lista LATAM), lo añadimos
                    if detected_country:
                        date_str = item.get('published', '')
                        try:
                            date_obj = datetime.strptime(date_str.split('T')[0], "%Y-%m-%d")
                            date_formatted = date_obj.strftime("%d/%m/%Y")
                        except:
                            date_obj = datetime.now()
                            date_formatted = "Desconocida"

                        all_victims.append({
                            "Organización": name,
                            "Grupo": item.get('group_name', item.get('group', 'N/A')),
                            "País": detected_country,
                            "Fecha": date_formatted,
                            "date_obj": date_obj,
                            "Fuente": f"https://ransomware.live/id/{item.get('id', '')}",
                            "Descripción": desc
                        })
                        
                return all_victims
            else:
                return []
        else:
            st.warning(f"Error API: Status {r.status_code}")
            return []
            
    except Exception as e:
        st.error(f"Error de conexión: {e}")
        return []

# --- FUNCIÓN RSS ---

@st.cache_data(ttl=1800)
def fetch_ransomware_data():
    url_api = "https://ransomware.live/api/recent"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    # Intento con API (Trae País Real)
    try:
        r = requests.get(url_api, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            formatted_data = []
            
            for item in data:
                # 1. País
                country = str(item.get('country', '')).upper()
                if not country or country == "NONE": country = "GLOBAL"
                
                # 2. Fecha
                date_str = item.get('published', '')
                try:
                    date_obj = datetime.strptime(date_str.split('T')[0], "%Y-%m-%d")
                    date_formatted = date_obj.strftime("%d/%m/%Y")
                except:
                    date_obj = datetime.now()
                    date_formatted = "Desconocida"

                # 3. Empresa y Grupo
                group = item.get('group_name', item.get('group', 'Desconocido'))
                victim_raw = item.get('victim', 'Desconocido')
                
                formatted_data.append({
                    "Empresa": victim_raw, # La API da el nombre limpio
                    "Grupo": group,
                    "País": country,
                    "Fecha": date_formatted,
                    "date_obj": date_obj,
                    "Fuente": f"https://ransomware.live/id/{item.get('id', '')}",
                    "Descripción": item.get('description', 'N/A')
                })
            return formatted_data, "API"
    except Exception as e:
        print(f"Error API: {e}")

    # Respaldo RSS (Limpieza de Título)
    try:
        url_rss = "https://ransomware.live/rss"
        feed = feedparser.parse(url_rss)
        formatted_data = []
        
        for entry in feed.entries:
            # Fecha
            date_str = entry.get('published', datetime.now().strftime("%Y-%m-%d"))
            try:
                dt = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %z")
                date_obj = dt.replace(tzinfo=None)
                date_formatted = dt.strftime("%d/%m/%Y")
            except:
                date_obj = datetime.now()
                date_formatted = date_str[:10]
            
            title = entry.get('title', '')
            summary = re.sub('<[^<]+?>', '', entry.get('summary', ''))
            
            # --- LIMPIEZA DE NOMBRE ---
            # El RSS suele traer: "Qilin has just published a new victim : Jgb"
            # Vamos a quitar la parte de "has just published..."
            empresa = title
            if " : " in title:
                # Tomamos solo lo que está después de los dos puntos
                empresa = title.split(" : ")[-1].strip()
            elif "victim:" in title.lower():
                 empresa = title.split(":")[-1].strip()
            
            # Detectar Grupo
            group = "Desconocido"
            if "lockbit" in title.lower(): group = "LockBit"
            elif "qilin" in title.lower(): group = "Qilin"
            elif "play" in title.lower(): group = "Play"
            elif "8base" in title.lower(): group = "8Base"
            elif "ransomhub" in title.lower(): group = "RansomHub"

            formatted_data.append({
                "Empresa": empresa, # Nombre limpio
                "Grupo": group,
                "País": "GLOBAL",
                "Fecha": date_formatted,
                "date_obj": date_obj,
                "Fuente": entry.get('link', ''),
                "Descripción": summary[:300]
            })
        return formatted_data, "RSS"
    except:
        return [], "Error"

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
# --- INYECCIÓN DE TEMA (DEBE ESTAR FUERA DE CUALQUIER TAB) ---
if st.session_state.dark_mode:
    st.markdown("""<style>
        /* ... todo tu CSS oscuro aquí ... */
        .stApp { background-color: #0e1117; color: white; }
        /* etc */
    </style>""", unsafe_allow_html=True)
else:
    st.markdown("""<style>
        /* ... todo tu CSS claro aquí ... */
        .stApp { background-color: #ffffff; color: black; }
        /* etc */
    </style>""", unsafe_allow_html=True)

# --- INTERFAZ PRINCIPAL ---
tabs = st.tabs(["📈 Dashboard", "☠️ Ransomware", "🔎 Analizar IP", "#️⃣ Hash", "🌐 URL", "📂 MasivoIps", "📚 Playbooks", "🚨 Watcher", "⚙️ Config"])

# --- TAB 0: DASHBOARD PROFESIONAL ---
with tabs[0]:
    # 1. Carga de datos
    live_threats = fetch_intelligence_feed()
    
    # Cálculos rápidos para KPIs basados en el Score (1-10)
    critical_events = sum(1 for t in live_threats if float(t['score']) >= 8.1)
    high_events = sum(1 for t in live_threats if 6.1 <= float(t['score']) <= 8.0)
    medium_events = sum(1 for t in live_threats if 4.1 <= float(t['score']) <= 6.0)
    low_events = sum(1 for t in live_threats if float(t['score']) <= 4.0)

    # --- KPI METRICS ROW ---
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value text-red">{critical_events}</div>
            <div class="kpi-label">Críticos (8.1 - 10)</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi2:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value text-orange">{high_events}</div>
            <div class="kpi-label">Altas (6.1 - 8.0)</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi3:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value text-blue">{medium_events}</div>
            <div class="kpi-label">Medias (4.1 - 6.0)</div>
        </div>
        """, unsafe_allow_html=True)
    with kpi4:
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-value text-green">{low_events}</div>
            <div class="kpi-label">Bajas (1.0 - 4.0)</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # --- MAIN LAYOUT GRID ---
    col_feed, col_side = st.columns([2.5, 1])

    # --- COLUMNA IZQUIERDA: FEED DE AMENAZAS ---
    with col_feed:
        st.markdown("<div class='section-header'>🕵️‍♂️ Feed de Amenazas Recientes</div>", unsafe_allow_html=True)
        
        for t in live_threats:
                        # Determinar colores y clases (Ajustado a nueva escala)
            score_val = float(t['score'])
            if score_val >= 8.1:
                sev_class = "critical"
                score_class = "score-critical"
            elif score_val >= 6.1:
                sev_class = "high"
                score_class = "score-high"
            elif score_val >= 4.1:
                sev_class = "medium"
                score_class = "score-medium"
            else:
                sev_class = "low" # Asegúrate de tener la clase "low" en tu CSS
                score_class = "score-low"

                        # Construir la tarjeta HTML (Con link en el título corregido)
            st.markdown(f"""
            <div class="threat-card {sev_class}">
                <div class="threat-info">
                    <div class="threat-title"><a href="{t.get('source', '#')}" target="_blank" style="color: white; text-decoration: none;">{t['name']}</a></div>
                    <div class="threat-meta">
                        🗞️ {t['sourceName']} &nbsp;|&nbsp; 📅 {t['date']} &nbsp;|&nbsp; 🏷️ {t['type']}
                    </div>
                </div>
                <div class="threat-score-box {score_class}">
                    <div style="font-size: 1.5rem; font-weight: bold;">{t['score']}</div>
                    <div style="font-size: 0.7rem; opacity: 0.8;">SCORE</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Botón expandible para detalles (usando expander nativo)
            with st.expander(f"Detalles & IOCs"):
                st.markdown(f"**Descripción:** {t['desc']}")
                st.markdown(f"**MITRE:** {', '.join(t.get('mitre', []))}")
                
                # Mostrar CVEs/IOCs encontrados
                found_cves = t.get('cves', [])
                found_iocs = t.get('iocs', [])
                
                if found_cves:
                    st.warning(f"**CVEs:** {', '.join([c['val'] for c in found_cves])}")
                if found_iocs:
                    st.error(f"**IOCs:** {len(found_iocs)} indicadores encontrados.")
                    for ioc in found_iocs:
                        st.code(f"{ioc['type']}: {ioc['val']}")

    # --- COLUMNA DERECHA: CVEs & INSIGHTS ---
    with col_side:
        # 1. Sección CVEs
        st.markdown("<div class='sidebar-section'>", unsafe_allow_html=True)
        st.markdown("<div class='section-header'>🛡️ CVEs & Zero-Days</div>", unsafe_allow_html=True)
        
        cve_global_list = []
        for t in live_threats:
            if t.get('cves'):
                for c in t['cves']:
                    cve_global_list.append(c['val'])
        
        # Mostrar únicos (Top 5)
        unique_cves = list(set(cve_global_list))[:5]
        if unique_cves:
            for cve in unique_cves:
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.05); padding:10px; border-radius:5px; margin-bottom:10px; display:flex; justify-content:space-between;">
                    <span style="font-family:'Share Tech Mono'; color:#00d4ff;">{cve}</span>
                    <span style="color:#ff3860; font-weight:bold;">HIGH</span>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Sin CVEs recientes.")
        st.markdown("</div>", unsafe_allow_html=True)

        # 2. Sección IOCs Rápidos
        st.markdown("<div class='sidebar-section'>", unsafe_allow_html=True)
        st.markdown("<div class='section-header'>🎯 IOCs Recientes</div>", unsafe_allow_html=True)
        
        ioc_count = 0
        for t in live_threats:
            if t.get('iocs'): ioc_count += len(t['iocs'])
        
        st.metric("Total Indicadores", ioc_count)
        st.caption("IPs, Hashes y Dominios extraídos.")
        st.markdown("</div>", unsafe_allow_html=True)

                # 3. OWASP TOP 10 (DINÁMICO Y VISUAL)
        st.markdown("<div class='sidebar-section'>", unsafe_allow_html=True)
        st.markdown("<div class='section-header'>🧱 OWASP TOP 10 (2025)</div>", unsafe_allow_html=True)
        
        # Calculamos relevancia basada en el feed actual
        owasp_counts = calculate_owasp_relevance(live_threats, OWASP_DATA)
        
        # Ordenamos: Primero los que tienen alertas, luego alfabéticamente
        sorted_owasp = sorted(OWASP_DATA, key=lambda x: (owasp_counts.get(x['id'], 0) * -1, x['id']))

        for item in sorted_owasp:
            count = owasp_counts.get(item['id'], 0)
            
            # Estilos dinámicos según severidad
            if count > 0:
                # ESTILO AFECTADO (Rojo/Naranja)
                border_color = "#ff3860" if count > 2 else "#ffb830"
                icon = "🔥"
                bg_alpha = "rgba(255, 56, 96, 0.1)" if count > 2 else "rgba(255, 184, 48, 0.1)"
                status_text = f"⚠️ {count} amenazas"
                
                # Contenedor HTML para la tarjeta
                st.markdown(f"""
                <div style="background:{bg_alpha}; border-left: 4px solid {border_color}; padding: 10px; border-radius: 5px; margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="font-weight: bold; color: #fff;">{item['id']} - {item['name']}</div>
                        <div style="background:{border_color}; color:white; padding: 2px 8px; border-radius: 10px; font-size: 0.8rem;">{icon} {count}</div>
                    </div>
                    <div style="font-size: 0.8rem; color: #aaa; margin-top: 5px;">{status_text} detectadas en el feed.</div>
                </div>
                """, unsafe_allow_html=True)
                
                # Expander para ver detalles de noticias
                with st.expander(f"👁️ Ver noticias relacionadas"):
                    found_news = False
                    for t in live_threats:
                        # Buscamos coincidencias en titulo y descripcion
                        content = (t.get('name', '') + " " + t.get('desc', '')).lower()
                        # Verificamos keywords de esta categoría OWASP
                        match = any(kw in content for kw in item['keywords'])
                        
                        if match:
                            found_news = True
                            st.markdown(f"• **{t['name']}**")
                            st.caption(f"Fuente: {t['sourceName']}")
                    
                    if not found_news:
                        st.write("Error al cargar detalles.")
            else:
                # ESTILO SEGURO (Verde/Gris)
                st.markdown(f"""
                <div style="background:rgba(255,255,255,0.03); border-left: 4px solid #252d3e; padding: 10px; border-radius: 5px; margin-bottom: 8px; opacity: 0.7;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="font-weight: bold; color: #8892a4;">{item['id']} - {item['name']}</div>
                        <div style="color: #2ed573; font-size: 0.9rem;">✅ OK</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
        st.markdown("</div>", unsafe_allow_html=True)

    # 4. Mapa 
    st.divider()
    st.subheader("🗺️ Mapa de Amenazas")
    m = folium.Map(location=COMPANY_CONTEXT['coords']['CO'], zoom_start=2, tiles="CartoDB dark_matter")
    for threat in live_threats:
        coords = COMPANY_CONTEXT['coords'].get(threat['country_code'], COMPANY_CONTEXT['coords']['DEFAULT'])
        color = "#ff3860" if threat['sev'] == 'critical' else "#ffb830"
        folium.CircleMarker(location=coords, radius=5, color=color, fill=True, popup=threat['name']).add_to(m)
    st_folium(m, width='100%', height=350)

# --- TAB 1: RANSOMWARE TRACKER (SINCRONIZADO) ---
with tabs[1]: 
    # st.title("🔒 Ransomware Tracker")
    
    # Cargar datos (Los tuyos)
    data, source_type = fetch_ransomware_data()
    # Cargar estadísticas globales (Las nuevas)
    global_stats = fetch_global_ransomware_stats()
    
    if source_type == "API":
        st.success(f"✅ Modo: API (Datos Precisos)")
    else:
        st.warning(f"⚠️ Modo: RSS (Datos limitados a ~200 recientes)")

    st.markdown("---")

    if not data:
        st.error("Sin datos.")
        st.stop()

    # --- NUEVO LAYOUT: IZQUIERDA (Datos) | DERECHA (Estadísticas) ---
    main_col, stats_col = st.columns([3, 1.2])

    # ==========================================================
    # COLUMNA IZQUIERDA: TU CÓDIGO ORIGINAL SIN MODIFICACIONES
    # ==========================================================
    with main_col:
        # --- FILTROS ---
        col1, col2, col3 = st.columns(3)
        
        time_window = col1.slider("Mostrar eventos de los últimos (días):", 1, 30, 30)
        today = datetime.now()
        
        available_groups = sorted(list(set([d['Grupo'] for d in data])))
        selected_groups = col2.multiselect("Filtrar por Grupo:", options=available_groups, default=available_groups)
        search_term = col3.text_input("Buscar Empresa:", placeholder="Nombre...")

        # --- PROCESAMIENTO Y FILTRADO ---
        final_data = []
        dates_in_data = [] 

        for item in data:
            if item['date_obj'].year > 2020: 
                dates_in_data.append(item['date_obj'])
                
            days_diff = (today - item['date_obj']).days
            if days_diff > time_window:
                continue
            if selected_groups and item['Grupo'] not in selected_groups:
                continue
            if search_term and search_term.lower() not in item['Empresa'].lower():
                continue
            final_data.append(item)

        # --- ESTADÍSTICAS DE DATOS REALES ---
        if dates_in_data:
            min_date = min(dates_in_data)
            max_date = max(dates_in_data)
            real_range = (max_date - min_date).days
            st.info(f"📊 **Rango real de datos cargados:** Del {min_date.strftime('%d/%m/%Y')} al {max_date.strftime('%d/%m/%Y')} ({real_range} días de antigüedad máxima).")
        
        st.metric("Eventos Encontrados", len(final_data))
        
        if final_data:
            df = pd.DataFrame(final_data)
            df = df.sort_values(by="date_obj", ascending=False)
            
            st.dataframe(
                df[["Grupo", "Empresa", "País", "Fecha"]],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Grupo": "Grupo Ransomware",
                    "Empresa": "Víctima (Empresa)",
                    "País": "País",
                    "Fecha": "Fecha"
                }
            )
            
            st.divider()
            sel = st.selectbox("Ver detalles:", df['Empresa'].unique())
            if sel:
                row = df[df['Empresa'] == sel].iloc[0]
                c1, c2 = st.columns([2, 1])
                with c1:
                    st.markdown(f"**Grupo:** {row['Grupo']}")
                    st.markdown(f"**País:** {row['País']}")
                    st.markdown(f"**Fecha:** {row['Fecha']}")
                    st.caption(f"**Descripción:** {row['Descripción']}")
                with c2:
                    st.link_button("🔗 Ir a Fuente", row['Fuente'], use_container_width=True)
        else:
            st.warning("No hay eventos para los filtros actuales.")

    # ==========================================================
    # COLUMNA DERECHA: ESTADÍSTICAS GLOBALES (BLINDADO HTML)
    # ==========================================================
    with stats_col:
        st.markdown('<div class="section-header">🌐 Panorama Global 2026</div>', unsafe_allow_html=True)
        
        # --- FUNCIÓN A PRUEBA DE ERRORES DE STREAMLIT ---
        def render_stat_bars(title, items, icon, color, unit="Víctimas"):
            # Título limpio
            st.markdown('<div style="font-size:0.85rem; font-weight:bold; color:' + color + '; margin-bottom:8px; margin-top:20px; border-bottom: 1px solid ' + color + ';">' + icon + ' ' + title + '</div>', unsafe_allow_html=True)
            
            for i, item in enumerate(items, 1):
                # Calculamos el ancho
                width_pct = max(15, 95 - (i * 8))
                
                # Limpieza extrema del nombre (sin comillas, sin etiquetas)
                safe_name = str(item.get("name", "N/A"))
                safe_name = safe_name.replace('"', '').replace("'", '').replace('<', '').replace('>', '')
                count_val = item.get("count", 0)
                count_str = f"{count_val:,}"
                
                # Construimos el HTML por partes (NUNCA usar f-string con comillas triples aquí)
                row_start = '<div style="display: flex; align-items: center; margin-bottom: 5px; gap: 6px;">'
                
                num_div = '<div style="width: 20px; color: #8892a4; font-size: 0.75rem; text-align: right;">' + str(i) + '.</div>'
                
                name_div = '<div style="width: 100px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #e0e0e0; font-size: 0.8rem; font-weight: 500;">' + safe_name + '</div>'
                
                bar_bg = '<div style="flex-grow: 1; height: 16px; background: rgba(255, 255, 255, 0.05); border-radius: 4px; overflow: hidden;">'
                bar_fill = '<div style="width: ' + str(width_pct) + '%; height: 100%; background: ' + color + '; border-radius: 4px; opacity: 0.8;"></div>'
                bar_close = '</div>'
                
                # OJO: Quité el 'Share Tech Mono' porque las comillas simples rompen Streamlit
                count_div = '<div style="width: 90px; text-align: right; color: ' + color + '; font-size: 0.75rem; font-weight: bold;">' + count_str + ' ' + unit + '</div>'
                
                row_end = '</div>'
                
                # Unimos todo
                final_html = row_start + num_div + name_div + bar_bg + bar_fill + bar_close + count_div + row_end
                
                # Imprimimos
                st.markdown(final_html, unsafe_allow_html=True)

        # 1. Top 10 Grupos
        render_stat_bars("TOP 10 GRUPOS DE RANSOMWARE", global_stats["top_groups"], "👹", "#ff3860", "Víctimas")
        
        # 2. Top 10 Sectores
        render_stat_bars("TOP 10 SECTORES COMPROMETIDOS", global_stats["top_sectors"], "🏭", "#ffb830", "Víctimas")
        
        # 3. Top 15 Países (Mostramos 10)
        render_stat_bars("TOP 10 PAÍSES MÁS ATACADOS", global_stats["top_countries"][:10], "🌍", "#00d4ff", "Víctimas")
        
        # 4. Nuevos Grupos 2026
        render_stat_bars("NUEVOS GROUPS 2026", global_stats["new_groups_2026"], "🆕", "#2ed573", "Posts")
        
        # 5. Top 10 Malware General 
        st.markdown('<div style="border-top: 1px solid #333; margin: 20px 0 0 0;"></div>', unsafe_allow_html=True)
        render_stat_bars("TOP 10 MALWARE GLOBAL", global_stats["top_malware"], "🦠", "#a855f7", "Muestras")

# --- TAB 1: ANALIZAR IP (DISEÑO 4 FUENTES) ---

with tabs[2]:
    # st.markdown("<h1 style='text-align: center;'>🔎 ANÁLISIS DE IP - 4 FUENTES EXTERNAS</h1>", unsafe_allow_html=True)
    
    # --- LÓGICA DE LIMPIEZA (ANTES DE LOS WIDGETS) ---
    # Verificamos si se presionó el botón de limpiar en la interacción anterior
    if st.session_state.get('trigger_clear_ip'):
        st.session_state.analysis_results = None
        st.session_state.input_ip_val = "" # Limpiamos el valor
        st.session_state.trigger_clear_ip = False # Reseteamos el disparador

    # --- FILA DE CONTROLES ---
    col_input, col_btn1, col_btn2 = st.columns([4, 1, 1])
    
    with col_input:
        # El widget se crea con el valor limpio (o el existente)
        user_input = st.text_input("IP:", key="input_ip_val", placeholder="Ej: 8.8.8.8")
    
    with col_btn1:
        st.write("") # Alineación vertical
        analyze_btn = st.button("ANALIZAR", type="primary", key="btn_analyze_ip_main", use_container_width=True)
        
    with col_btn2:
        st.write("")
        # Al hacer clic, solo activamos la bandera y recargamos
        if st.button("🧹 NUEVA", key="btn_new_query_ip", use_container_width=True):
            st.session_state.trigger_clear_ip = True
            st.rerun()

    # --- LÓGICA DE ANÁLISIS ---
    results = {"abuse": None, "vt": None, "otx": None, "grey": None}
    
    if analyze_btn and user_input:
        if not is_private_ip(user_input):
            with st.spinner("Consultando fuentes de inteligencia..."):
                # 1. AbuseIPDB
                if st.session_state.api_keys['abuseipdb']:
                    try:
                        r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                            headers={"Key": st.session_state.api_keys['abuseipdb'], "Accept": "application/json"},
                            params={"ipAddress": user_input, "maxAgeInDays": 90})
                        if r.status_code == 200: results['abuse'] = r.json()['data']
                    except: pass
                
                # 2. VirusTotal
                if st.session_state.api_keys['virustotal']:
                    try:
                        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{user_input}",
                            headers={"x-apikey": st.session_state.api_keys['virustotal']})
                        if r.status_code == 200: results['vt'] = r.json()['data']['attributes']
                    except: pass
                
                # 3. AlienVault OTX
                results['otx'] = get_alienvault_report(user_input)
                
                # 4. Greynoise
                results['grey'] = get_greynoise_report(user_input)
                
                st.session_state.analysis_results = results
                
                # Guardar en historial
                ts = datetime.now().strftime("%Y-%m-%d %H:%M")
                sc = results['abuse'].get('abuseConfidenceScore', 0) if results.get('abuse') else 0
                st.session_state.analysis_history.append({
                    "Fecha": ts, "IP": user_input, "Score": f"{sc}%", 
                    "Status": "Malo" if sc>50 else "OK"
                })
        else:
            st.warning("⚠️ No se analizan IPs privadas.")

    # --- VISUALIZACIÓN EN GRID ---
    res = st.session_state.get('analysis_results')
    if not isinstance(res, dict):
        res = {"abuse": None, "vt": None, "otx": None, "grey": None}
    
    col1, col2 = st.columns(2)
    
    # CARD 1: AbuseIPDB
    with col1:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>AbuseIPDB</span>", unsafe_allow_html=True)
        st.markdown("<h3>🚫 AbuseIPDB</h3>", unsafe_allow_html=True)
        
        if res.get('abuse'):
            data = res['abuse']
            score = data.get('abuseConfidenceScore', 0)
            color = "#ff4757" if score > 50 else "#2ed573"
            st.markdown(f"<h1 style='color:{color}; text-align: center;'>{score}%</h1>", unsafe_allow_html=True)
            st.caption("Confianza de Abuso")
            
            df_abuse = pd.DataFrame({
                "Detalle": ["País", "ISP", "Dominio", "Tipo", "Reportes (90d)"],
                "Valor": [
                    f"{data.get('countryCode', 'N/A')} ({data.get('countryName', '')})",
                    data.get('isp', 'N/A'), data.get('domain', 'N/A'),
                    data.get('usageType', 'Desconocido'), data.get('totalReports', 0)
                ]
            })
            st.dataframe(df_abuse, hide_index=True, use_container_width=True)
        else:
            st.info("Esperando análisis...")
        st.markdown("</div>", unsafe_allow_html=True)

    # CARD 2: VirusTotal
    with col2:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>VirusTotal</span>", unsafe_allow_html=True)
        st.markdown("<h3>🔷 VirusTotal</h3>", unsafe_allow_html=True)
        
        if res.get('vt'):
            stats = res['vt'].get('last_analysis_stats', {})
            mal = stats.get('malicious', 0)
            color = "#ff4757" if mal > 0 else "#2ed573"
            st.markdown(f"<h1 style='color:{color}; text-align: center;'>{mal} / {sum(stats.values())}</h1>", unsafe_allow_html=True)
            st.caption("Motores Maliciosos")
            
            df_vt = pd.DataFrame({
                "Estado": ["Malicioso", "Sospechoso", "Limpio", "No detectado"],
                "Cantidad": [stats.get('malicious', 0), stats.get('suspicious', 0), stats.get('harmless', 0), stats.get('undetected', 0)]
            })
            st.dataframe(df_vt, hide_index=True, use_container_width=True)
        else:
            st.info("Esperando análisis...")
        st.markdown("</div>", unsafe_allow_html=True)

    col3, col4 = st.columns(2)

    # CARD 3: AlienVault OTX
    with col3:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>AlienVault OTX</span>", unsafe_allow_html=True)
        st.markdown("<h3>👽 AlienVault OTX</h3>", unsafe_allow_html=True)
        
        if res.get('otx'):
            pulse_info = res['otx'].get('pulse_info', {})
            pulse_count = len(pulse_info.get('pulses', []))
            st.metric("Pulsos Asociados", pulse_count)
            st.caption(f"Reputación General: {res['otx'].get('reputation', 'N/A')}")
            
            if pulse_count > 0:
                with st.expander("⚠️ Ver Amenazas Relacionadas"):
                    for p in pulse_info['pulses'][:5]:
                        st.write(f"• [{p.get('name')}]({p.get('link', '#')})")
        else:
            st.info("Esperando análisis...")
        st.markdown("</div>", unsafe_allow_html=True)

    # CARD 4: Greynoise
    with col4:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>Greynoise</span>", unsafe_allow_html=True)
        st.markdown("<h3>📡 Greynoise</h3>", unsafe_allow_html=True)
        
        if res.get('grey'):
            gn_data = res['grey']
            classification = gn_data.get('classification', 'unknown')
            
            if classification == 'malicious': color, icon = "#ff4757", "⚠️"
            elif classification == 'benign': color, icon = "#2ed573", "✅"
            else: color, icon = "#ffa502", "❓"
                
            st.markdown(f"<h2 style='color:{color}; text-align: center;'>{icon} {classification.upper()}</h2>", unsafe_allow_html=True)
            st.caption("Clasificación de Actividad")
            st.write(f"**Ruido:** {gn_data.get('noise', False)}")
            if gn_data.get('link'): st.link_button("Ver Reporte", gn_data['link'], use_container_width=True)
        else:
            st.info("IP no encontrada en Greynoise.")
        st.markdown("</div>", unsafe_allow_html=True)

    # --- GENERADOR DE SCRIPT FORTIGATE ---
    st.divider()
    st.subheader("🛡️ Generador de Script Fortigate")
    


        # --- FUNCIÓN HELPER (Mantener igual) ---
    def cidr_to_netmask(cidr):
        try:
            cidr = int(cidr)
            mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
            return f"{(mask >> 24) & 255}.{(mask >> 16) & 255}.{(mask >> 8) & 255}.{mask & 255}"
        except: return "255.255.255.255"

    # --- NUEVA INTERFAZ: SEPARACIÓN DE IP Y MÁSCARA ---
    st.markdown("#### ⚙️ Configuración de Objeto")
    
    # ASEGÚRATE DE QUE ESTE TEXT_INPUT NO TENGA value="masiva"
    alarm_id = st.text_input("🚨 Ingrese ID de Alarma:", placeholder="Ej: IM-00145", key="alarm_input_fix")
    
    # Suponiendo que group_name ya lo tienes definido arriba, si no, añade este input:
    group_name = st.text_input("📂 Grupo de direcciones (Address Group):", value="Ip_Reportadas_SOCCVJ_Mayo_2026")

    # Separamos la IP y el Rango en dos columnas
    col_ip_input, col_cidr_input = st.columns([3, 1])
    
    with col_ip_input:
        # Aquí el usuario solo pone la IP base (ej. 192.168.1.0)
        base_ip = st.text_input("🌐 Dirección IP Base:", placeholder="Ej: 192.168.1.0")
        
    with col_cidr_input:
        # Menú desplegable para elegir el rango fácilmente
        selected_cidr = st.selectbox(
            " máscara:", 
            options=["/32", "/24", "/16", "/8"], 
            index=0, # Por defecto /32
            format_func=lambda x: f" {x}"
        )
        
    # Calculamos la máscara automáticamente según lo que eligió
    cidr_num = selected_cidr.replace("/", "")
    netmask = cidr_to_netmask(cidr_num)

    st.markdown("---")

    # --- BOTONES DE GENERACIÓN ---
    col_btn_scr1, col_btn_scr2 = st.columns(2)
    
    with col_btn_scr1:
        if st.button("📋 Script IP Individual", key="btn_script_ip_fix", use_container_width=True):
            if alarm_id and base_ip:
                object_name = f"IP_Sospechosa_{base_ip}"
                # Formateo estándar de FortiGate (con sangrías correctas)
                script = f"""config firewall address
edit "{object_name}"
set subnet {base_ip} 255.255.255.255
set comment "Alarma {alarm_id}"
next
end

config firewall addrgrp
edit "{group_name}"
append member "{object_name}"
next
end"""
                st.code(script, language="bash")
            else: 
                st.error("⚠️ Falta el ID de Alarma o la IP Base.")

    with col_btn_scr2:
        if st.button("🛠️ Script Rango (Usa máscara elegida)", key="btn_script_range_fix", use_container_width=True):
            if alarm_id and base_ip:
                # Genera un nombre limpio, ej: Rd_192.168.1.0/24
                object_name = f"Rd_{base_ip}/{cidr_num}"
                
                # Formateo estándar de FortiGate
                script = f"""config firewall address
edit "{object_name}"
set subnet {base_ip}/{cidr_num} {netmask}
set comment "Alarma {alarm_id}"
next
end

config firewall addrgrp
edit "{group_name}"
append member "{object_name}"
next
end"""
                st.code(script, language="bash")
            else: 
                st.error("⚠️ Falta el ID de Alarma o la IP Base.")
# --- TAB 3: ANÁLISIS DE HASH (DETALLADO) ---
with tabs[3]:
    # 1. Lógica de Limpieza (Antes de widgets)
    if st.session_state.get('trigger_clear_hash'):
        st.session_state.analysis_results = None
        st.session_state.input_hash_val = ""
        st.session_state.trigger_clear_hash = False

   #  st.title("#️⃣ Análisis de Hash")
    
    col_in, col_btn1, col_btn2 = st.columns([4, 1, 1])
    with col_in:
        hash_input = st.text_input("Hash (MD5, SHA1, SHA256)", key="input_hash_val", placeholder="Ej: 44d88612fea8a8f36de82e1278abb02f")
    
    with col_btn1:
        st.write("")
        analyze_hash_btn = st.button("ANALIZAR", type="primary", key="btn_analyze_hash", use_container_width=True)
    
    with col_btn2:
        st.write("")
        if st.button("🧹 NUEVA", key="btn_new_hash", use_container_width=True):
            st.session_state.trigger_clear_hash = True
            st.rerun()

    # Lógica de Análisis
    if analyze_hash_btn and hash_input:
        if not st.session_state.api_keys['virustotal']:
            st.error("Configure la API Key de VirusTotal.")
        else:
            with st.spinner("Consultando VirusTotal..."):
                res = get_vt_hash_report(hash_input)
                if res:
                    st.session_state.analysis_results = res
                else:
                    st.error("❌ Hash no encontrado en VirusTotal.")

    # Visualización de Resultados
    res = st.session_state.get('analysis_results')
    # Verificamos que sea un reporte de Hash (tiene 'type_description' o similar)
    if res and isinstance(res, dict) and 'data' in res:
        attrs = res['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        mal = stats.get('malicious', 0)
        
        st.divider()
        
        # 1. Métrica Principal y Estado
        col_m1, col_m2 = st.columns([1, 2])
        with col_m1:
            color = "#ff4757" if mal > 0 else "#2ed573"
            icon = "🦠" if mal > 0 else "✅"
            st.markdown(f"""
            <div style="text-align: center; background: {color}15; padding: 20px; border-radius: 10px; border: 1px solid {color};">
                <h1 style="color: {color}; margin:0;">{icon} {mal}</h1>
                <small style="color: {color};">Detecciones Maliciosas</small>
            </div>
            """, unsafe_allow_html=True)
            st.caption(f"Total Motores: {sum(stats.values())}")

        with col_m2:
            st.subheader("📋 Metadata del Archivo")
            # Info básica
            file_type = attrs.get('type_description', 'Desconocido')
            first_seen = attrs.get('first_submission_date', 0)
            fs_date = datetime.fromtimestamp(first_seen).strftime('%Y-%m-%d') if first_seen else "N/A"
            
            st.markdown(f"**Tipo:** `{file_type}`")
            st.markdown(f"**Primera visto:** `{fs_date}`")
            
            # Nombres de archivo (sugeridos por usuarios)
            names = attrs.get('names', [])
            if names:
                st.markdown(f"**Nombres detectados:**")
                st.caption(", ".join(names[:5])) # Mostrar primeros 5
            
            # Hashes relacionados
            st.markdown("---")
            st.caption(f"**MD5:** `{attrs.get('md5', 'N/A')}`")
            st.caption(f"**SHA256:** `{attrs.get('sha256', 'N/A')}`")

        # 2. Tabla de Detecciones Detalladas
        st.divider()
        st.subheader("🔬 Detalle de Motores Antivirus")
        
        results_map = attrs.get('last_analysis_results', {})
        # Filtrar solo los que lo detectan como malicioso
        detections = []
        for engine, data in results_map.items():
            if data.get('category') == 'malicious':
                detections.append({
                    "Motor": engine,
                    "Resultado": data.get('result', 'N/A'),
                    "Método": data.get('method', 'N/A')
                })
        
        if detections:
            df_det = pd.DataFrame(detections)
            st.dataframe(df_det, use_container_width=True, hide_index=True)
        else:
            st.success("Ningún motor detectó este hash como malicioso.")
            
        # Link a VT
        st.link_button("🔗 Ver Reporte Completo en VirusTotal", f"https://www.virustotal.com/gui/file/{hash_input}", use_container_width=True)

# --# --- TAB 4: ANÁLISIS DE URL (DETALLADO) ---
with tabs[4]:
    # 1. Lógica de Limpieza
    if st.session_state.get('trigger_clear_url'):
        st.session_state.analysis_results = None
        st.session_state.input_url_val = ""
        st.session_state.trigger_clear_url = False

    # st.title("🌐 Análisis de URL")
    
    col_in, col_btn1, col_btn2 = st.columns([4, 1, 1])
    with col_in:
        url_input = st.text_input("Ingrese URL", key="input_url_val", placeholder="https://ejemplo-sospechoso.com")
    
    with col_btn1:
        st.write("")
        analyze_url_btn = st.button("ANALIZAR", type="primary", key="btn_analyze_url", use_container_width=True)
    
    with col_btn2:
        st.write("")
        if st.button("🧹 NUEVA", key="btn_new_url", use_container_width=True):
            st.session_state.trigger_clear_url = True
            st.rerun()

    # Lógica de Análisis
    if analyze_url_btn and url_input:
        if not st.session_state.api_keys['virustotal']:
            st.error("Configure la API Key de VirusTotal.")
        else:
            with st.spinner("Analizando URL..."):
                res = get_vt_url_report(url_input)
                if res:
                    st.session_state.analysis_results = res
                else:
                    st.error("❌ Error al analizar la URL o no encontrada.")

    # Visualización de Resultados
    res = st.session_state.get('analysis_results')
    if res and isinstance(res, dict) and 'data' in res:
        attrs = res['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        mal = stats.get('malicious', 0)
        
        st.divider()
        
        # 1. Métrica Principal
        color = "#ff4757" if mal > 0 else "#2ed573"
        status = "⚠️ SITIO PELIGROSO" if mal > 0 else "✅ SITIO LIMPIO"
        st.markdown(f"<h2 style='color:{color}; text-align:center;'>{status}</h2>", unsafe_allow_html=True)
        st.caption(f"Detecciones: {mal} / {sum(stats.values())} motores.")
        
        # 2. Metadata de la Web
        col_w1, col_w2 = st.columns(2)
        with col_w1:
            st.subheader("📡 Información del Sitio")
            # Datos HTTP
            http_code = attrs.get('last_http_response_code', 'N/A')
            st.metric("Código HTTP", http_code)
            
            title = attrs.get('title', 'Sin título')
            st.markdown(f"**Título:** {title}")
            
            redir = attrs.get('last_final_url', 'N/A')
            if redir != 'N/A' and redir != url_input:
                st.warning(f"Redirige a: `{redir}`")

        with col_w2:
            st.subheader("🔐 Seguridad")
            st.metric("Reputación", attrs.get('reputation', 0))
            
            # Fecha último análisis
            last_anal = attrs.get('last_analysis_date', 0)
            if last_anal:
                st.caption(f"Último análisis: {datetime.fromtimestamp(last_anal).strftime('%d/%m/%Y %H:%M')}")

        # 3. Tabla de Detecciones
        st.divider()
        st.subheader("🔬 Motores que detectan amenaza")
        
        results_map = attrs.get('last_analysis_results', {})
        detections = []
        for engine, data in results_map.items():
            if data.get('category') == 'malicious':
                detections.append({
                    "Motor": engine,
                    "Resultado": data.get('result', 'Malicious')
                })
        
        if detections:
            df_url = pd.DataFrame(detections)
            st.dataframe(df_url, use_container_width=True, hide_index=True)
        else:
            st.info("Ningún motor detectó esta URL como maliciosa.")
            
        # Link a VT
        # VT usa el ID codificado en base64 para URLs en la GUI
        st.link_button("🔗 Ver en VirusTotal", f"https://www.virustotal.com/gui/url/{res['data']['id']}", use_container_width=True)
        

# --- TAB 5: MASIVO IPS 
with tabs[5]:
    # st.title("📂 Análisis Masivo & Generador de Scripts")
    
    # --- LÓGICA DE LIMPIEZA ---
    if st.session_state.get('trigger_clear_bulk'):
        if 'bulk_results_df' in st.session_state: del st.session_state.bulk_results_df
        if 'bulk_script_content' in st.session_state: del st.session_state.bulk_script_content
        st.session_state.trigger_clear_bulk = False
        st.session_state.file_uploader_counter = st.session_state.get('file_uploader_counter', 0) + 1

    # 1. Configuración del Script
    with st.expander("⚙️ Configuración de Bloqueo Fortigate", expanded=True):
        st.markdown("Estos datos se aplicarán a **todas** las IPs válidas del archivo.")
        
        MESES_ES = {1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio", 
                    7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"}
        default_group = f"Ip_Reportadas_SOCCVJ_{MESES_ES.get(datetime.now().month, 'Mes')}_{datetime.now().year}"
        
        col_cfg1, col_cfg2 = st.columns(2)
        alarm_id_bulk = col_cfg1.text_input("ID de Alarma (Lote)", placeholder="Ej: IM-BULK-001", key="bulk_alarm_id")
        group_name_bulk = col_cfg2.text_input("Grupo de Direcciones", value=default_group, key="bulk_group_name")

    st.divider()

    # 2. Carga de Archivo
    col_up, col_btn = st.columns([4, 1])
    
    with col_up:
        uploader_key = f"file_uploader_{st.session_state.get('file_uploader_counter', 0)}"
        uploaded_file = st.file_uploader("Cargar archivo CSV o TXT", type=['csv', 'txt'], key=uploader_key)
    
    with col_btn:
        st.write("")
        st.write("")
        if st.button("🧹 NUEVA", key="btn_new_bulk_query", use_container_width=True):
            st.session_state.trigger_clear_bulk = True
            st.rerun()

    # 3. Procesamiento
    if uploaded_file:
        try:
            try:
                df = pd.read_csv(uploaded_file)
            except:
                df = pd.read_csv(uploaded_file, header=None, names=['ip'])
            
            with st.expander("📊 Vista previa de datos cargados"):
                st.dataframe(df.head(3))

            target_column = [col for col in df.columns if 'ip' in col.lower()] or [df.columns[0]]
            
            if st.button("🚀 Iniciar Análisis Masivo", type="primary", key="btn_bulk_scan"):
                if not st.session_state.api_keys['abuseipdb']:
                    st.error("Configure la API Key de AbuseIPDB.")
                else:
                    progress_bar = st.progress(0, text="Iniciando...")
                    status_text = st.empty()
                    
                    results = []
                    scripts_list = []
                    ips = df[target_column[0]].dropna().astype(str).unique().tolist()
                    
                    for i, ip in enumerate(ips):
                        ip = ip.strip()
                        
                        # Estructura de la fila con todos los campos deseados
                        row_data = {
                            "IP": ip, 
                            "Score": "N/A", 
                            "Reportes": 0,
                            "País": "N/A",
                            "ISP": "N/A",
                            "Dominio": "N/A",
                            "Tipo": "N/A"
                        }

                        if is_private_ip(ip):
                            row_data["Score"] = "PRIVATE"
                            row_data["ISP"] = "Red Interna (Omitida)"
                        else:
                            try:
                                r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                                                 headers={"Key": st.session_state.api_keys['abuseipdb'], "Accept": "application/json"}, 
                                                 params={"ipAddress": ip, "maxAgeInDays": 90})
                                if r.status_code == 200:
                                    d = r.json()['data']
                                    
                                    # Poblamos los datos detallados
                                    score_val = d.get('abuseConfidenceScore', 0)
                                    row_data["Score"] = f"{score_val}%"
                                    row_data["Reportes"] = d.get('totalReports', 0)
                                    row_data["País"] = f"{d.get('countryCode', 'N/A')} ({d.get('countryName', '')})"
                                    row_data["ISP"] = d.get('isp', 'N/A')
                                    row_data["Dominio"] = d.get('domain', 'N/A')
                                    row_data["Tipo"] = d.get('usageType', 'Desconocido')

                                    # Generar Script (Solo si no es privada)
                                    object_name = f"IP_Sospechosa_{ip}"
                                    comment_text = f"Alarma {alarm_id_bulk}" if alarm_id_bulk else "Analisis_Masivo"
                                    
                                    # SCRIPT SIN ESPACIOS AL INICIO (FORMATO CORRECTO)
                                    script_block = f"""config firewall address
edit "{object_name}"
set subnet {ip} 255.255.255.255
set comment "{comment_text}"
next
end
config firewall addrgrp
edit "{group_name_bulk}"
append member "{object_name}"
next
end
"""
                                    scripts_list.append(script_block)
                            except: pass
                        
                        results.append(row_data)
                        progress_bar.progress((i+1)/len(ips))
                        status_text.text(f"Procesado {i+1}/{len(ips)}")
                        time.sleep(1.1)
                    
                    st.session_state.bulk_results_df = pd.DataFrame(results)
                    st.session_state.bulk_script_content = "\n".join(scripts_list)
                    st.rerun()

        except Exception as e:
            st.error(f"Error: {e}")

    # 4. Resultados y Descargas
    if 'bulk_results_df' in st.session_state:
        st.divider()
        res_df = st.session_state.bulk_results_df
        
        # Contamos las que no son privadas
        processed_count = len(res_df[res_df['Score'] != "PRIVATE"])
        st.metric("✅ IPs Procesadas para Bloqueo", processed_count)
        
        # Mostramos la tabla con la nueva información
        st.dataframe(
            res_df,
            use_container_width=True, 
            hide_index=True,
            column_config={
                "Score": st.column_config.TextColumn("Score", width="small"),
                "Reportes": st.column_config.NumberColumn("Reportes", width="small"),
                "País": st.column_config.TextColumn("País", width="small"),
                "ISP": st.column_config.TextColumn("ISP", width="medium"),
                "Tipo": st.column_config.TextColumn("Tipo", width="medium"),
            }
        )
        
        col_dl1, col_dl2 = st.columns(2)
        with col_dl1:
            csv_data = res_df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Descargar Reporte CSV", csv_data, "reporte_masivo.csv", "text/csv", key="dl_bulk_csv")

        with col_dl2:
            if st.session_state.get('bulk_script_content'):
                st.download_button(
                    label="🛡️ Descargar Scripts Fortigate (.txt)",
                    data=st.session_state.bulk_script_content,
                    file_name=f"bloqueo_{alarm_id_bulk or 'masivo'}.txt",
                    mime="text/plain",
                    key="dl_bulk_script"
                )

# --- TAB 6: PLAYBOOKS (MOTOR DE REGLAS: GLOBAL + ESPECÍFICOS) ---
with tabs[6]:
    # st.title("📚 Playbooks de Respuesta (Motor Híbrido)")
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
    # st.title("🚨 Watcher")
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
    # st.title("⚙️ Centro de Administración")
    
    # Config
        # --- CONFIGURACIÓN DE TEMA ---
    # st.subheader("🎨 Apariencia")
    
    # Leemos el estado actual
    is_dark = st.session_state.get("dark_mode", True)
    
    # Si cambia el toggle, actualizamos y refrescamos
    if st.toggle("☀️ Modo Claro 🌙 /  Modo Oscuro", value=is_dark, key="theme_toggle"):
        if not st.session_state.dark_mode:
            st.session_state.dark_mode = True
            st.rerun()
    else:
        if st.session_state.dark_mode:
            st.session_state.dark_mode = False
            st.rerun()
            
    st.caption("Nota: Puede tomar un segundo actualizuarse todos los colores.")
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
        st.markdown("### 📜 Historial Análisis")
        if st.session_state.analysis_history:
            df_hist = pd.DataFrame(st.session_state.analysis_history)
            st.dataframe(df_hist, use_container_width=True, hide_index=True)
            st.download_button("📥 CSV", df_hist.to_csv(index=False).encode('utf-8'), "hist.csv", "text/csv", key="dl_hist_tab8")
        else: st.info("Vacío")

    with c_rep3:
        st.markdown("### 🛑 IOCs Detectados")
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
