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

# --- CSS DINÁMICO (DISEÑO DASHBOARD PRO) ---
def inject_css():
    dark = st.session_state.dark_mode
    bg_color = "#0e1117" if dark else "#f8f9fa"
    bg_secondary = "#161b22" if dark else "#ffffff"
    text_color = "#c9d1d9" if dark else "#212529"
    accent_color = "#58a6ff" if dark else "#0d6efd"
    border_color = "#30363d" if dark else "#dee2e6"
    red_glow = "#ff4757"
    green_glow = "#2ed573"
    orange_glow = "#ffa502"

    st.markdown(f"""
    <style>
        /* Base General */
        body, .stApp {{ background-color: {bg_color}; color: {text_color}; transition: all 0.3s ease; }}
        p, span, div, label, .stMarkdown {{ color: {text_color} !important; }}
        
        /* TARJETAS (CARDS) */
        .stMetric {{
            background-color: {bg_secondary};
            border: 1px solid {border_color};
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        /* Contenedor de Análisis IP (Grid) */
        .analysis-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }}
        
        .source-card {{
            background-color: {bg_secondary};
            border: 1px solid {border_color};
            border-radius: 10px;
            padding: 20px;
            height: 100%;
            position: relative;
            overflow: hidden;
        }}
        
        /* Efecto de borde iluminado para tarjetas activas */
        .source-card.active {{
            border-left: 4px solid {accent_color};
            box-shadow: 0 0 15px rgba(88, 166, 255, 0.1);
        }}
        .source-card.danger {{
            border-left: 4px solid {red_glow};
            box-shadow: 0 0 15px rgba(255, 71, 87, 0.1);
        }}
        .source-card.warning {{
            border-left: 4px solid {orange_glow};
            box-shadow: 0 0 15px rgba(255, 165, 2, 0.1);
        }}

        /* Botones */
        .stButton > button {{
            background-color: {accent_color};
            color: white;
            border-radius: 8px;
            border: none;
            padding: 10px 24px;
            font-weight: bold;
            transition: transform 0.2s;
        }}
        .stButton > button:hover {{
            transform: scale(1.02);
            box-shadow: 0 0 10px {accent_color};
        }}

        /* Inputs */
        .stTextInput > div > div > input {{
            background-color: {bg_secondary} !important;
            color: {text_color} !important;
            border: 1px solid {border_color};
            border-radius: 8px;
        }}
        
        /* Tabs Superiores (Manteniendo tu requisito) */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 8px;
            background-color: {bg_secondary};
            padding: 10px;
            border-radius: 10px 10px 0 0;
            border-bottom: 1px solid {border_color};
        }}
        .stTabs [data-baseweb="tab"] {{
            border-radius: 8px;
            padding: 10px 20px;
            color: {text_color};
        }}
        .stTabs [aria-selected="true"] {{
            background-color: {accent_color} !important;
            color: white !important;
        }}

        /* Status Badges */
        .status-badge {{
            position: absolute;
            top: 10px;
            right: 10px;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .status-ok {{ background: rgba(46, 213, 115, 0.2); color: {green_glow}; border: 1px solid {green_glow}; }}
        .status-wait {{ background: rgba(136, 147, 164, 0.2); color: #8892a4; border: 1px solid #8892a4; }}
        .status-danger {{ background: rgba(255, 71, 87, 0.2); color: {red_glow}; border: 1px solid {red_glow}; }}

        /* Responsive para móviles */
        @media (max-width: 768px) {{
            .analysis-grid {{ grid-template-columns: 1fr; }}
        }}
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

# ---FUNCIONES: IOCs RANSOMWARE Y MYCERT ---

@st.cache_data(ttl=3600)
def fetch_ransomware_iocs():
    """
    Extrae IOCs estructurados (URLs, IPs, Dominios) directamente desde 
    la API de Ransomware.live
    """
    url = "https://ransomware.live/api/ioc"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 200:
            data = r.json()
            ioc_list = []
            # La API devuelve una lista de entradas con 'threat_actor' y 'iocs'
            for entry in data:
                actor = entry.get('threat_actor', 'Desconocido')
                for ioc in entry.get('iocs', []):
                    ioc_list.append({
                        "Actor": actor,
                        "Tipo": ioc.get('type', 'unknown').upper(),
                        "Indicador": ioc.get('value', 'N/A'),
                        "Fuente": "Ransomware.live IOC Feed"
                    })
            return ioc_list
        return []
    except Exception as e:
        print(f"Error fetching IOCs: {e}")
        return []

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

# --- FUNCIÓN LATAM CORREGIDA (BÚSQUEDA POR PALABRAS CLAVE) ---
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
        #threat_cves = t.get('cves', [])
        #if threat_cves:
         #   for c in threat_cves:
        #        if c and isinstance(c, dict) and 'val' in c:
         #           cves_list.append({
          #              "CVE ID": c['val'], 
           #             "Contexto": t['name'][:40]+"...", 
            #            "Fuente": t.get('sourceName', 'N/A')
             #       })
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
    st.title("🦠 Ransomware Tracker")
    
    data, source_type = fetch_ransomware_data()
    
    if source_type == "API":
        st.success(f"✅ Modo: Datos Precisos (API)")
    else:
        st.warning(f"⚠️ Modo: Respaldo (RSS). Filtro de país no disponible.")

    st.markdown("---")

    if not data:
        st.error("Sin datos.")
        st.stop()

    # --- FILTROS ---
    col1, col2, col3 = st.columns(3)
    
    time_window = col1.slider("Últimos días:", 1, 90, 30)
    today = datetime.now()
    
    # Filtro Grupo
    available_groups = sorted(list(set([d['Grupo'] for d in data])))
    selected_groups = col2.multiselect("Grupo:", options=available_groups, default=available_groups)

    # Búsqueda por Texto (Ahora buscará en 'Empresa')
    search_term = col3.text_input("Buscar Empresa:", placeholder="Ej: Jgb, Salud...")

    # --- PROCESAMIENTO ---
    final_data = []
    for item in data:
        # Filtros
        if (today - item.get('date_obj', today)).days > time_window: continue
        if selected_groups and item['Grupo'] not in selected_groups: continue
        if search_term and search_term.lower() not in item['Empresa'].lower(): continue
        
        final_data.append(item)

    # --- TABLA ---
    st.metric("Eventos", len(final_data))
    
    if final_data:
        df = pd.DataFrame(final_data)
        df = df.sort_values(by="date_obj", ascending=False)
        
        # Configuramos las columnas requeridas: GRUPO, EMPRESA, PAIS, FECHA
        st.dataframe(
            df[["Grupo", "Empresa", "País", "Fecha"]],
            use_container_width=True,
            hide_index=True,
            column_config={
                "Grupo": st.column_config.TextColumn("Grupo Ransomware", width="medium"),
                "Empresa": st.column_config.TextColumn("Víctima (Empresa)", width="large"),
                "País": st.column_config.TextColumn("País", width="small"),
                "Fecha": st.column_config.TextColumn("Fecha", width="small")
            }
        )
        
        # Detalle
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
                st.link_button("🦠 Ver IOCs", "https://www.ransomware.live/ioc", use_container_width=True)
    else:
        st.warning("No hay eventos.")

# --- TAB 1: ANALIZAR IP (DISEÑO 4 FUENTES) ---
with tabs[2]:
    st.markdown("<h1 style='text-align: center;'>🔎 ANÁLISIS DE IP - 4 FUENTES EXTERNAS</h1>", unsafe_allow_html=True)
    
    # Inputs
    col_search, col_btn = st.columns([4, 1])
    with col_search:
        user_input = st.text_input("IP:", key="input_ip_val", placeholder="Ej: 8.8.8.8")
    with col_btn:
        st.write("") # Alineación vertical
        analyze_btn = st.button("ANALIZAR IP", type="primary", key="btn_analyze_ip_main", use_container_width=True)

    # Lógica de Análisis
    results = {"abuse": None, "vt": None, "otx": None, "mx": None}
    
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
                
                # 4. Greynoise (NUEVO - Reemplazo MXToolbox)
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

        # --- VISUALIZACIÓN EN GRID (2x2) ---
    # Aseguramos que 'res' siempre sea un diccionario válido
    res = st.session_state.get('analysis_results')
    if not isinstance(res, dict):
        res = {"abuse": None, "vt": None, "otx": None, "grey": None}
    
    # Grid Layout
    col1, col2 = st.columns(2)
    
    # CARD 1: AbuseIPDB (Mejorada)
    with col1:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>AbuseIPDB</span>", unsafe_allow_html=True)
        st.markdown("<h3>🛡️ AbuseIPDB</h3>", unsafe_allow_html=True)
        
        if res.get('abuse'):
            data = res['abuse']
            score = data.get('abuseConfidenceScore', 0)
            
            # Métrica Principal
            color = "#ff4757" if score > 50 else "#2ed573"
            st.markdown(f"<h1 style='color:{color}; text-align: center;'>{score}%</h1>", unsafe_allow_html=True)
            st.caption("Confianza de Abuso")
            
            # Tabla de Detalles (En lugar de JSON crudo)
            df_abuse = pd.DataFrame({
                "Detalle": ["País", "ISP", "Dominio", "Tipo", "Reportes (90d)"],
                "Valor": [
                    f"{data.get('countryCode', 'N/A')} ({data.get('countryName', '')})",
                    data.get('isp', 'N/A'),
                    data.get('domain', 'N/A'),
                    data.get('usageType', 'Desconocido'),
                    data.get('totalReports', 0)
                ]
            })
            st.dataframe(df_abuse, hide_index=True, use_container_width=True)
            
            with st.expander("⏳ Ver Últimos Reportes"):
                for rep in data.get('reports', [])[:3]:
                    st.write(f"🗨️ **{rep.get('category', 'N/A')}**: {rep.get('comment', 'Sin comentario')}")
        else:
            st.info("Esperando análisis o API Key no configurada.")
        st.markdown("</div>", unsafe_allow_html=True)

    # CARD 2: VirusTotal (Mejorada)
    with col2:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>VirusTotal</span>", unsafe_allow_html=True)
        st.markdown("<h3>🦠 VirusTotal</h3>", unsafe_allow_html=True)
        
        if res.get('vt'):
            stats = res['vt'].get('last_analysis_stats', {})
            mal = stats.get('malicious', 0)
            
            # Métrica Principal
            color = "#ff4757" if mal > 0 else "#2ed573"
            st.markdown(f"<h1 style='color:{color}; text-align: center;'>{mal} / {sum(stats.values())}</h1>", unsafe_allow_html=True)
            st.caption("Motores Maliciosos")
            
            # Resumen en Tabla
            df_vt = pd.DataFrame({
                "Estado": ["Malicioso", "Sospechoso", "Limpio", "No detectado"],
                "Cantidad": [stats.get('malicious', 0), stats.get('suspicious', 0), stats.get('harmless', 0), stats.get('undetected', 0)]
            })
            st.dataframe(df_vt, hide_index=True, use_container_width=True)
            
            with st.expander("📋 Ver Detalles de Detecciones"):
                results_vt = res['vt'].get('last_analysis_results', {})
                # Mostramos solo los que detectaron algo
                detecciones = [(k, v['result']) for k, v in results_vt.items() if v['result'] not in ['clean', 'undetected', None]]
                if detecciones:
                    for engine, res_val in detecciones[:5]:
                        st.write(f"• **{engine}**: `{res_val}`")
                else:
                    st.write("Sin detecciones maliciosas detalladas.")
        else:
            st.info("Esperando análisis o API Key no configurada.")
        st.markdown("</div>", unsafe_allow_html=True)

    col3, col4 = st.columns(2)

    # CARD 3: AlienVault OTX
    with col3:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>AlienVault OTX</span>", unsafe_allow_html=True)
        st.markdown("<h3>👾 AlienVault OTX</h3>", unsafe_allow_html=True)
        
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

    # CARD 4: Greynoise (Reemplazo MXToolbox)
    with col4:
        st.markdown("<div class='source-card active'>", unsafe_allow_html=True)
        st.markdown("<span class='status-badge status-wait'>Greynoise</span>", unsafe_allow_html=True)
        st.markdown("<h3>📡 Greynoise (Contexto)</h3>", unsafe_allow_html=True)
        
        if res.get('grey'):
            gn_data = res['grey']
            classification = gn_data.get('classification', 'unknown')
            
            # Color según clasificación
            if classification == 'malicious':
                color = "#ff4757"
                icon = "🚨"
            elif classification == 'benign':
                color = "#2ed573"
                icon = "✅"
            else:
                color = "#ffa502"
                icon = "❓"
                
            st.markdown(f"<h2 style='color:{color}; text-align: center;'>{icon} {classification.upper()}</h2>", unsafe_allow_html=True)
            st.caption("Clasificación de Actividad")
            
            # Detalles
            st.write(f"**Ruido:** {gn_data.get('noise', False)}")
            st.write(f"**Visto por última vez:** {gn_data.get('last_seen', 'N/A')}")
            
            if gn_data.get('link'):
                st.link_button("Ver Reporte Completo", gn_data['link'], use_container_width=True)
        else:
            st.info("IP no encontrada en Greynoise (Posiblemente sin actividad registrada).")
        st.markdown("</div>", unsafe_allow_html=True)

    # --- GENERADOR DE SCRIPT FORTIGATE (DOS OPCIONES) ---
    st.divider()
    st.subheader("🛡️ Generador de Script Fortigate")
    
    # Diccionario para nombres de mes en español
    MESES_ES = {1: "Enero", 2: "Febrero", 3: "Marzo", 4: "Abril", 5: "Mayo", 6: "Junio", 
                7: "Julio", 8: "Agosto", 9: "Septiembre", 10: "Octubre", 11: "Noviembre", 12: "Diciembre"}
    
    # Obtener fecha actual
    current_date = datetime.now()
    mes_actual = MESES_ES.get(current_date.month, "Mes")
    anio_actual = current_date.year
    
    # Nombre del grupo por defecto
    default_group_name = f"Ip_Reportadas_SOCCVJ_{mes_actual}_{anio_actual}"
    
    # Campos de entrada
    col_input1, col_input2 = st.columns([1, 1])
    alarm_id = col_input1.text_input("ID de Alarma (Ej: IM-24575)", placeholder="IM-XXXXX", key="input_alarm_id")
    group_name = col_input2.text_input("Grupo de Direcciones", value=default_group_name, key="input_group_name")

    # --- Lógica para generar los scripts ---
    
    # 1. Detectar si el input es un rango (CIDR) o una IP simple
    is_cidr = "/" in user_input
    ip_part = user_input.split('/')[0] if is_cidr else user_input
    cidr_part = user_input.split('/')[1] if is_cidr else "32"

    # Función auxiliar para calcular máscara decimal desde CIDR (opcional, Fortigate acepta CIDR directo en 'set subnet' a veces, pero usemos el formato que me diste: IP MASCARA)
    # Nota: El ejemplo 'set subnet 15.177.0.0 255.255.255.255' sugiere que prefieres la máscara decimal.
    # Si es un rango, asumiremos que el usuario pone la IP y la máscara manual o calculada. 
    # Para simplificar y que no falle, si es CIDR intentaremos convertirlo, si no, usaremos host mask (/32).
    
    def cidr_to_netmask(cidr):
        try:
            cidr = int(cidr)
            mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
            return f"{(mask >> 24) & 255}.{(mask >> 16) & 255}.{(mask >> 8) & 255}.{mask & 255}"
        except:
            return "255.255.255.255"

    netmask = cidr_to_netmask(cidr_part)

    # Botones en columnas
    col_btn1, col_btn2 = st.columns(2)
    
    with col_btn1:
        if st.button("📋 Generar Script IP Individual", key="btn_script_ip", use_container_width=True):
            if alarm_id and user_input:
                object_name = f"IP:Sospechosa_{ip_part}"
                
                script = f"""config firewall address
    edit "{object_name}"
        set subnet {ip_part} 255.255.255.255
        set comment "Alarma {alarm_id}"
    next
end
config firewall addrgrp
    edit "{group_name}"
        append member "{object_name}"
    next
end"""
                st.code(script, language="bash")
                st.success(f"✅ Script generado para IP Individual: {ip_part}")
            else:
                st.error("Falta ID de Alarma o IP.")

    with col_btn2:
        if st.button("🛠️ Generar Script Rango (CIDR)", key="btn_script_range", use_container_width=True):
            if alarm_id and user_input:
                # Formato Rd_
                # Si el usuario no puso /XX, asumimos /32 pero con nombre Rd_
                object_name = f"Rd_{user_input.replace('/', '_')}" 
                
                script = f"""config firewall address
    edit "{object_name}"
        set subnet {ip_part} {netmask}
        set comment "Alarma {alarm_id}"
    next
end
config firewall addrgrp
    edit "{group_name}"
        append member "{object_name}"
    next
end"""
                st.code(script, language="bash")
                st.info(f"ℹ️ Script generado para Rango/Red: {user_input} (Máscara: {netmask})")
            else:
                st.error("Falta ID de Alarma o IP/Rango.")
                
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
