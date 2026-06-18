import hashlib
import random
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Cyber Threat Intelligence API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_types = [
    "Mirai Botnet C2",
    "Cobalt Strike Beacon",
    "LockBit Ransomware Distribution",
    "Log4Shell Exploit Attempt",
    "Phishing Campaign Redirect",
    "Brute Force Attacks on SSH",
    "WannaCry Ransomware Activity",
    "Pegasus Spyware Domain",
    "Qakbot Malware Infrastructure",
    "Anubis Banker Trojan C2"
]

countries = [
    {"name": "United States", "code": "US", "lat": 37.0902, "lon": -95.7129},
    {"name": "China", "code": "CN", "lat": 35.8617, "lon": 104.1954},
    {"name": "Russia", "code": "RU", "lat": 61.5240, "lon": 105.3188},
    {"name": "Germany", "code": "DE", "lat": 51.1657, "lon": 10.4515},
    {"name": "Brazil", "code": "BR", "lat": -14.2350, "lon": -51.9253},
    {"name": "India", "code": "IN", "lat": 20.5937, "lon": 78.9629},
    {"name": "United Kingdom", "code": "GB", "lat": 55.3781, "lon": -3.4360},
    {"name": "Ukraine", "code": "UA", "lat": 48.3794, "lon": 31.1656},
    {"name": "Netherlands", "code": "NL", "lat": 52.1326, "lon": 5.2913},
    {"name": "Japan", "code": "JP", "lat": 36.2048, "lon": 138.2529}
]

apt_groups = [
    {
        "name": "Lazarus Group (APT38)",
        "origin": "North Korea",
        "threat_level": "Critical",
        "description": "State-sponsored cyber espionage and financial warfare group active since at least 2009. Known for devastating destructive attacks and massive cryptocurrency thefts.",
        "sectors": ["Financial Services", "Cryptocurrency", "Government", "Defense", "Aerospace"],
        "tactics": ["Spear-phishing", "Watering hole attacks", "Custom backdoor deployment", "Ransomware"],
        "malware": ["Destover", "Duuzer", "HermitVipper", "AppleJeus"],
        "cves": ["CVE-2023-38831", "CVE-2021-44228"]
    },
    {
        "name": "Cozy Bear (APT29)",
        "origin": "Russia",
        "threat_level": "High",
        "description": "Russian state-sponsored group, likely associated with the Foreign Intelligence Service (SVR). Known for stealthy operations targeting government and diplomatic organizations.",
        "sectors": ["Government", "Diplomatic", "Think Tanks", "Healthcare", "Energy"],
        "tactics": ["Spear-phishing campaigns", "Supply chain compromise", "Cloud service exploitation"],
        "malware": ["MiniDuke", "CosmicDuke", "Duke", "WellMess"],
        "cves": ["CVE-2023-38831", "CVE-2024-3094"]
    },
    {
        "name": "Fancy Bear (APT28)",
        "origin": "Russia",
        "threat_level": "High",
        "description": "Highly sophisticated group associated with the Russian military intelligence (GRU). Infamous for political influence operations and hacking of election infrastructures.",
        "sectors": ["Government", "Military", "Media", "Political Organizations"],
        "tactics": ["Credential harvesting", "Zero-day exploits", "Spear-phishing"],
        "malware": ["Sofacy", "X-Agent", "Coresshell", "Sedreco"],
        "cves": ["CVE-2022-41040", "CVE-2023-23397"]
    },
    {
        "name": "Sandworm",
        "origin": "Russia",
        "threat_level": "Critical",
        "description": "Extremely aggressive cyberwarfare unit. Famous for launching the BlackEnergy power grid attacks and the NotPetya ransomware outbreak, the most destructive cyberattack in history.",
        "sectors": ["Critical Infrastructure", "Energy", "Logistics", "Government"],
        "tactics": ["Destructive wiper malware", "SCADA hacking", "OT network compromise"],
        "malware": ["BlackEnergy", "Industroyer", "NotPetya", "CaddyWiper"],
        "cves": ["CVE-2017-0144", "CVE-2022-26925"]
    },
    {
        "name": "Volt Typhoon",
        "origin": "China",
        "threat_level": "Critical",
        "description": "State-sponsored cyber espionage group focusing on stealthy, long-term persistence within US critical infrastructure, specifically communication, utility, and transportation systems.",
        "sectors": ["Critical Infrastructure", "Energy", "Telecommunications", "Water Systems"],
        "tactics": ["Living off the Land (LotL)", "Compromised SOHO routers", "Credential theft"],
        "malware": ["KV Botnet", "custom web shells"],
        "cves": ["CVE-2024-21887", "CVE-2023-46805"]
    }
]

cve_database = [
    {
        "id": "CVE-2024-3094",
        "title": "XZ Utils Backdoor",
        "severity": "Critical",
        "cvss": 10.0,
        "published": "2024-03-29",
        "description": "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file, which is then used to modify the liblzma code to hijack sshd logins.",
        "impact": "Remote code execution, authentication bypass in SSH servers.",
        "mitigation": "Downgrade xz-utils to version 5.4.x or upgrade to fixed versions >= 5.6.2 depending on distribution advisory."
    },
    {
        "id": "CVE-2023-38831",
        "title": "WinRAR RCE Vulnerability",
        "severity": "High",
        "cvss": 7.8,
        "published": "2023-08-24",
        "description": "WinRAR allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. This occurs because of a flaw in processing file extensions, leading to the execution of a malicious payload with the same base name.",
        "impact": "Arbitrary code execution upon opening crafted archive file.",
        "mitigation": "Update WinRAR to version 6.23 or later."
    },
    {
        "id": "CVE-2021-44228",
        "title": "Log4Shell (Apache Log4j RCE)",
        "severity": "Critical",
        "cvss": 10.0,
        "published": "2021-12-10",
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
        "impact": "Remote Code Execution (RCE) on java servers logging user-controlled input.",
        "mitigation": "Upgrade Apache Log4j2 to version 2.15.0 or 2.16.0+, or set system property log4j2.formatMsgNoLookups=true."
    },
    {
        "id": "CVE-2023-23397",
        "title": "Microsoft Outlook Elevation of Privilege",
        "severity": "Critical",
        "cvss": 9.8,
        "published": "2023-03-14",
        "description": "Microsoft Outlook fails to properly parse custom reminder sound files, allowing an attacker to trigger an NTLM authentication relay attack. Opening or even previewing a malicious email initiates a connection to an attacker-controlled UNC path, leaking NTLM hashes.",
        "impact": "Information disclosure (NTLM hashes) leading to credential relay and account takeover.",
        "mitigation": "Apply Microsoft patch KB5024021, and block outbound SMB connections (TCP port 445)."
    },
    {
        "id": "CVE-2017-0144",
        "title": "EternalBlue (MS17-010)",
        "severity": "Critical",
        "cvss": 8.1,
        "published": "2017-03-16",
        "description": "A vulnerability in Microsoft's implementation of the Server Message Block v1 (SMBv1) protocol allows remote attackers to execute arbitrary code on target machines. Exploited in the wild by WannaCry and NotPetya.",
        "impact": "Remote code execution, worm-like propagation across local networks.",
        "mitigation": "Disable SMBv1 protocol and apply Microsoft security update MS17-010."
    }
]

def get_threats_list():
    threats = []
    base_time = datetime.utcnow()
    random.seed(42)
    for i in range(50):
        country = random.choice(countries)
        ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        severity = random.choice(["high", "medium", "low"])
        pulse = random.choice(threat_types)
        time_offset = random.randint(1, 3600)
        timestamp = (base_time - timedelta(seconds=time_offset)).isoformat() + "Z"
        threats.append({
            "id": f"threat-{i}",
            "indicator": ip,
            "type": "IPv4",
            "pulse_name": pulse,
            "severity": severity,
            "country": country["name"],
            "country_code": country["code"],
            "timestamp": timestamp,
            "description": f"Detected suspicious activity matching {pulse} signature."
        })
    threats.sort(key=lambda x: x["timestamp"], reverse=True)
    return threats

def get_map_attacks():
    attacks = []
    random.seed(42)
    for i in range(25):
        origin = random.choice(countries)
        target = random.choice([c for c in countries if c["code"] != origin["code"]])
        attack_type = random.choice(["DDoS", "Malware", "Phishing", "Brute Force", "Exploit"])
        severity = random.choice(["high", "medium", "low"])
        value = random.randint(10, 100)
        attacks.append({
            "id": f"attack-{i}",
            "origin": {
                "country": origin["name"],
                "code": origin["code"],
                "lat": origin["lat"],
                "lon": origin["lon"]
            },
            "target": {
                "country": target["name"],
                "code": target["code"],
                "lat": target["lat"],
                "lon": target["lon"]
            },
            "type": attack_type,
            "severity": severity,
            "value": value,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        })
    return attacks

@app.get("/api/threats")
def read_threats():
    return get_threats_list()

@app.get("/api/map-data")
def read_map_data():
    return get_map_attacks()

@app.get("/api/apt-groups")
def read_apt_groups():
    return apt_groups

@app.get("/api/cves")
def read_cves():
    return cve_database

@app.get("/api/check-ip/{ip}")
def check_ip_reputation(ip: str):
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    
    hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    risk_score = hash_val % 101
    
    country_idx = hash_val % len(countries)
    country = countries[country_idx]
    
    if risk_score > 70:
        threat_type = ["Botnet C2", "Malware Distribution"]
        category = "High Risk"
    elif risk_score > 40:
        threat_type = ["SSH Scanner"]
        category = "Medium Risk"
    else:
        threat_type = ["Clean"]
        category = "Low Risk"
        
    isps = ["DigitalOcean LLC", "Amazon Technologies Inc.", "Google Cloud", "Comcast Cable", "OVH SAS", "Microsoft Corp"]
    isp = isps[hash_val % len(isps)]
    
    return {
        "ip": ip,
        "risk_score": risk_score,
        "category": category,
        "threat_types": threat_type,
        "isp": isp,
        "country": country["name"],
        "country_code": country["code"],
        "latitude": country["lat"],
        "longitude": country["lon"],
        "last_active": (datetime.utcnow() - timedelta(minutes=int(hash_val % 120))).isoformat() + "Z"
    }
