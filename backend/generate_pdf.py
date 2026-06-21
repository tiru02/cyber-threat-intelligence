import sys
from fpdf import FPDF

class CyberSentinelDoc(FPDF):
    def __init__(self):
        super().__init__()
        self.set_margins(15, 20, 15)
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        if self.page_no() == 1:
            return # Skip header on cover page
        self.set_font("Courier", "I", 8)
        self.set_text_color(110, 110, 140)
        self.cell(0, 10, "CYBER SENTINEL V2.0 - TECHNICAL SPECIFICATION AND OPERATIONAL MANUAL", 0, new_x="LMARGIN", new_y="NEXT", align="R")
        self.set_draw_color(26, 26, 54) # Dark border
        self.line(15, 27, 195, 27)
        self.ln(6)

    def footer(self):
        if self.page_no() == 1:
            return # Skip footer on cover page
        self.set_y(-15)
        self.set_font("Courier", "I", 8)
        self.set_text_color(110, 110, 140)
        # Left-aligned status, Right-aligned page number
        self.cell(100, 10, "CONFIDENTIAL // DEFENSIVE OPERATIONAL COMMAND", 0, new_x="RIGHT", new_y="TOP", align="L")
        self.cell(80, 10, f"Page {self.page_no()}", 0, new_x="LMARGIN", new_y="NEXT", align="R")

    def add_cover_page(self):
        self.add_page()
        # Cover page dark background
        self.set_fill_color(3, 3, 7) # Deep cyber black
        self.rect(0, 0, 210, 297, "F")
        
        # Cyber grid layout border lines
        self.set_draw_color(26, 26, 54)
        self.line(10, 10, 200, 10)
        self.line(10, 10, 10, 287)
        self.line(200, 10, 200, 287)
        self.line(10, 287, 200, 287)

        # Title Block
        self.ln(60)
        self.set_font("Courier", "B", 34)
        self.set_text_color(255, 0, 127) # Neon Pink
        self.cell(0, 15, "CYBER SENTINEL", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        
        self.set_font("Courier", "B", 14)
        self.set_text_color(0, 240, 255) # Neon Cyan
        self.cell(0, 10, "SYSTEM LEVEL V2.0 PRO SPECIFICATIONS", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        
        # Horizontal rule
        self.ln(10)
        self.set_draw_color(255, 0, 127)
        self.line(50, 105, 160, 105)
        self.ln(15)

        # Subtitle Block
        self.set_font("Courier", "", 10)
        self.set_text_color(200, 200, 220)
        self.multi_cell(0, 5, "REAL-TIME CYBER THREAT INTELLIGENCE FEED,\nNation-State APT Actor Profiling,\nMitigation Center CVE Registry, & Firewall Policy Generator.", 0, "C")

        # System Status Box
        self.ln(45)
        self.set_fill_color(11, 11, 22)
        self.set_draw_color(0, 240, 255)
        self.set_text_color(0, 240, 255)
        self.rect(35, 175, 140, 45, "DF")
        self.set_y(180)
        self.set_font("Courier", "B", 10)
        self.cell(0, 5, "SECURE OPERATION CENTER ACCESS LOG", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        self.set_font("Courier", "", 9)
        self.set_text_color(200, 200, 220)
        self.cell(0, 5, "CODENAME: CYBER-SENTINEL-CTI", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 5, "RELEASE STAGE: TECHNICAL MANUAL", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 5, "COMPILE TIME: JUNE 18, 2026", 0, new_x="LMARGIN", new_y="NEXT", align="C")

        # Footer on cover
        self.set_y(260)
        self.set_font("Courier", "I", 8)
        self.set_text_color(100, 100, 120)
        self.cell(0, 5, "DEEPMIND ADVANCED CODES DIVISION", 0, new_x="LMARGIN", new_y="NEXT", align="C")
        self.cell(0, 5, "RESTRICTED DISTRIBUTION ONLY", 0, new_x="LMARGIN", new_y="NEXT", align="C")

    def add_section_header(self, num, title):
        self.set_font("Courier", "B", 13)
        self.set_text_color(0, 240, 255) # Cyan
        self.set_fill_color(11, 11, 22)
        self.cell(0, 9, f"SECTION {num} // {title.upper()}", 1, new_x="LMARGIN", new_y="NEXT", align="L", fill=True)
        self.ln(4)

    def write_paragraph(self, text):
        self.set_font("Courier", "", 9.5)
        self.set_text_color(220, 220, 240)
        self.multi_cell(0, 5, text)
        self.ln(3.5)

    def write_bullet(self, label, desc):
        self.set_font("Courier", "B", 9.5)
        self.set_text_color(255, 0, 127) # Pink bullet
        self.cell(30, 5, f"  * {label}:", 0, new_x="RIGHT", new_y="TOP", align="L")
        self.set_font("Courier", "", 9.5)
        self.set_text_color(220, 220, 240)
        self.multi_cell(0, 5, desc)
        self.ln(2)

    def write_code(self, text):
        self.set_font("Courier", "", 8.5)
        self.set_text_color(57, 255, 20) # Green text
        self.set_fill_color(3, 3, 7) # Deep dark
        self.set_draw_color(26, 26, 54)
        self.multi_cell(0, 4.5, text, 1, "L", fill=True)
        self.ln(3)

def generate_pdf():
    pdf = CyberSentinelDoc()
    
    # Page 1: Cover Page
    pdf.add_cover_page()
    
    # Page 2: System Overview & Architecture
    pdf.add_page()
    pdf.add_section_header("1.0", "System Overview & Design Architecture")
    pdf.write_paragraph(
        "The Cyber Sentinel platform is a unified cyber threat intelligence (CTI) dashboard "
        "and security operation command interface. The system acts as a real-time monitor for global network indicators of compromise (IoC) "
        "combined with threat actor profile catalogs, remediation lookup sheets, and copy-pastable firewall rules compiling."
    )
    
    pdf.write_paragraph(
        "Design Architecture relies on a split-client system that maps real-time geolocation indicators directly onto a customized vector map, "
        "processing background intelligence datasets, and generating firewall rule structures dynamically."
    )
    
    pdf.write_paragraph("The technology stack comprises the following key components:")
    pdf.write_bullet("FastAPI Backend", "A lightweight Python 3 web service serving simulated real-time data payloads and routing lookup engines.")
    pdf.write_bullet("React 19 Frontend", "Single Page Application (SPA) dashboard containing responsive widgets, tabs state, and user actions.")
    pdf.write_bullet("Leaflet Maps API", "Renders global geographic vectors utilizing customized tile maps, animation loops, and popups.")
    pdf.write_bullet("Recharts Engines", "Processes attack vectors to output categorized distributions in clean SVG layouts.")
    
    pdf.ln(5)
    pdf.add_section_header("2.0", "Core Directory Map")
    pdf.write_paragraph("The workspace structure contains clean decoupling between the client assets and server services:")
    pdf.write_code(
        "cyber-threat-intelligence/\n"
        "|-- start.sh                      # Unified concurrent launch script\n"
        "|-- backend/\n"
        "|   |-- main.py                   # FastAPI server, routers, & datasets\n"
        "|   |-- requirements.txt          # Python packages (fastapi, uvicorn)\n"
        "|   +-- venv/                     # Python 3 virtual environment\n"
        "+-- frontend/\n"
        "    |-- .env                      # Vite environment configuration file\n"
        "    |-- index.html                # Entry meta tags and html structure\n"
        "    |-- src/\n"
        "    |   |-- main.jsx              # React mounting structure\n"
        "    |   |-- App.jsx               # Dashboard module layout, maps, & state\n"
        "    |   +-- index.css             # Theme imports, modals, & glow styles\n"
        "    +-- package.json              # Client packages and build commands"
    )

    # Page 3: Core Features Manual
    pdf.add_page()
    pdf.add_section_header("3.0", "Operational Features Manual")
    pdf.write_paragraph(
        "Cyber Sentinel V2.0 provides an interactive operations command console structured across five specialized dashboard sections:"
    )

    pdf.write_bullet("Live Threat Monitor", "The main visual module displaying origin-to-target attack vectors as dashed lines. Glowing markers fly along coordinates dynamically based on interpolation loops, triggering concentric expanding rings (shockwaves) upon collision with target countries. It integrates a live threat log feed with severity indicators, IP reputation scanning, and attack category distributions.")
    pdf.write_bullet("Country Threat Monitor", "A dedicated geographic monitoring interface. It aggregates attack telemetry dynamically per nation-state. Features a circular visual distribution of local threat families and renders an automated Prevention & Mitigation Advisor offering specific system repair recommendations and command templates.")
    pdf.write_bullet("Simulator Control", "The map header integrates speed multipliers (1x, 2x, 5x) and play/pause controls to speed up or pause the background threat stream feed simulator. You can inspect threats in details or export feed datasets directly as JSON or CSV files.")
    pdf.write_bullet("APT Threat Actors", "A Nation-state adversary catalog. Groups like Lazarus Group (APT38), Cozy Bear (APT29), Fancy Bear (APT28), Volt Typhoon, and Sandworm are profiled with threat levels, origins, target industries, preferred vectors, and CVE exploit history.")
    pdf.write_bullet("Mitigation CVEs", "Common Vulnerabilities and Exposures (CVE) search engine. Displays critical vulnerabilities with CVSS scores, threat details, and explicit patch recommendations or firewall blockings.")
    pdf.write_bullet("Defensive Toolkit", "Instantly compiles IP blocking shell rules. Users check suspicious IPs in the logs to generate output block scripts for UFW (deny host), iptables (INPUT DROP), or Cisco ASA (access-list deny).")


    # Page 4: Backend API Specification
    pdf.add_page()
    pdf.add_section_header("5.0", "Backend API Routing Specification")
    pdf.write_paragraph(
        "The backend FastAPI server runs on port 8000. It exposes REST API routes serving JSON structures to the frontend:"
    )

    pdf.write_bullet("GET /api/threats", "Returns a JSON list of active threat payloads containing indicator IP, type, signature, severity, origin country, and timestamp.")
    pdf.write_bullet("GET /api/map-data", "Returns connecting flight pathways for the map layout containing geocoded origin and target coordinates, payload type, and values.")
    pdf.write_bullet("GET /api/apt-groups", "Returns the database registry of nation-state threat actors.")
    pdf.write_bullet("GET /api/cves", "Returns the vulnerability database registry with CVSS score metrics and mitigations. Used as local fallback data.")
    pdf.write_bullet("GET /api/prevention-strategies", "Returns a mapping of threat signatures to detailed forensic summaries, checklists, and copy-pasteable firewall commands.")
    pdf.write_bullet("GET /api/check-ip/{ip}", "Dynamically checks risk index, threat category, owner, and geolocation. The score is simulated in python via MD5 hashing on input IP.")
    pdf.write_bullet("GET /api/threatfox", "Returns the 50 most recent live IOCs (IPs, domains, hashes) from the ThreatFox community feed.")
    pdf.write_bullet("GET /api/urlhaus", "Returns the 50 most recent active malware URLs from the URLhaus community feed.")
    pdf.write_bullet("GET /api/github-advisories", "Proxies the official GitHub Security Advisory database API, returning recent open-source package vulnerabilities.")
    pdf.write_bullet("GET /api/circl-cves", "Returns the 30 most recent CVE records published or updated from the CIRCL live feed.")

    pdf.ln(5)
    pdf.add_section_header("6.0", "API Response Example")
    pdf.write_paragraph("Example JSON output from GET /api/check-ip/8.8.8.8:")
    pdf.write_code(
        "{\n"
        "  \"ip\": \"8.8.8.8\",\n"
        "  \"risk_score\": 76,\n"
        "  \"category\": \"High Risk\",\n"
        "  \"threat_types\": [\n"
        "    \"Botnet C2\",\n"
        "    \"Malware Distribution\"\n"
        "  ],\n"
        "  \"isp\": \"Google Cloud\",\n"
        "  \"country\": \"Brazil\",\n"
        "  \"country_code\": \"BR\",\n"
        "  \"latitude\": -14.235,\n"
        "  \"longitude\": -51.925,\n"
        "  \"last_active\": \"2026-06-18T06:05:00Z\"\n"
        "}"
    )

    # Page 5: Operation & Setup
    pdf.add_page()
    pdf.add_section_header("7.0", "Installation & Operating Manual")
    pdf.write_paragraph(
        "Operating both servers concurrently is managed using the VITE environment files "
        "and the bash launcher. Set up the frontend to target the correct backend host."
    )
    
    pdf.write_paragraph("Create a frontend/.env file to override the default API url target:")
    pdf.write_code(
        "# frontend/.env\n"
        "VITE_API_BASE_URL=http://localhost:8000"
    )

    pdf.write_paragraph("To start both servers with a single command from the project root directory, run:")
    pdf.write_code(
        "chmod +x start.sh\n"
        "./start.sh"
    )

    pdf.write_paragraph("This command executes the following script to spin up the servers concurrently and clean up cleanly on exit:")
    pdf.write_code(
        "#!/bin/bash\n\n"
        "# Function to kill child processes on exit\n"
        "cleanup() {\n"
        "    echo \"\"\n"
        "    echo \"Stopping servers...\"\n"
        "    kill $(jobs -p) 2>/dev/null\n"
        "}\n"
        "trap cleanup EXIT\n\n"
        "PROJECT_ROOT=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n\n"
        "# Start backend\n"
        "echo \"Starting Backend API (Uvicorn)...\"\n"
        "cd \"$PROJECT_ROOT/backend\"\n"
        "./venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 --reload &\n\n"
        "# Start frontend\n"
        "echo \"Starting Frontend App (Vite)...\"\n"
        "cd \"$PROJECT_ROOT/frontend\"\n"
        "npm run dev &\n\n"
        "wait"
    )

    pdf.write_paragraph(
        "To terminate the servers, simply press CTRL+C once. The trap signal handler catches "
        "the interrupt and sends SIGTERM to both the Node.js (Vite) and Python (Uvicorn) background tasks."
    )

    # Page 6: Country Threat Monitor & Prevention Advisor
    pdf.add_page()
    pdf.add_section_header("8.0", "Country Threat Monitor & Prevention")
    pdf.write_paragraph(
        "The Country Threat Monitor tab provides deep visibility into localized cyber threat telemetry. "
        "This component computes dynamic real-time statistics per monitored country, linking outbound incident frequencies, "
        "inbound targeted vectors, and overall threat index calculations."
    )
    pdf.write_paragraph(
        "The interactive module includes two main areas: a monitored regions sidebar showing active risk categories "
        "(Critical, High, Medium, Low), and an analytics workspace rendering a Recharts distribution of threat families "
        "and active log events specific to that nation."
    )
    pdf.write_paragraph(
        "Directly below the metrics, the Prevention & Mitigation Advisor automatically parses active threats in the "
        "selected country and displays custom security recommendations. For instance:"
    )
    pdf.write_bullet("SSH Brute Force", "Requires disabling root login, enforcing key authentication, and configuring Fail2Ban blocks.")
    pdf.write_bullet("Log4Shell Attempts", "Requires upgrading dependencies, deploying WAF rules, and disabling format string lookup mechanisms.")
    pdf.write_bullet("Mirai Botnet C2", "Requires credentials modification on IoT hosts, port blocks (23/2323), and network segmentation.")
    
    pdf.write_paragraph(
        "Each advisory card includes copy-pasteable firewall commands (like iptables, ufw, or cisco ACL overrides) "
        "allowing security administrators to rapidly apply defensive parameters."
    )

    # Page 7: Threat Intelligence Feeds Hub
    pdf.add_page()
    pdf.add_section_header("9.0", "Threat Intelligence Feeds Hub")
    pdf.write_paragraph(
        "The Threat Intelligence Feeds Hub integrates multiple open-source intelligence feeds as separate routes "
        "within a unified React frontend dashboard view. This provides a central command center for tracking live, "
        "in-the-wild Indicators of Compromise (IOCs), malware URLs, package vulnerabilities, and new CVE database listings."
    )
    pdf.write_paragraph(
        "Each feed constitutes a separate tab route with custom filters and dedicated UI cards:"
    )
    pdf.write_bullet("ThreatFox IOCs", "A tabular view of IP addresses, domains, and files associated with malware families like ClearFake, showing reporter credit and source timestamp.")
    pdf.write_bullet("URLhaus URLs", "An active feed of malicious web links used in dropper campaigns. Active and offline URLs are badged with copyable links for threat validation.")
    pdf.write_bullet("GitHub Advisories", "A grid view of package security alerts showing vulnerability summaries, severity levels, target packages, and direct links to GitHub Advisories.")
    pdf.write_bullet("CIRCL CVEs", "A timeline of new CVE reports with CVSS score color badges and technical vulnerability summaries, keeping administrators informed of emerging threats.")

    # Save PDF
    pdf.output("../Cyber_Sentinel_Documentation.pdf")
    print("Documentation PDF compiled successfully at project root.")

if __name__ == "__main__":
    generate_pdf()
