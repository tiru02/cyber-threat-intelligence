import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Polyline } from 'react-leaflet';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid, PieChart, Pie } from 'recharts';
import { 
  Shield, Search, AlertTriangle, Activity, MapPin, Server, Globe, X, Clock, Cpu, 
  Play, Pause, FastForward, UserCheck, Terminal, Download, ShieldAlert, BookOpen, 
  Layers, Copy, Check, Filter, RefreshCw, Rss, ExternalLink, AlertOctagon
} from 'lucide-react';

const countries = [
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
];

const threatTypes = [
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
];

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

export default function App() {
  // Navigation & Data Tabs
  const [activeTab, setActiveTab] = useState('monitor'); // 'monitor' | 'country' | 'apt' | 'cves' | 'toolkit' | 'feeds'
  
  // Feeds Hub states
  const [feedTab, setFeedTab] = useState('threatfox'); // 'threatfox' | 'urlhaus' | 'github' | 'circl'
  const [threatfoxData, setThreatfoxData] = useState([]);
  const [urlhausData, setUrlhausData] = useState([]);
  const [githubAdvisoriesData, setGithubAdvisoriesData] = useState([]);
  const [circlCvesData, setCirclCvesData] = useState([]);
  
  const [threatfoxSearch, setThreatfoxSearch] = useState('');
  const [urlhausSearch, setUrlhausSearch] = useState('');
  const [githubSearch, setGithubSearch] = useState('');
  const [circlSearch, setCirclSearch] = useState('');
  
  const [threatfoxLoading, setThreatfoxLoading] = useState(false);
  const [urlhausLoading, setUrlhausLoading] = useState(false);
  const [githubLoading, setGithubLoading] = useState(false);
  const [circlLoading, setCirclLoading] = useState(false);
  
  // Data States
  const [threats, setThreats] = useState([]);
  const [mapData, setMapData] = useState([]);
  const [aptGroups, setAptGroups] = useState([]);
  const [cves, setCves] = useState([]);
  const [preventionStrategies, setPreventionStrategies] = useState({});
  const [selectedCountry, setSelectedCountry] = useState(countries[0]);
  const [copiedRulesKey, setCopiedRulesKey] = useState(null);
  const [toolkitSubTab, setToolkitSubTab] = useState('local'); // 'local' | 'global'
  const [globalFeedType, setGlobalFeedType] = useState('tor'); // 'tor' | 'spamhaus' | 'cisa'
  const [cisaKevData, setCisaKevData] = useState([]);
  const [torExitData, setTorExitData] = useState([]);
  const [spamhausDropData, setSpamhausDropData] = useState([]);
  const [cisaSearch, setCisaSearch] = useState('');
  
  // Simulation States
  const [isLive, setIsLive] = useState(true);
  const [speedMultiplier, setSpeedMultiplier] = useState(1); // 1x, 2x, 5x
  
  // Search & Filter States
  const [ipQuery, setIpQuery] = useState('');
  const [ipResult, setIpResult] = useState(null);
  const [ipLoading, setIpLoading] = useState(false);
  const [ipError, setIpError] = useState('');
  
  const [feedSearch, setFeedSearch] = useState('');
  const [feedFilter, setFeedFilter] = useState('all'); // 'all' | 'high' | 'medium' | 'low'
  
  const [aptSearch, setAptSearch] = useState('');
  const [cveSearch, setCveSearch] = useState('');
  const [cveSeverityFilter, setCveSeverityFilter] = useState('all');

  // Defensive Toolkit
  const [selectedBlockedIps, setSelectedBlockedIps] = useState(new Set());
  const [toolkitFormat, setToolkitFormat] = useState('ufw'); // 'ufw' | 'iptables' | 'cisco_asa'
  const [copiedCode, setCopiedCode] = useState(false);

  // Inspector Details Modals
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [selectedApt, setSelectedApt] = useState(null);
  const [selectedCve, setSelectedCve] = useState(null);

  // Map Animation Coordinates
  const [flyingPackets, setFlyingPackets] = useState([]);
  const [shockwaves, setShockwaves] = useState([]);

  // Modal Dialog Refs
  const threatDialogRef = useRef(null);
  const aptDialogRef = useRef(null);
  const cveDialogRef = useRef(null);

  // Initial Fetch
  // Helper functions for parsing NVD API response
  const getCvss = (cve) => {
    const metrics = cve.metrics || {};
    const v31 = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore;
    if (v31 !== undefined) return v31;
    const v30 = metrics.cvssMetricV30?.[0]?.cvssData?.baseScore;
    if (v30 !== undefined) return v30;
    const v2 = metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
    if (v2 !== undefined) return v2;
    return 5.0; // default fallback
  };

  const getSeverity = (cvss) => {
    if (cvss >= 9.0) return "Critical";
    if (cvss >= 7.0) return "High";
    if (cvss >= 4.0) return "Medium";
    return "Low";
  };

  const getImpact = (cve) => {
    const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || "";
    if (desc.toLowerCase().includes("remote code execution") || desc.toLowerCase().includes("rce")) {
      return "Remote code execution, arbitrary command execution.";
    }
    if (desc.toLowerCase().includes("privilege") || desc.toLowerCase().includes("elevation")) {
      return "Privilege escalation and unauthorized admin access.";
    }
    if (desc.toLowerCase().includes("denial of service") || desc.toLowerCase().includes("dos")) {
      return "Denial of Service (DoS) and application instability.";
    }
    return "Potential system compromise or sensitive information disclosure.";
  };

  const getMitigation = (cve) => {
    const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || "";
    if (desc.toLowerCase().includes("patch") || desc.toLowerCase().includes("update")) {
      return "Apply vendor security patches and update software to the latest secure version.";
    }
    return "Implement strict firewall rules to restrict network access, inspect logs for indicators of compromise, and monitor system integrations.";
  };

  // Initial Fetch
  useEffect(() => {
    fetch(`${API_BASE_URL}/api/threats`)
      .then(res => res.json())
      .then(data => setThreats(data))
      .catch(err => console.error("Error fetching threats:", err));

    fetch(`${API_BASE_URL}/api/map-data`)
      .then(res => res.json())
      .then(data => setMapData(data))
      .catch(err => console.error("Error fetching map data:", err));

    fetch(`${API_BASE_URL}/api/apt-groups`)
      .then(res => res.json())
      .then(data => setAptGroups(data))
      .catch(err => console.error("Error fetching APT groups:", err));

    fetch(`${API_BASE_URL}/api/prevention-strategies`)
      .then(res => res.json())
      .then(data => setPreventionStrategies(data))
      .catch(err => console.error("Error fetching prevention strategies:", err));

    fetch(`${API_BASE_URL}/api/cisa-kev`)
      .then(res => res.json())
      .then(data => setCisaKevData(data))
      .catch(err => console.error("Error fetching CISA KEV:", err));

    fetch(`${API_BASE_URL}/api/tor-exit-nodes`)
      .then(res => res.json())
      .then(data => setTorExitData(data))
      .catch(err => console.error("Error fetching Tor exit nodes:", err));

    fetch(`${API_BASE_URL}/api/spamhaus-drop`)
      .then(res => res.json())
      .then(data => setSpamhausDropData(data))
      .catch(err => console.error("Error fetching Spamhaus DROP:", err));

    setThreatfoxLoading(true);
    fetch(`${API_BASE_URL}/api/threatfox`)
      .then(res => res.json())
      .then(data => {
        setThreatfoxData(data);
        setThreatfoxLoading(false);
      })
      .catch(err => {
        console.error("Error fetching ThreatFox:", err);
        setThreatfoxLoading(false);
      });

    setUrlhausLoading(true);
    fetch(`${API_BASE_URL}/api/urlhaus`)
      .then(res => res.json())
      .then(data => {
        setUrlhausData(data);
        setUrlhausLoading(false);
      })
      .catch(err => {
        console.error("Error fetching URLhaus:", err);
        setUrlhausLoading(false);
      });

    setGithubLoading(true);
    fetch(`${API_BASE_URL}/api/github-advisories`)
      .then(res => res.json())
      .then(data => {
        setGithubAdvisoriesData(data);
        setGithubLoading(false);
      })
      .catch(err => {
        console.error("Error fetching GitHub advisories:", err);
        setGithubLoading(false);
      });

    setCirclLoading(true);
    fetch(`${API_BASE_URL}/api/circl-cves`)
      .then(res => res.json())
      .then(data => {
        setCirclCvesData(data);
        setCirclLoading(false);
      })
      .catch(err => {
        console.error("Error fetching CIRCL CVEs:", err);
        setCirclLoading(false);
      });

    // NIST NVD API direct fetching
    fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=30")
      .then(res => {
        if (!res.ok) throw new Error("NIST API returned status " + res.status);
        return res.json();
      })
      .then(data => {
        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
          throw new Error("Empty vulnerability list from NIST");
        }
        const parsed = data.vulnerabilities.map(item => {
          const cve = item.cve;
          const cvss = getCvss(cve);
          const severity = getSeverity(cvss);
          const description = cve.descriptions.find(d => d.lang === 'en')?.value || "No description available.";
          
          const firstSentence = description.split(/[.!?]/)[0];
          const title = firstSentence.length > 80 ? firstSentence.substring(0, 77) + "..." : firstSentence || `${cve.id} Vulnerability`;

          return {
            id: cve.id,
            title: title,
            severity: severity,
            cvss: cvss,
            published: cve.published ? cve.published.split('T')[0] : 'N/A',
            description: description,
            impact: getImpact(cve),
            mitigation: getMitigation(cve)
          };
        });
        setCves(parsed);
      })
      .catch(err => {
        console.warn("Direct NIST NVD fetch failed (CORS/offline/rate limit). Falling back to local backend:", err);
        fetch(`${API_BASE_URL}/api/cves`)
          .then(res => res.json())
          .then(data => setCves(data))
          .catch(err2 => console.error("Error fetching fallback CVEs:", err2));
      });
  }, []);

  // Sync animation packets when static mapData changes initially
  useEffect(() => {
    if (mapData.length > 0 && flyingPackets.length === 0) {
      setFlyingPackets(mapData.slice(0, 15).map((attack, i) => ({
        id: attack.id,
        origin: [attack.origin.lat, attack.origin.lon],
        originCountry: attack.origin.country,
        target: [attack.target.lat, attack.target.lon],
        targetCountry: attack.target.country,
        current: [attack.origin.lat, attack.origin.lon],
        progress: Math.random(), // desynchronize initial particles
        severity: attack.severity,
        type: attack.type,
        speed: 0.008 + Math.random() * 0.015
      })));
    }
  }, [mapData]);

  // Real-time animation loop for flying map particles & expanding shockwaves
  useEffect(() => {
    if (!isLive || flyingPackets.length === 0) return;

    const interval = setInterval(() => {
      // 1. Update flying packets
      setFlyingPackets(prev => prev.map(p => {
        const nextProgress = p.progress + p.speed * speedMultiplier;
        
        if (nextProgress >= 1) {
          // Spawn shockwave at target coordinate
          setShockwaves(sw => [
            ...sw, 
            { 
              id: `${p.id}-wave-${Date.now()}-${Math.random()}`, 
              center: p.target, 
              severity: p.severity, 
              radius: 2 
            }
          ].slice(-10)); // cap shockwaves to prevent leak

          // Reset packet back to origin
          return {
            ...p,
            progress: 0,
            current: [...p.origin]
          };
        }

        // Interpolate coordinates
        const lat = p.origin[0] + (p.target[0] - p.origin[0]) * nextProgress;
        const lon = p.origin[1] + (p.target[1] - p.origin[1]) * nextProgress;

        return {
          ...p,
          progress: nextProgress,
          current: [lat, lon]
        };
      }));

      // 2. Expand shockwaves
      setShockwaves(prev => prev
        .map(sw => ({ ...sw, radius: sw.radius + 1.5 }))
        .filter(sw => sw.radius < 24)
      );

    }, 50);

    return () => clearInterval(interval);
  }, [isLive, speedMultiplier, flyingPackets.length]);





  // IP Reputation Search Submit
  const handleSearch = (e) => {
    e.preventDefault();
    if (!ipQuery.trim()) return;
    setIpLoading(true);
    setIpError('');
    setIpResult(null);

    fetch(`${API_BASE_URL}/api/check-ip/${ipQuery.trim()}`)
      .then(res => {
        if (!res.ok) throw new Error('Invalid IP format or lookup failure');
        return res.json();
      })
      .then(data => {
        setIpResult(data);
        setIpLoading(false);
      })
      .catch(err => {
        setIpError(err.message);
        setIpLoading(false);
      });
  };

  // Inspect Modal handlers using Native Dialog
  const openThreatModal = (threat) => {
    setSelectedThreat(threat);
    if (threatDialogRef.current) threatDialogRef.current.showModal();
  };

  const closeThreatModal = () => {
    if (threatDialogRef.current) threatDialogRef.current.close();
    setSelectedThreat(null);
  };

  const openAptModal = (apt) => {
    setSelectedApt(apt);
    if (aptDialogRef.current) aptDialogRef.current.showModal();
  };

  const closeAptModal = () => {
    if (aptDialogRef.current) aptDialogRef.current.close();
    setSelectedApt(null);
  };

  const openCveModal = (cve) => {
    setSelectedCve(cve);
    if (cveDialogRef.current) cveDialogRef.current.showModal();
  };

  const closeCveModal = () => {
    if (cveDialogRef.current) cveDialogRef.current.close();
    setSelectedCve(null);
  };

  // Backdrop click listener to close native modal
  const handleBackdropClick = (e, ref, closeFn) => {
    if (e.target === ref.current) {
      closeFn();
    }
  };

  // Filtered threat feeds
  const filteredThreats = threats.filter(t => {
    const matchSearch = t.indicator.includes(feedSearch) || t.country.toLowerCase().includes(feedSearch.toLowerCase()) || t.pulse_name.toLowerCase().includes(feedSearch.toLowerCase());
    const matchSeverity = feedFilter === 'all' || t.severity.toLowerCase() === feedFilter;
    return matchSearch && matchSeverity;
  });

  // Export Threat Feed as CSV or JSON
  const exportThreats = (format) => {
    let dataStr = "";
    let filename = "";
    let mimeType = "";
    
    if (format === 'json') {
      dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredThreats, null, 2));
      filename = `cyber_sentinel_threats_${Date.now()}.json`;
      mimeType = "application/json";
    } else {
      const headers = "id,indicator,type,pulse_name,severity,country,country_code,timestamp\n";
      const rows = filteredThreats.map(t => 
        `"${t.id}","${t.indicator}","${t.type}","${t.pulse_name}","${t.severity}","${t.country}","${t.country_code}","${t.timestamp}"`
      ).join("\n");
      dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(headers + rows);
      filename = `cyber_sentinel_threats_${Date.now()}.csv`;
      mimeType = "text/csv";
    }

    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", filename);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Calculate DEFCON Status
  const getDefconStatus = () => {
    const highThreatsCount = threats.filter(t => t.severity === 'high').length;
    const totalCount = threats.length || 1;
    const ratio = highThreatsCount / totalCount;

    if (ratio > 0.4) {
      return {
        level: "DEFCON 1",
        label: "CRITICAL SYSTEM THREAT",
        color: "text-cyber-pink border-cyber-pink bg-cyber-pink/10 shadow-[0_0_15px_rgba(255,0,127,0.3)]",
        badge: "bg-cyber-pink text-white animate-ping",
        desc: "Severe global attacks active. Security controls set to maximum alert."
      };
    } else if (ratio > 0.25) {
      return {
        level: "DEFCON 2",
        label: "ELEVATED ACTOR ACTIVITY",
        color: "text-cyber-purple border-cyber-purple bg-cyber-purple/10 shadow-[0_0_12px_rgba(157,0,255,0.25)]",
        badge: "bg-cyber-purple text-white animate-pulse",
        desc: "Targeted campaigns detected. Restrict outbound vector logs."
      };
    } else if (ratio > 0.12) {
      return {
        level: "DEFCON 3",
        label: "ELEVATED SYSTEM ALERT",
        color: "text-cyber-yellow border-cyber-yellow bg-cyber-yellow/10",
        badge: "bg-cyber-yellow text-black",
        desc: "Moderate scanner activity. Verify firewall intrusion integrity."
      };
    } else {
      return {
        level: "DEFCON 4",
        label: "SYSTEMS OPERATIONAL / SECURE",
        color: "text-cyber-cyan border-cyber-cyan bg-cyber-cyan/10",
        badge: "bg-cyber-cyan text-black",
        desc: "Normal scan levels detected. Continuous background surveillance."
      };
    }
  };

  const defcon = getDefconStatus();

  // Recharts Chart Data
  const chartData = Object.entries(
    mapData.reduce((acc, curr) => {
      acc[curr.type] = (acc[curr.type] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, count]) => ({ name, count }));

  // Color mappings
  const getSeverityColor = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'high': return 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30';
      case 'medium': return 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30';
      case 'low': return 'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/30';
      default: return 'text-cyber-green bg-cyber-green/10 border-cyber-green/30';
    }
  };

  // Toolkit rule generation
  const toggleToolkitIp = (ip) => {
    const updated = new Set(selectedBlockedIps);
    if (updated.has(ip)) {
      updated.delete(ip);
    } else {
      updated.add(ip);
    }
    setSelectedBlockedIps(updated);
  };

  const selectAllHighThreatIps = () => {
    const highs = threats.filter(t => t.severity === 'high').map(t => t.indicator);
    setSelectedBlockedIps(new Set([...selectedBlockedIps, ...highs]));
  };

  const clearToolkitIps = () => {
    setSelectedBlockedIps(new Set());
  };

  const generateFirewallScript = () => {
    if (selectedBlockedIps.size === 0) {
      return "# SELECT SUSPICIOUS IPS FROM THE LIST TO GENERATE BLOCKLIST COMMANDS";
    }

    const ipList = Array.from(selectedBlockedIps);
    
    if (toolkitFormat === 'ufw') {
      return `# UFW DENY RULES GENERATED ON ${new Date().toLocaleDateString()}\n` +
        ipList.map(ip => `sudo ufw deny from ${ip} to any comment 'CyberSentinel Block'`).join('\n');
    } else if (toolkitFormat === 'iptables') {
      return `# IPTABLES INPUT DROP RULES GENERATED ON ${new Date().toLocaleDateString()}\n` +
        `# Run these commands to drop packets at kernel level\n\n` +
        ipList.map(ip => `sudo iptables -A INPUT -s ${ip} -j DROP`).join('\n');
    } else {
      // cisco_asa
      return `! CISCO ASA BLOCKLIST ACCESS-LIST CONFIGURATION\n` +
        `! Generated on ${new Date().toLocaleDateString()}\n\n` +
        `object-group network CYBER_SENTINEL_BLOCKLIST\n` +
        ipList.map(ip => ` network-object host ${ip}`).join('\n') +
        `\n!\naccess-list deny_threats extended deny ip object-group CYBER_SENTINEL_BLOCKLIST any\n` +
        `access-group deny_threats in interface outside`;
    }
  };

  const copyFirewallScript = () => {
    const codeText = generateFirewallScript();
    navigator.clipboard.writeText(codeText)
      .then(() => {
        setCopiedCode(true);
        setTimeout(() => setCopiedCode(false), 2000);
      });
  };

  return (
    <div className="min-h-screen bg-cyber-bg text-slate-100 flex flex-col font-mono selection:bg-cyber-pink selection:text-white cyber-grid">
      
      {/* Header Area */}
      <header className="border-b border-cyber-border bg-cyber-card/85 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        
        {/* Brand Identity */}
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyber-pink/10 border border-cyber-pink/30 rounded shadow-[0_0_15px_rgba(255,0,127,0.25)]">
            <Shield className="w-6 h-6 text-cyber-pink animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-cyan via-cyber-purple to-cyber-pink">
                CYBER SENTINEL
              </h1>
              <span className="text-[9px] px-1.5 py-0.5 border border-cyber-cyan/30 bg-cyber-cyan/10 rounded text-cyber-cyan">V2.0 PRO</span>
            </div>
            <p className="text-[9px] text-slate-400 tracking-widest uppercase flex items-center gap-1">
              <Activity className="w-3 h-3 text-cyber-green animate-ping shrink-0" />
              THREAT INTELLIGENCE & DEFENSIVE ENGINE
            </p>
          </div>
        </div>

        {/* Global Tabs Navigation */}
        <nav className="flex gap-1.5 p-1 bg-cyber-bg/60 border border-cyber-border rounded-lg max-sm:w-full max-sm:justify-between">
          <button
            onClick={() => setActiveTab('monitor')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'monitor' 
                ? 'bg-cyber-cyan/15 border border-cyber-cyan text-cyber-cyan shadow-[0_0_8px_rgba(0,240,255,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Live Monitor</span>
          </button>

          <button
            onClick={() => setActiveTab('country')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'country' 
                ? 'bg-cyber-cyan/15 border border-cyber-cyan text-cyber-cyan shadow-[0_0_8px_rgba(0,240,255,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Country Monitor</span>
          </button>

          <button
            onClick={() => setActiveTab('apt')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'apt' 
                ? 'bg-cyber-purple/15 border border-cyber-purple text-cyber-purple shadow-[0_0_8px_rgba(157,0,255,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span className="hidden md:inline">APT Actors</span>
          </button>

          <button
            onClick={() => setActiveTab('cves')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'cves' 
                ? 'bg-cyber-yellow/15 border border-cyber-yellow text-cyber-yellow shadow-[0_0_8px_rgba(255,223,0,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span className="hidden md:inline">CVE Registry</span>
          </button>

          <button
            onClick={() => setActiveTab('feeds')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'feeds' 
                ? 'bg-cyber-green/15 border border-cyber-green text-cyber-green shadow-[0_0_8px_rgba(57,255,20,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Rss className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Feeds Hub</span>
          </button>

          <button
            onClick={() => setActiveTab('toolkit')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider transition-all ${
              activeTab === 'toolkit' 
                ? 'bg-cyber-pink/15 border border-cyber-pink text-cyber-pink shadow-[0_0_8px_rgba(255,0,127,0.15)]' 
                : 'border border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Defensive Toolkit</span>
          </button>
        </nav>

        {/* IP Search bar in header */}
        <form onSubmit={handleSearch} className="flex items-center gap-2 max-w-sm w-full max-lg:max-w-none max-lg:w-full">
          <div className="relative flex-1">
            <input
              type="text"
              placeholder="TARGET IP SCOPE SCAN..."
              value={ipQuery}
              onChange={(e) => setIpQuery(e.target.value)}
              className="w-full bg-cyber-bg/90 border border-cyber-border rounded px-3 py-1.5 pl-9 text-[10px] focus:outline-none focus:border-cyber-cyan focus:shadow-[0_0_8px_rgba(0,240,255,0.15)] transition-all placeholder:text-slate-600 text-cyber-cyan uppercase font-bold"
            />
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          </div>
          <button
            type="submit"
            disabled={ipLoading}
            className="bg-cyber-cyan/15 hover:bg-cyber-cyan/35 border border-cyber-cyan/50 hover:border-cyber-cyan text-cyber-cyan px-3 py-1.5 rounded text-[10px] font-bold uppercase transition-all tracking-wider disabled:opacity-50"
          >
            {ipLoading ? 'RUNNING...' : 'SCAN'}
          </button>
        </form>
      </header>

      {/* Main Container */}
      <main className="flex-1 p-6">
        
        {/* TAB 1: LIVE MONITOR */}
        {activeTab === 'monitor' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            
            {/* Map and Charts Grid Column */}
            <div className="lg:col-span-3 flex flex-col gap-6">
              
              {/* Map Panel */}
              <div className="bg-cyber-card border border-cyber-border rounded-lg overflow-hidden flex flex-col min-h-[460px] relative">
                
                {/* Map Header */}
                <div className="bg-cyber-card-light px-4 py-2.5 border-b border-cyber-border flex flex-wrap items-center justify-between gap-3">
                  <span className="text-xs text-cyber-cyan font-bold tracking-wider flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-cyber-green animate-ping" />
                    GLOBAL ATTACK PATHWAY ROUTER [GEO-COORDINATE FLIGHTS]
                  </span>
                  
                  {/* Simulation Controls Overlay */}
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setIsLive(!isLive)}
                      title={isLive ? "Pause Feed Simulation" : "Resume Feed Simulation"}
                      className={`p-1 border rounded transition-all flex items-center gap-1.5 text-[9px] font-bold uppercase px-2 ${
                        isLive 
                          ? 'border-cyber-pink/50 text-cyber-pink hover:bg-cyber-pink/15' 
                          : 'border-cyber-green/50 text-cyber-green hover:bg-cyber-green/15'
                      }`}
                    >
                      {isLive ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                      {isLive ? "Pause" : "Resume"}
                    </button>

                    <div className="flex items-center gap-1 border border-cyber-border rounded bg-cyber-bg/50 px-1.5 py-0.5">
                      <span className="text-[8px] text-slate-500 uppercase font-black mr-1">Speed:</span>
                      {[1, 2, 5].map((multiplier) => (
                        <button
                          key={multiplier}
                          onClick={() => setSpeedMultiplier(multiplier)}
                          className={`text-[9px] font-extrabold px-1 rounded transition-all ${
                            speedMultiplier === multiplier
                              ? 'bg-cyber-cyan text-cyber-bg font-black'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {multiplier}x
                        </button>
                      ))}
                    </div>

                  </div>
                </div>

                {/* Map Display */}
                <div className="flex-1 w-full relative min-h-[400px]">
                  <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={true} className="z-10">
                    <TileLayer
                      url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                      attribution='&copy; <a href="https://carto.com/">CARTO</a>'
                    />
                    
                    {/* Render static attack routes (connecting lines) */}
                    {mapData.map((attack) => (
                      <React.Fragment key={attack.id}>
                        {/* Source Marker */}
                        <CircleMarker
                          center={[attack.origin.lat, attack.origin.lon]}
                          radius={3.5}
                          fillColor="#ff007f"
                          color="#ff007f"
                          weight={1}
                          fillOpacity={0.4}
                        />

                        {/* Destination Marker */}
                        <CircleMarker
                          center={[attack.target.lat, attack.target.lon]}
                          radius={4.5}
                          fillColor="#00f0ff"
                          color="#00f0ff"
                          weight={1}
                          fillOpacity={0.4}
                        />

                        {/* Dashed Polyline Route */}
                        <Polyline
                          positions={[
                            [attack.origin.lat, attack.origin.lon],
                            [attack.target.lat, attack.target.lon]
                          ]}
                          color={attack.severity === 'high' ? '#ff007f' : attack.severity === 'medium' ? '#ffdf00' : '#00f0ff'}
                          weight={1.5}
                          opacity={0.3}
                          dashArray="4, 4"
                        />
                      </React.Fragment>
                    ))}

                    {/* Render live flying packets */}
                    {flyingPackets.map((packet) => (
                      <CircleMarker
                        key={packet.id}
                        center={packet.current}
                        radius={4}
                        fillColor={packet.severity === 'high' ? '#ff007f' : packet.severity === 'medium' ? '#ffdf00' : '#00f0ff'}
                        color="#ffffff"
                        weight={1.2}
                        fillOpacity={1.0}
                        className="animate-pulse"
                      >
                        <Popup>
                          <div className="text-[10px] font-mono text-slate-100 bg-cyber-card p-2 rounded border border-cyber-border">
                            <div className="font-extrabold text-cyber-cyan border-b border-cyber-border pb-1 mb-1">LIVE VECTOR IN FLIGHT</div>
                            <div><span className="text-slate-400 font-bold">Origin:</span> {packet.originCountry}</div>
                            <div><span className="text-slate-400 font-bold">Target:</span> {packet.targetCountry}</div>
                            <div><span className="text-slate-400 font-bold">Payload:</span> {packet.type}</div>
                            <div><span className="text-slate-400 font-bold">Risk Level:</span> <span className="uppercase font-extrabold text-cyber-pink">{packet.severity}</span></div>
                          </div>
                        </Popup>
                      </CircleMarker>
                    ))}

                    {/* Render exploding shockwaves */}
                    {shockwaves.map((wave) => (
                      <CircleMarker
                        key={wave.id}
                        center={wave.center}
                        radius={wave.radius}
                        fillColor="transparent"
                        color={wave.severity === 'high' ? '#ff007f' : wave.severity === 'medium' ? '#ffdf00' : '#00f0ff'}
                        weight={1.5}
                        opacity={Math.max(0, (24 - wave.radius) / 24)}
                      />
                    ))}
                  </MapContainer>
                </div>
              </div>

              {/* Analytics Subgrid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* BarChart Analysis */}
                <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col">
                  <h2 className="text-xs text-cyber-cyan font-bold tracking-wider uppercase border-b border-cyber-border pb-3 mb-4 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyber-cyan animate-pulse" />
                    Attack Vectors Distribution
                  </h2>
                  <div className="h-52 w-full">
                    {chartData.length > 0 ? (
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1a1a36" />
                          <XAxis dataKey="name" stroke="#64748b" fontSize={9} />
                          <YAxis stroke="#64748b" fontSize={9} />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: '#0b0b16',
                              borderColor: '#1a1a36',
                              color: '#f1f5f9',
                              fontFamily: 'monospace',
                              fontSize: '11px'
                            }}
                          />
                          <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                            {chartData.map((entry, index) => {
                              const colors = ['#ff007f', '#00f0ff', '#9d00ff', '#ffdf00', '#39ff14'];
                              return <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />;
                            })}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    ) : (
                      <div className="h-full flex items-center justify-center text-xs text-slate-500">
                        WAITING FOR VECTOR DATASTREAM...
                      </div>
                    )}
                  </div>
                </div>

                {/* IP Reputation Analyzer Panel */}
                <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col justify-between">
                  <div>
                    <h2 className="text-xs text-cyber-pink font-bold tracking-wider uppercase border-b border-cyber-border pb-3 mb-4 flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-cyber-pink" />
                      IP Reputation Scanner
                    </h2>
                    
                    {ipError && (
                      <div className="text-xs bg-cyber-pink/10 border border-cyber-pink/30 text-cyber-pink p-3 rounded mb-3 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 shrink-0 animate-bounce" />
                        {ipError}
                      </div>
                    )}

                    {ipResult ? (
                      <div className="flex flex-col gap-2.5 text-xs">
                        <div className="flex justify-between items-center border-b border-cyber-border/40 pb-1.5">
                          <span className="text-slate-400 font-extrabold">IP SCOPE:</span>
                          <span className="font-black text-cyber-cyan">{ipResult.ip}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-cyber-border/40 pb-1.5">
                          <span className="text-slate-400 font-extrabold">RISK SCALE:</span>
                          <span className={`font-black ${ipResult.risk_score > 70 ? 'text-cyber-pink' : ipResult.risk_score > 40 ? 'text-cyber-yellow' : 'text-cyber-green'}`}>
                            {ipResult.risk_score} / 100 ({ipResult.category})
                          </span>
                        </div>
                        <div className="flex justify-between items-center border-b border-cyber-border/40 pb-1.5">
                          <span className="text-slate-400 font-extrabold">THREAT FAMILY:</span>
                          <span className="text-cyber-pink font-bold">{ipResult.threat_types.join(', ')}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-cyber-border/40 pb-1.5">
                          <span className="text-slate-400 font-extrabold">ISP/AS BLOCK:</span>
                          <span className="text-slate-200 truncate max-w-[180px]">{ipResult.isp}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-cyber-border/40 pb-1.5">
                          <span className="text-slate-400 font-extrabold">GEOLOCATION:</span>
                          <span className="text-slate-200">{ipResult.country} ({ipResult.country_code})</span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-slate-400 font-extrabold">LAST SCAN DETECT:</span>
                          <span className="text-cyber-cyan font-bold">{new Date(ipResult.last_active).toLocaleTimeString()}</span>
                        </div>
                      </div>
                    ) : !ipError ? (
                      <div className="flex flex-col items-center justify-center text-center p-6 border border-dashed border-cyber-border/60 rounded bg-cyber-bg/40">
                        <Globe className="w-8 h-8 text-slate-700 mb-2 animate-pulse" />
                        <p className="text-[10px] text-slate-400 uppercase max-w-[220px] leading-relaxed">
                          Enter target IPv4 hosts in the header lookup console to extract deep vector reputation.
                        </p>
                      </div>
                    ) : null}
                  </div>

                  {ipResult && (
                    <button
                      onClick={() => toggleToolkitIp(ipResult.ip)}
                      className={`mt-4 w-full border text-[10px] font-extrabold py-1.5 rounded transition-all uppercase ${
                        selectedBlockedIps.has(ipResult.ip)
                          ? 'bg-cyber-pink/20 border-cyber-pink text-cyber-pink'
                          : 'bg-transparent border-cyber-border hover:border-cyber-cyan text-slate-300 hover:text-cyber-cyan'
                      }`}
                    >
                      {selectedBlockedIps.has(ipResult.ip) ? 'Remove Block Rule' : 'Stage Block Rule'}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Right Column: Threats Feed Panel */}
            <div className="lg:col-span-1 bg-cyber-card border border-cyber-border rounded-lg flex flex-col h-[740px] overflow-hidden">
              
              {/* Feed Control Bar */}
              <div className="bg-cyber-card-light px-4 py-3 border-b border-cyber-border flex flex-col gap-2">
                <span className="text-xs text-cyber-cyan font-bold tracking-wider flex items-center justify-between">
                  <span className="flex items-center gap-1.5">
                    <Server className="w-4 h-4 text-cyber-cyan" />
                    LIVE SENSOR FEED ({threats.length} LOGS RETRIEVED)
                  </span>
                  <div className="flex gap-1">
                    <button
                      onClick={() => exportThreats('csv')}
                      title="Export CSV Feed"
                      className="p-1 hover:bg-cyber-bg rounded border border-cyber-border text-slate-400 hover:text-cyber-cyan text-[8px] font-extrabold uppercase"
                    >
                      CSV
                    </button>
                    <button
                      onClick={() => exportThreats('json')}
                      title="Export JSON Feed"
                      className="p-1 hover:bg-cyber-bg rounded border border-cyber-border text-slate-400 hover:text-cyber-cyan text-[8px] font-extrabold uppercase"
                    >
                      JSON
                    </button>
                  </div>
                </span>

                {/* Filter and Search inside Feed */}
                <div className="flex flex-col gap-1.5 mt-1">
                  <div className="relative">
                    <input
                      type="text"
                      placeholder="FILTER FEED INDICATORS..."
                      value={feedSearch}
                      onChange={(e) => setFeedSearch(e.target.value)}
                      className="w-full bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-[9px] focus:outline-none focus:border-cyber-cyan text-cyber-cyan uppercase font-bold placeholder:text-slate-700"
                    />
                    {feedSearch && (
                      <X 
                        onClick={() => setFeedSearch('')} 
                        className="w-3.5 h-3.5 text-slate-500 absolute right-2 top-1.5 cursor-pointer hover:text-white"
                      />
                    )}
                  </div>
                  
                  {/* Severity Filter Tabs */}
                  <div className="flex gap-1 w-full justify-between">
                    {['all', 'high', 'medium', 'low'].map((tab) => (
                      <button
                        key={tab}
                        onClick={() => setFeedFilter(tab)}
                        className={`flex-1 py-1 text-[8px] font-extrabold uppercase rounded border transition-all ${
                          feedFilter === tab
                            ? 'bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan'
                            : 'bg-transparent border-cyber-border text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {tab}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Live threats feed listing */}
              <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2.5">
                {filteredThreats.map((threat) => (
                  <div
                    key={threat.id}
                    onClick={() => openThreatModal(threat)}
                    className="border border-cyber-border bg-cyber-bg/50 hover:bg-cyber-card-light/40 p-2.5 rounded transition-all flex flex-col gap-1.5 relative overflow-hidden group cursor-pointer"
                  >
                    {/* Lateral Indicator Line */}
                    <div className="absolute top-0 left-0 h-full w-1 transition-all group-hover:w-1.5 bg-current text-opacity-80"
                      style={{ color: threat.severity === 'high' ? '#ff007f' : threat.severity === 'medium' ? '#ffdf00' : '#00f0ff' }}
                    />
                    
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-cyber-cyan font-bold tracking-wider group-hover:text-white transition-colors">{threat.indicator}</span>
                      <span className={`px-1.5 py-0.5 border rounded-full text-[8px] font-bold uppercase ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}
                      </span>
                    </div>
                    
                    <div className="text-[11px] text-slate-200 font-bold truncate">{threat.pulse_name}</div>
                    
                    <div className="text-[8px] text-slate-500 flex items-center justify-between mt-0.5 border-t border-cyber-border/40 pt-1.5">
                      <span className="flex items-center gap-1">
                        <Globe className="w-2.5 h-2.5 text-slate-600" />
                        {threat.country}
                      </span>
                      <span className="flex items-center gap-1 font-semibold">
                        <Clock className="w-2.5 h-2.5 text-slate-600" />
                        {new Date(threat.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                ))}
                {filteredThreats.length === 0 && (
                  <div className="h-full flex flex-col items-center justify-center text-[10px] text-slate-600 py-12">
                    <AlertTriangle className="w-6 h-6 text-slate-700 mb-2" />
                    NO CORRESPONDING LOGS FILTERED
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {/* TAB 1B: COUNTRY THREAT MONITOR */}
        {activeTab === 'country' && (() => {
          // Dynamic metrics calculations for selected country
          const countryThreats = threats.filter(t => t.country_code === selectedCountry.code);
          const inboundAttacksCount = mapData.filter(a => a.target.code === selectedCountry.code).length;
          const outboundAttacksCount = mapData.filter(a => a.origin.code === selectedCountry.code).length;
          
          // Determine top attack vector
          const vectorCounts = countryThreats.reduce((acc, curr) => {
            acc[curr.pulse_name] = (acc[curr.pulse_name] || 0) + 1;
            return acc;
          }, {});
          const topVector = Object.entries(vectorCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "None Detected";

          // Calculate risk score
          const highRiskCount = countryThreats.filter(t => t.severity === 'high').length;
          const medRiskCount = countryThreats.filter(t => t.severity === 'medium').length;
          const lowRiskCount = countryThreats.filter(t => t.severity === 'low').length;
          const totalRiskScore = Math.min(100, Math.round((highRiskCount * 20) + (medRiskCount * 10) + (lowRiskCount * 5)));

          // Chart data for threat type breakdown
          const chartData = Object.entries(vectorCounts).map(([name, value]) => ({ name, value }));

          return (
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 animate-fadeIn">
              {/* Left Column: Countries Sidebar */}
              <div className="lg:col-span-1 bg-cyber-card border border-cyber-border rounded-lg flex flex-col h-[740px] overflow-hidden">
                <div className="bg-cyber-card-light px-4 py-3 border-b border-cyber-border">
                  <span className="text-xs text-cyber-cyan font-bold tracking-wider flex items-center gap-1.5">
                    <Globe className="w-4 h-4 text-cyber-cyan animate-pulse" />
                    MONITORED REGIONS
                  </span>
                  <p className="text-[9px] text-slate-500 uppercase mt-1 leading-relaxed">
                    Select a nation to inspect localized threat events and compile security posture.
                  </p>
                </div>
                
                <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2">
                  {countries.map((c) => {
                    const cThreats = threats.filter(t => t.country_code === c.code);
                    const cHigh = cThreats.filter(t => t.severity === 'high').length;
                    const cIn = mapData.filter(a => a.target.code === c.code).length;
                    const cOut = mapData.filter(a => a.origin.code === c.code).length;

                    // Determine active severity class
                    let severityBadge = "text-cyber-green bg-cyber-green/10 border-cyber-green/30";
                    let severityLabel = "Low Risk";
                    if (cHigh > 2) {
                      severityBadge = "text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30 animate-pulse";
                      severityLabel = "Critical";
                    } else if (cHigh > 0) {
                      severityBadge = "text-cyber-purple bg-cyber-purple/10 border-cyber-purple/30";
                      severityLabel = "High";
                    } else if (cThreats.length > 0) {
                      severityBadge = "text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30";
                      severityLabel = "Medium";
                    }

                    const isSelected = selectedCountry.code === c.code;

                    return (
                      <div
                        key={c.code}
                        onClick={() => setSelectedCountry(c)}
                        className={`border p-3 rounded cursor-pointer transition-all flex flex-col gap-1.5 relative overflow-hidden group ${
                          isSelected
                            ? 'border-cyber-cyan bg-cyber-cyan/5 shadow-[0_0_12px_rgba(0,240,255,0.1)]'
                            : 'border-cyber-border bg-cyber-bg/40 hover:bg-cyber-card-light/20 hover:border-slate-500'
                        }`}
                      >
                        {/* Selected Indicator bar */}
                        {isSelected && (
                          <div className="absolute left-0 top-0 h-full w-1.5 bg-cyber-cyan" />
                        )}

                        <div className="flex items-center justify-between text-[11px] font-bold">
                          <span className="flex items-center gap-1.5 text-slate-100 group-hover:text-cyber-cyan transition-colors">
                            <span className="text-sm shrink-0" role="img" aria-label={c.name}>
                              {c.code === 'US' && '🇺🇸'}
                              {c.code === 'CN' && '🇨🇳'}
                              {c.code === 'RU' && '🇷🇺'}
                              {c.code === 'DE' && '🇩🇪'}
                              {c.code === 'BR' && '🇧🇷'}
                              {c.code === 'IN' && '🇮🇳'}
                              {c.code === 'GB' && '🇬🇧'}
                              {c.code === 'UA' && '🇺🇦'}
                              {c.code === 'NL' && '🇳🇱'}
                              {c.code === 'JP' && '🇯🇵'}
                            </span>
                            {c.name}
                          </span>
                          <span className={`px-1.5 py-0.5 border rounded-full text-[8px] font-bold uppercase ${severityBadge}`}>
                            {severityLabel}
                          </span>
                        </div>

                        <div className="flex justify-between items-center text-[9px] text-slate-400 border-t border-cyber-border/40 pt-1.5 mt-0.5">
                          <span>Inbound: <strong className="text-cyber-cyan font-bold">{cIn}</strong></span>
                          <span>Outbound: <strong className="text-cyber-pink font-bold">{cOut}</strong></span>
                          <span>Alerts: <strong className="text-slate-200 font-bold">{cThreats.length}</strong></span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Right Column: Country Analytics & Prevention Advisor */}
              <div className="lg:col-span-3 flex flex-col gap-6 h-[740px] overflow-y-auto pr-1">
                {/* Header panel */}
                <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                  <div>
                    <h2 className="text-lg font-black text-slate-100 flex items-center gap-2">
                      <span className="text-2xl" role="img" aria-label={selectedCountry.name}>
                        {selectedCountry.code === 'US' && '🇺🇸'}
                        {selectedCountry.code === 'CN' && '🇨🇳'}
                        {selectedCountry.code === 'RU' && '🇷🇺'}
                        {selectedCountry.code === 'DE' && '🇩🇪'}
                        {selectedCountry.code === 'BR' && '🇧🇷'}
                        {selectedCountry.code === 'IN' && '🇮🇳'}
                        {selectedCountry.code === 'GB' && '🇬🇧'}
                        {selectedCountry.code === 'UA' && '🇺🇦'}
                        {selectedCountry.code === 'NL' && '🇳🇱'}
                        {selectedCountry.code === 'JP' && '🇯🇵'}
                      </span>
                      {selectedCountry.name.toUpperCase()} THREAT METRICS
                    </h2>
                    <p className="text-[10px] text-slate-400 uppercase mt-1 flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-cyber-cyan shrink-0 animate-bounce" />
                      COORD BASE: LAT {selectedCountry.lat.toFixed(4)} / LON {selectedCountry.lon.toFixed(4)} • {countryThreats.length} THREAT LOGS RETRIEVED
                    </p>
                  </div>

                  <div className="w-full md:w-60">
                    <div className="flex justify-between text-[9px] font-extrabold text-slate-400 mb-1">
                      <span>CALCULATED THREAT INDEX</span>
                      <span className={`${totalRiskScore > 60 ? 'text-cyber-pink animate-pulse' : totalRiskScore > 30 ? 'text-cyber-yellow' : 'text-cyber-green'} font-black`}>
                        {totalRiskScore}% ({totalRiskScore > 60 ? 'CRITICAL' : totalRiskScore > 30 ? 'ELEVATED' : 'STABLE'})
                      </span>
                    </div>
                    <div className="w-full bg-cyber-bg/90 border border-cyber-border h-3 rounded overflow-hidden p-0.5">
                      <div 
                        className={`h-full rounded-sm transition-all duration-500 ${
                          totalRiskScore > 60 ? 'bg-cyber-pink shadow-[0_0_8px_#ff007f]' : totalRiskScore > 30 ? 'bg-cyber-yellow shadow-[0_0_8px_#ffdf00]' : 'bg-cyber-green shadow-[0_0_8px_#39ff14]'
                        }`} 
                        style={{ width: `${totalRiskScore}%` }} 
                      />
                    </div>
                  </div>
                </div>

                {/* Stats cards grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 flex items-center justify-between transition-all hover:border-cyber-cyan/50">
                    <div>
                      <div className="text-[9px] text-slate-500 uppercase font-black">INBOUND VECTORS</div>
                      <div className="text-xl font-black text-cyber-cyan mt-1">{inboundAttacksCount}</div>
                      <div className="text-[8px] text-slate-400 mt-1 uppercase">Targeted intrusion attempts</div>
                    </div>
                    <div className="p-2.5 bg-cyber-cyan/10 border border-cyber-cyan/30 rounded">
                      <Globe className="w-5 h-5 text-cyber-cyan" />
                    </div>
                  </div>

                  <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 flex items-center justify-between transition-all hover:border-cyber-pink/50">
                    <div>
                      <div className="text-[9px] text-slate-500 uppercase font-black">OUTBOUND VECTORS</div>
                      <div className="text-xl font-black text-cyber-pink mt-1">{outboundAttacksCount}</div>
                      <div className="text-[8px] text-slate-400 mt-1 uppercase">Attacks originating from region</div>
                    </div>
                    <div className="p-2.5 bg-cyber-pink/10 border border-cyber-pink/30 rounded">
                      <ShieldAlert className="w-5 h-5 text-cyber-pink" />
                    </div>
                  </div>

                  <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 flex items-center justify-between transition-all hover:border-cyber-yellow/50">
                    <div>
                      <div className="text-[9px] text-slate-500 uppercase font-black">PRIMARY ATTACK FAMILY</div>
                      <div className="text-xs font-black text-cyber-yellow mt-2 truncate max-w-[170px]" title={topVector}>{topVector}</div>
                      <div className="text-[8px] text-slate-400 mt-1.5 uppercase">Most frequent threat signature</div>
                    </div>
                    <div className="p-2.5 bg-cyber-yellow/10 border border-cyber-yellow/30 rounded">
                      <Server className="w-5 h-5 text-cyber-yellow" />
                    </div>
                  </div>
                </div>

                {/* Donut Chart & Vector logs */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  {/* Recharts donut chart */}
                  <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col">
                    <h3 className="text-xs text-cyber-cyan font-bold tracking-wider uppercase border-b border-cyber-border pb-3 mb-4 flex items-center gap-1.5">
                      <Activity className="w-4 h-4 text-cyber-cyan" />
                      Active Vectors Distribution
                    </h3>
                    
                    <div className="h-56 w-full flex items-center justify-center relative">
                      {chartData.length > 0 ? (
                        <ResponsiveContainer width="100%" height="100%">
                          <PieChart>
                            <Pie
                              data={chartData}
                              cx="50%"
                              cy="50%"
                              innerRadius={50}
                              outerRadius={75}
                              paddingAngle={4}
                              dataKey="value"
                            >
                              {chartData.map((entry, index) => {
                                const colors = ['#00f0ff', '#ff007f', '#9d00ff', '#ffdf00', '#39ff14'];
                                return <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />;
                              })}
                            </Pie>
                            <Tooltip
                              contentStyle={{
                                backgroundColor: '#0b0b16',
                                borderColor: '#1a1a36',
                                color: '#f1f5f9',
                                fontFamily: 'monospace',
                                fontSize: '10px'
                              }}
                            />
                          </PieChart>
                        </ResponsiveContainer>
                      ) : (
                        <div className="text-[10px] text-slate-500 uppercase">NO ACTIVE THREATS LOGGED</div>
                      )}
                      
                      {/* Custom Legend Overlay */}
                      {chartData.length > 0 && (
                        <div className="absolute right-4 top-0 bottom-0 overflow-y-auto max-w-[120px] flex flex-col justify-center gap-1.5 text-[8px] font-bold uppercase select-none">
                          {chartData.map((entry, index) => {
                            const colors = ['#00f0ff', '#ff007f', '#9d00ff', '#ffdf00', '#39ff14'];
                            return (
                              <div key={index} className="flex items-center gap-1.5 text-slate-300">
                                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: colors[index % colors.length] }} />
                                <span className="truncate max-w-[90px]">{entry.name}</span>
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Active incident logs */}
                  <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col">
                    <h3 className="text-xs text-cyber-pink font-bold tracking-wider uppercase border-b border-cyber-border pb-3 mb-4 flex items-center gap-1.5">
                      <Terminal className="w-4 h-4 text-cyber-pink" />
                      Active Incident Stream Log
                    </h3>
                    
                    <div className="flex-1 overflow-y-auto max-h-56 pr-1 flex flex-col gap-2">
                      {countryThreats.map((threat) => (
                        <div 
                          key={threat.id}
                          className="bg-cyber-bg/50 border border-cyber-border p-2.5 rounded text-[9px] flex justify-between items-center group hover:bg-cyber-card-light/20 transition-all cursor-pointer"
                          onClick={() => openThreatModal(threat)}
                        >
                          <div className="flex flex-col gap-0.5">
                            <span className="text-cyber-cyan font-bold">{threat.indicator}</span>
                            <span className="text-slate-400 font-semibold truncate max-w-[180px]">{threat.pulse_name}</span>
                          </div>
                          <div className="text-right flex flex-col items-end gap-1">
                            <span className={`px-1.5 py-0.5 rounded-full border text-[7px] font-black uppercase ${
                              threat.severity === 'high' ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/20' : threat.severity === 'medium' ? 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/20' : 'text-cyber-cyan bg-cyber-cyan/10 border-cyber-cyan/20'
                            }`}>
                              {threat.severity}
                            </span>
                            <span className="text-slate-500 font-bold">{new Date(threat.timestamp).toLocaleTimeString()}</span>
                          </div>
                        </div>
                      ))}
                      {countryThreats.length === 0 && (
                        <div className="h-full flex items-center justify-center text-[10px] text-slate-500 py-12 uppercase">
                          NO ACTIVE INCIDENTS REGISTERED
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* PREVENTION AND MITIGATION ADVISOR */}
                <div className="bg-cyber-card border border-cyber-border rounded-lg p-5">
                  <h3 className="text-xs text-cyber-yellow font-bold tracking-wider uppercase border-b border-cyber-border pb-3 mb-4 flex items-center gap-1.5">
                    <Shield className="w-4 h-4 text-cyber-yellow" />
                    SECURITY RECOMMENDATIONS & PREVENTION ADVISOR
                  </h3>

                  <div className="flex flex-col gap-4">
                    {/* Resolve unique active threat types for this country */}
                    {(() => {
                      const activeThreatNames = Array.from(new Set(countryThreats.map(t => t.pulse_name)));
                      
                      if (activeThreatNames.length === 0) {
                        return (
                          <div className="p-6 border border-dashed border-cyber-green/20 bg-cyber-green/5 text-cyber-green rounded-lg flex items-center gap-3 text-[10px] uppercase font-bold">
                            <Check className="w-5 h-5 shrink-0" />
                            <div>
                              <strong className="block text-xs font-black">Region Posture Stable</strong>
                              No active signature matches identified. Continuous background monitoring is engaged. No local firewall overrides required.
                            </div>
                          </div>
                        );
                      }

                      return activeThreatNames.map((threatName) => {
                        const strategy = preventionStrategies[threatName];
                        if (!strategy) return null;

                        const isCopied = copiedRulesKey === threatName;

                        return (
                          <details 
                            key={threatName}
                            className="group border border-cyber-border bg-cyber-bg/40 rounded-lg overflow-hidden transition-all duration-300 open:border-cyber-yellow open:shadow-[0_0_12px_rgba(255,223,0,0.05)]"
                          >
                            <summary className="bg-cyber-card-light/50 hover:bg-cyber-card-light px-4 py-3 cursor-pointer select-none text-[11px] font-bold text-slate-200 flex justify-between items-center list-none outline-none">
                              <span className="flex items-center gap-2">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyber-yellow animate-ping shrink-0" />
                                {threatName.toUpperCase()} DETECTION ADVISORY
                              </span>
                              <span className="text-[8px] text-cyber-yellow font-black group-open:rotate-180 transition-transform uppercase">
                                [Toggle Details]
                              </span>
                            </summary>
                            
                            <div className="p-4 border-t border-cyber-border/60 flex flex-col gap-4 text-xs">
                              {/* Explanation */}
                              <div>
                                <span className="text-slate-400 font-extrabold text-[8px] uppercase block mb-1">Incident Profile</span>
                                <p className="text-slate-300 leading-relaxed bg-cyber-bg/50 p-2.5 border border-cyber-border rounded">
                                  {strategy.description}
                                </p>
                              </div>

                              {/* Checklist */}
                              <div>
                                <span className="text-slate-400 font-extrabold text-[8px] uppercase block mb-1.5">Actionable Prevention Recommendations</span>
                                <ul className="flex flex-col gap-1.5 pl-1">
                                  {strategy.recommendations.map((rec, i) => (
                                    <li key={i} className="text-[10px] text-slate-200 font-semibold flex items-start gap-2">
                                      <span className="text-cyber-yellow shrink-0 mt-0.5">•</span>
                                      <span>{rec}</span>
                                    </li>
                                  ))}
                                </ul>
                              </div>

                              {/* Commands block */}
                              {strategy.action_commands && (
                                <div className="flex flex-col gap-1.5">
                                  <span className="text-slate-400 font-extrabold text-[8px] uppercase block">Defensive Mitigation Rules</span>
                                  <div className="relative bg-cyber-bg border border-cyber-border rounded p-3 pt-4 font-mono text-[10px] text-slate-300 overflow-x-auto">
                                    <pre className="whitespace-pre">{strategy.action_commands}</pre>
                                    <button
                                      onClick={() => {
                                        navigator.clipboard.writeText(strategy.action_commands);
                                        setCopiedRulesKey(threatName);
                                        setTimeout(() => setCopiedRulesKey(null), 2000);
                                      }}
                                      className="absolute top-2 right-2 p-1.5 bg-cyber-card border border-cyber-border hover:border-cyber-yellow text-slate-400 hover:text-cyber-yellow rounded transition-all flex items-center gap-1 text-[8px] font-bold uppercase"
                                    >
                                      {isCopied ? <Check className="w-3 h-3 text-cyber-green" /> : <Copy className="w-3 h-3" />}
                                      {isCopied ? 'Copied' : 'Copy'}
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          </details>
                        );
                      });
                    })()}
                  </div>
                </div>
              </div>
            </div>
          );
        })()}

        {/* TAB 2: APT THREAT ACTORS */}
        {activeTab === 'apt' && (
          <div className="flex flex-col gap-6">
            
            {/* Control header */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-bold text-cyber-purple tracking-widest uppercase flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyber-purple animate-pulse" />
                  Advanced Persistent Threat (APT) Profile Registry
                </h2>
                <p className="text-[10px] text-slate-400 mt-1 uppercase">
                  State-sponsored adversary databases. Track nation-state origin groups and exploitation signatures.
                </p>
              </div>

              {/* Search filter */}
              <div className="relative w-full md:max-w-xs">
                <input
                  type="text"
                  placeholder="SEARCH APT GROUPS OR TACTICS..."
                  value={aptSearch}
                  onChange={(e) => setAptSearch(e.target.value)}
                  className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-1.5 pl-9 text-[10px] focus:outline-none focus:border-cyber-purple text-cyber-purple uppercase font-bold placeholder:text-slate-700"
                />
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            {/* APT Actors Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {aptGroups
                .filter(apt => {
                  const matchSearch = apt.name.toLowerCase().includes(aptSearch.toLowerCase()) || 
                                      apt.origin.toLowerCase().includes(aptSearch.toLowerCase()) ||
                                      apt.sectors.some(s => s.toLowerCase().includes(aptSearch.toLowerCase())) ||
                                      apt.malware.some(m => m.toLowerCase().includes(aptSearch.toLowerCase()));
                  return matchSearch;
                })
                .map(apt => (
                  <div
                    key={apt.name}
                    className="bg-cyber-card border border-cyber-border hover:border-cyber-purple rounded-lg p-5 flex flex-col justify-between transition-all hover:-translate-y-1 relative group overflow-hidden"
                  >
                    {/* Shadow overlay background */}
                    <div className="absolute -top-12 -right-12 w-24 h-24 bg-cyber-purple/5 rounded-full blur-xl group-hover:bg-cyber-purple/10 transition-all" />
                    
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-2.5">
                        <h3 className="font-extrabold text-sm text-slate-100 group-hover:text-cyber-purple transition-colors">{apt.name}</h3>
                        <span className={`px-2 py-0.5 border text-[8px] font-black uppercase rounded-full ${
                          apt.threat_level === 'Critical' 
                            ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30' 
                            : 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30'
                        }`}>
                          {apt.threat_level}
                        </span>
                      </div>
                      
                      <div className="text-[10px] text-slate-400 mb-3 uppercase flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-slate-500" />
                        NATION ORIGIN: <span className="text-slate-200 font-bold">{apt.origin}</span>
                      </div>
                      
                      <p className="text-[11px] text-slate-300 leading-relaxed line-clamp-3 mb-4">
                        {apt.description}
                      </p>

                      <div className="flex flex-wrap gap-1 mb-4">
                        {apt.sectors.slice(0, 3).map((s, idx) => (
                          <span key={idx} className="text-[8px] bg-cyber-bg border border-cyber-border/80 px-1.5 py-0.5 rounded text-slate-400 font-bold uppercase">
                            {s}
                          </span>
                        ))}
                        {apt.sectors.length > 3 && (
                          <span className="text-[8px] text-slate-500 font-bold self-center">+{apt.sectors.length - 3} MORE</span>
                        )}
                      </div>
                    </div>

                    <button
                      onClick={() => openAptModal(apt)}
                      className="w-full border border-cyber-purple/40 hover:border-cyber-purple bg-cyber-purple/5 hover:bg-cyber-purple/20 text-cyber-purple text-[10px] font-black py-2 rounded transition-all uppercase tracking-wider"
                    >
                      Analyze Attack Profile
                    </button>
                  </div>
                ))}
            </div>

          </div>
        )}

        {/* TAB 3: CVE REGISTRY */}
        {activeTab === 'cves' && (
          <div className="flex flex-col gap-6">
            
            {/* Control header */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg p-4 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-sm font-bold text-cyber-yellow tracking-widest uppercase flex items-center gap-2">
                  <BookOpen className="w-4 h-4 text-cyber-yellow animate-pulse" />
                  Common Vulnerabilities and Exposures (CVE) Registry ({cves.length} Records Retrieved)
                </h2>
                <p className="text-[10px] text-slate-400 mt-1 uppercase">
                  Query critical hardware and software vulnerabilities. Cross-referenced with exploitation mitigations.
                </p>
              </div>

              {/* Filters grid */}
              <div className="flex flex-wrap gap-3 w-full md:w-auto">
                {/* Severity select filter */}
                <div className="flex items-center gap-1.5 border border-cyber-border rounded bg-cyber-bg/50 px-2 py-1">
                  <Filter className="w-3.5 h-3.5 text-slate-500" />
                  <span className="text-[8px] text-slate-500 font-bold uppercase">Severity:</span>
                  {['all', 'critical', 'high'].map(tab => (
                    <button
                      key={tab}
                      onClick={() => setCveSeverityFilter(tab)}
                      className={`text-[9px] font-extrabold px-2 py-0.5 rounded transition-all uppercase ${
                        cveSeverityFilter === tab
                          ? 'bg-cyber-yellow text-black font-black'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {tab}
                    </button>
                  ))}
                </div>

                {/* Input Search */}
                <div className="relative flex-1 md:w-56">
                  <input
                    type="text"
                    placeholder="QUERY CVE ID OR VENDOR..."
                    value={cveSearch}
                    onChange={(e) => setCveSearch(e.target.value)}
                    className="w-full bg-cyber-bg border border-cyber-border rounded px-3 py-1.5 pl-9 text-[10px] focus:outline-none focus:border-cyber-yellow text-cyber-yellow uppercase font-bold placeholder:text-slate-700"
                  />
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
                </div>
              </div>
            </div>

            {/* CVE Database Table Grid */}
            <div className="bg-cyber-card border border-cyber-border rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs font-mono">
                  <thead>
                    <tr className="bg-cyber-card-light/80 border-b border-cyber-border text-slate-400 text-[10px] uppercase font-bold">
                      <th className="p-4 w-32">CVE Identifier</th>
                      <th className="p-4 w-48">Vulnerability Title</th>
                      <th className="p-4 w-24">CVSS score</th>
                      <th className="p-4">Short Description</th>
                      <th className="p-4 w-28 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border/40">
                    {cves
                      .filter(cve => {
                        const matchSearch = cve.id.toLowerCase().includes(cveSearch.toLowerCase()) ||
                                            cve.title.toLowerCase().includes(cveSearch.toLowerCase()) ||
                                            cve.description.toLowerCase().includes(cveSearch.toLowerCase());
                        const matchSeverity = cveSeverityFilter === 'all' || cve.severity.toLowerCase() === cveSeverityFilter;
                        return matchSearch && matchSeverity;
                      })
                      .map(cve => (
                        <tr key={cve.id} className="hover:bg-cyber-card-light/20 transition-all group">
                          <td className="p-4 font-black text-cyber-cyan group-hover:text-white">{cve.id}</td>
                          <td className="p-4 font-bold text-slate-100">{cve.title}</td>
                          <td className="p-4">
                            <span className={`px-2 py-0.5 border text-[9px] font-black rounded-full ${
                              cve.cvss >= 9.0 
                                ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30 shadow-[0_0_8px_rgba(255,0,127,0.15)]' 
                                : 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30'
                            }`}>
                              {cve.cvss.toFixed(1)}
                            </span>
                          </td>
                          <td className="p-4 text-slate-400 line-clamp-2 max-w-md my-2">
                            {cve.description}
                          </td>
                          <td className="p-4 text-right">
                            <button
                              onClick={() => openCveModal(cve)}
                              className="border border-cyber-yellow/40 hover:border-cyber-yellow bg-cyber-yellow/5 hover:bg-cyber-yellow/20 text-cyber-yellow text-[9px] font-bold py-1 px-3 rounded uppercase transition-all"
                            >
                              Mitigation
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
                {cves.length === 0 && (
                  <div className="p-12 text-center text-slate-500 uppercase">
                    NO CORRESPONDING VULNERABILITY ARCHIVES LOGGED
                  </div>
                )}
              </div>
            </div>

          </div>
        )}

        {/* TAB 4: DEFENSIVE TOOLKIT */}
        {activeTab === 'toolkit' && (
          <div className="flex flex-col gap-4 animate-fadeIn">
            {/* Sub Tabs */}
            <div className="flex gap-2">
              <button
                onClick={() => setToolkitSubTab('local')}
                className={`px-4 py-2 border rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer ${
                  toolkitSubTab === 'local'
                    ? 'bg-cyber-cyan/15 border-cyber-cyan text-cyber-cyan shadow-[0_0_8px_rgba(0,240,255,0.15)]'
                    : 'border-cyber-border text-slate-400 hover:text-slate-200'
                }`}
              >
                Local Incidents Selector
              </button>
              <button
                onClick={() => setToolkitSubTab('global')}
                className={`px-4 py-2 border rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer ${
                  toolkitSubTab === 'global'
                    ? 'bg-cyber-purple/15 border-cyber-purple text-cyber-purple shadow-[0_0_8px_rgba(157,0,255,0.15)]'
                    : 'border-cyber-border text-slate-400 hover:text-slate-200'
                }`}
              >
                Global Threat Feeds ({torExitData.length + spamhausDropData.length + cisaKevData.length} Records)
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Left Column: Selector (either Local or Global feeds) */}
              {toolkitSubTab === 'local' ? (
                <div className="lg:col-span-1 bg-cyber-card border border-cyber-border rounded-lg flex flex-col h-[650px] overflow-hidden">
                  <div className="bg-cyber-card-light px-4 py-3 border-b border-cyber-border flex flex-col gap-2">
                    <span className="text-xs text-cyber-cyan font-bold tracking-wider flex items-center gap-1.5">
                      <Layers className="w-4 h-4 text-cyber-cyan" />
                      LOCAL LOG INDICATORS
                    </span>
                    <p className="text-[9px] text-slate-500 uppercase leading-relaxed">
                      Stage suspicious hosts from sensor history for defensive firewall rule compiler deployment.
                    </p>
                    <div className="flex gap-2 mt-1">
                      <button
                        onClick={selectAllHighThreatIps}
                        className="flex-1 py-1 bg-cyber-pink/10 hover:bg-cyber-pink/20 border border-cyber-pink/30 hover:border-cyber-pink text-cyber-pink text-[8px] font-black uppercase rounded transition-all cursor-pointer"
                      >
                        Select All High Risk
                      </button>
                      <button
                        onClick={clearToolkitIps}
                        className="flex-1 py-1 bg-transparent border border-cyber-border hover:border-slate-400 text-slate-400 hover:text-white text-[8px] font-black uppercase rounded transition-all cursor-pointer"
                      >
                        Clear Select
                      </button>
                    </div>
                  </div>

                  {/* Selector List */}
                  <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2">
                    {threats.map((threat) => {
                      const isChecked = selectedBlockedIps.has(threat.indicator);
                      return (
                        <div
                          key={threat.id}
                          onClick={() => toggleToolkitIp(threat.indicator)}
                          className={`border p-2 rounded transition-all flex items-center justify-between cursor-pointer ${
                            isChecked 
                              ? 'border-cyber-cyan bg-cyber-cyan/5 shadow-[inset_0_0_8px_rgba(0,240,255,0.05)]' 
                              : 'border-cyber-border bg-cyber-bg/40 hover:bg-cyber-card-light/20'
                          }`}
                        >
                          <div className="flex items-center gap-2.5">
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => {}} // handled by div onClick
                              className="accent-cyber-cyan"
                            />
                            <div>
                              <div className="text-[11px] font-bold text-slate-100">{threat.indicator}</div>
                              <div className="text-[8px] text-slate-500 uppercase mt-0.5">
                                {threat.country} • {threat.pulse_name}
                              </div>
                            </div>
                          </div>
                          <span className={`px-1.5 py-0.5 border text-[7px] font-black uppercase rounded-full ${getSeverityColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                        </div>
                      );
                    })}
                    {threats.length === 0 && (
                      <div className="p-8 text-center text-slate-600 uppercase text-[9px]">
                        No threats detected in history to select.
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                /* GLOBAL FEEDS SELECTOR VIEW */
                <div className="lg:col-span-1 bg-cyber-card border border-cyber-border rounded-lg flex flex-col h-[650px] overflow-hidden">
                  <div className="bg-cyber-card-light px-4 py-3 border-b border-cyber-border flex flex-col gap-2">
                    <span className="text-xs text-cyber-purple font-bold tracking-wider flex items-center gap-1.5">
                      <Globe className="w-4 h-4 text-cyber-purple" />
                      GLOBAL INTELLIGENCE FEEDSTOCK
                    </span>
                    
                    {/* Feed selection buttons */}
                    <div className="flex gap-1 mt-1.5">
                      {[
                        { type: 'tor', label: 'Tor Exit' },
                        { type: 'spamhaus', label: 'Spamhaus' },
                        { type: 'cisa', label: 'CISA KEV' }
                      ].map(feed => (
                        <button
                          key={feed.type}
                          onClick={() => setGlobalFeedType(feed.type)}
                          className={`flex-1 py-1.5 text-[8px] font-black uppercase rounded border transition-all cursor-pointer ${
                            globalFeedType === feed.type
                              ? 'bg-cyber-purple/20 border-cyber-purple text-cyber-purple shadow-[0_0_8px_rgba(157,0,255,0.15)]'
                              : 'bg-transparent border-cyber-border text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          {feed.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Feed contents */}
                  <div className="flex-1 overflow-y-auto p-3 flex flex-col gap-2">
                    
                    {/* 1. TOR EXIT NODES */}
                    {globalFeedType === 'tor' && (
                      <>
                        <div className="text-[9px] text-slate-500 uppercase px-1 pb-1.5 border-b border-cyber-border/40 mb-1 flex justify-between">
                          <span>ACTIVE EXIT NODES: {torExitData.length}</span>
                          <span className="text-cyber-cyan">Ingress scans blocking</span>
                        </div>
                        {torExitData.map((ip, idx) => {
                          const isChecked = selectedBlockedIps.has(ip);
                          return (
                            <div
                              key={idx}
                              onClick={() => toggleToolkitIp(ip)}
                              className={`border p-2 rounded transition-all flex items-center justify-between cursor-pointer ${
                                isChecked 
                                  ? 'border-cyber-cyan bg-cyber-cyan/5' 
                                  : 'border-cyber-border bg-cyber-bg/40 hover:bg-cyber-card-light/20'
                              }`}
                            >
                              <span className="text-[11px] font-bold text-slate-200">{ip}</span>
                              <button
                                className={`px-2 py-0.5 text-[8px] border rounded font-bold uppercase transition-all cursor-pointer ${
                                  isChecked
                                    ? 'bg-cyber-pink/20 border-cyber-pink text-cyber-pink'
                                    : 'bg-cyber-cyan/10 border-cyber-cyan text-cyber-cyan hover:bg-cyber-cyan/25'
                                }`}
                              >
                                {isChecked ? 'Staged' : 'Stage Block'}
                              </button>
                            </div>
                          );
                        })}
                      </>
                    )}

                    {/* 2. SPAMHAUS DROP NETBLOCKS */}
                    {globalFeedType === 'spamhaus' && (
                      <>
                        <div className="text-[9px] text-slate-500 uppercase px-1 pb-1.5 border-b border-cyber-border/40 mb-1 flex justify-between">
                          <span>HIJACKED NETWORKS: {spamhausDropData.length}</span>
                          <span className="text-cyber-pink">Perimeter CIDR blocks</span>
                        </div>
                        {spamhausDropData.map((item, idx) => {
                          const isChecked = selectedBlockedIps.has(item.netblock);
                          return (
                            <div
                              key={idx}
                              onClick={() => toggleToolkitIp(item.netblock)}
                              className={`border p-2.5 rounded transition-all flex items-center justify-between cursor-pointer ${
                                isChecked 
                                  ? 'border-cyber-cyan bg-cyber-cyan/5' 
                                  : 'border-cyber-border bg-cyber-bg/40 hover:bg-cyber-card-light/20'
                              }`}
                            >
                              <div>
                                <span className="text-[11px] font-bold text-slate-200 block">{item.netblock}</span>
                                <span className="text-[8px] text-slate-500 font-extrabold uppercase mt-0.5 block">SBL REF: {item.sbl_id}</span>
                              </div>
                              <button
                                className={`px-2 py-0.5 text-[8px] border rounded font-bold uppercase transition-all cursor-pointer ${
                                  isChecked
                                    ? 'bg-cyber-pink/20 border-cyber-pink text-cyber-pink'
                                    : 'bg-cyber-cyan/10 border-cyber-cyan text-cyber-cyan hover:bg-cyber-cyan/25'
                                }`}
                              >
                                {isChecked ? 'Staged' : 'Stage Block'}
                              </button>
                            </div>
                          );
                        })}
                      </>
                    )}

                    {/* 3. CISA KEV CATALOG */}
                    {globalFeedType === 'cisa' && (
                      <>
                        <div className="bg-cyber-bg/60 border border-cyber-border rounded px-2.5 py-1.5 mb-2 flex items-center gap-2">
                          <Search className="w-3.5 h-3.5 text-slate-500" />
                          <input
                            type="text"
                            placeholder="FILTER VENDOR / CVE ID..."
                            value={cisaSearch}
                            onChange={(e) => setCisaSearch(e.target.value)}
                            className="bg-transparent border-none text-[9px] focus:outline-none text-cyber-yellow w-full uppercase font-bold placeholder:text-slate-600"
                          />
                          {cisaSearch && <X onClick={() => setCisaSearch('')} className="w-3 h-3 text-slate-500 cursor-pointer" />}
                        </div>

                        {cisaKevData
                          .filter(item => 
                            item.cveID.toLowerCase().includes(cisaSearch.toLowerCase()) ||
                            item.vendorProject.toLowerCase().includes(cisaSearch.toLowerCase()) ||
                            item.product.toLowerCase().includes(cisaSearch.toLowerCase()) ||
                            item.vulnerabilityName.toLowerCase().includes(cisaSearch.toLowerCase())
                          )
                          .map((item, idx) => (
                            <div key={idx} className="border border-cyber-border bg-cyber-bg/40 p-2.5 rounded flex flex-col gap-1.5 hover:border-cyber-yellow/40 transition-all">
                              <div className="flex justify-between items-center text-[10px] border-b border-cyber-border/40 pb-1">
                                <span className="font-black text-cyber-yellow">{item.cveID}</span>
                                <span className="text-[8px] bg-cyber-yellow/15 border border-cyber-yellow/20 text-cyber-yellow px-1 py-0.5 rounded uppercase font-bold">{item.vendorProject}</span>
                              </div>
                              <span className="text-[11px] font-bold text-slate-200">{item.vulnerabilityName}</span>
                              <p className="text-[9px] text-slate-400 leading-relaxed font-semibold">{item.shortDescription}</p>
                              <div className="text-[8px] text-slate-500 border-t border-cyber-border/30 pt-1.5 flex justify-between font-bold">
                                <span>PRODUCT: {item.product}</span>
                                <span>ADDED: {item.dateAdded}</span>
                              </div>
                            </div>
                          ))}
                      </>
                    )}

                  </div>
                </div>
              )}

              {/* Right Column: Code Generator */}
              <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col justify-between h-[650px] overflow-hidden">
                <div className="flex-1 flex flex-col overflow-hidden">
                  
                  {/* Title & Format bar */}
                  <div className="border-b border-cyber-border pb-3 mb-4 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="text-xs text-cyber-pink font-bold tracking-wider uppercase flex items-center gap-2">
                        <Terminal className="w-4 h-4 text-cyber-pink animate-pulse" />
                        FIREWALL BLOCKLIST COMPILER
                      </h2>
                      <p className="text-[9px] text-slate-400 mt-1 uppercase">
                        Select rules and copy-paste shell script syntax directly to device interfaces.
                      </p>
                    </div>

                    <div className="flex items-center gap-1.5 border border-cyber-border rounded bg-cyber-bg/50 px-2 py-1">
                      <span className="text-[8px] text-slate-500 font-bold uppercase">FORMAT:</span>
                      {['ufw', 'iptables', 'cisco_asa'].map(fmt => (
                        <button
                          key={fmt}
                          onClick={() => setToolkitFormat(fmt)}
                          className={`text-[9px] font-extrabold px-2 py-0.5 rounded transition-all uppercase cursor-pointer ${
                            toolkitFormat === fmt
                              ? 'bg-cyber-pink text-white font-black shadow-[0_0_8px_rgba(255,0,127,0.15)]'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          {fmt === 'cisco_asa' ? 'Cisco ASA' : fmt}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Staging stats */}
                  <div className="mb-3 flex justify-between text-[10px] text-slate-400">
                    <span>STAGED ATTACK INTRUDERS: <span className="text-cyber-cyan font-black">{selectedBlockedIps.size} IPS</span></span>
                    <span className="uppercase">ENGINE DESTINATION: <span className="text-cyber-pink font-black">{toolkitFormat}</span></span>
                  </div>

                  {/* Shell rule block output */}
                  <div className="flex-1 bg-cyber-bg/90 border border-cyber-border rounded-lg p-4 overflow-y-auto font-mono text-xs text-slate-300 relative group">
                    <pre className="whitespace-pre-wrap font-mono leading-relaxed select-all">
                      {generateFirewallScript()}
                    </pre>
                    
                    {selectedBlockedIps.size > 0 && (
                      <button
                        onClick={copyFirewallScript}
                        className="absolute top-3 right-3 p-1.5 bg-cyber-card border border-cyber-border hover:border-cyber-pink text-slate-400 hover:text-cyber-pink rounded transition-all flex items-center gap-1 text-[9px] font-bold cursor-pointer"
                      >
                        {copiedCode ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedCode ? 'COPIED' : 'COPY'}
                      </button>
                    )}
                  </div>
                </div>

                {/* Toolkit warning */}
                <div className="mt-4 p-3 bg-cyber-yellow/5 border border-cyber-yellow/20 rounded-lg flex items-start gap-2.5 text-[10px] text-cyber-yellow/80 leading-relaxed uppercase">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-cyber-yellow animate-pulse" />
                  <div>
                    <span className="font-extrabold">ADMINISTRATOR CAUTION:</span> Deny policies block all inbound traffic from source scopes permanently. Validate configurations on isolated network partitions before full deployment.
                  </div>
                </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: FEEDS HUB */}
      {activeTab === 'feeds' && (
        <div className="flex flex-col gap-4 animate-fadeIn">
          
          {/* Feeds Sub-Tabs */}
          <div className="flex flex-wrap gap-2 border-b border-cyber-border pb-3">
            {[
              { id: 'threatfox', label: 'ThreatFox IOCs', color: 'text-cyber-cyan', activeBg: 'bg-cyber-cyan/15 border-cyber-cyan', count: threatfoxData.length },
              { id: 'urlhaus', label: 'URLhaus URLs', color: 'text-cyber-green', activeBg: 'bg-cyber-green/15 border-cyber-green', count: urlhausData.length },
              { id: 'github', label: 'GitHub Advisories', color: 'text-cyber-purple', activeBg: 'bg-cyber-purple/15 border-cyber-purple', count: githubAdvisoriesData.length },
              { id: 'circl', label: 'CIRCL CVE Feed', color: 'text-cyber-yellow', activeBg: 'bg-cyber-yellow/15 border-cyber-yellow', count: circlCvesData.length }
            ].map(subTab => (
              <button
                key={subTab.id}
                onClick={() => setFeedTab(subTab.id)}
                className={`px-3 py-1.5 border rounded text-xs font-bold uppercase tracking-wider transition-all cursor-pointer flex items-center gap-2 ${
                  feedTab === subTab.id
                    ? `${subTab.activeBg} ${subTab.color} shadow-[0_0_8px_rgba(0,0,0,0.2)] font-black`
                    : `border-cyber-border text-slate-400 hover:text-slate-200`
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${feedTab === subTab.id ? 'bg-current animate-pulse' : 'bg-slate-500'}`} />
                {subTab.label}
                <span className="text-[8px] bg-cyber-bg px-1.5 py-0.5 rounded border border-cyber-border text-slate-400 font-extrabold ml-1">
                  {subTab.count}
                </span>
              </button>
            ))}
          </div>

          {/* FEED CONTENT CONTAINER */}
          <div className="bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col h-[700px] overflow-hidden">
            
            {/* 1. THREATFOX IOCS FEED */}
            {feedTab === 'threatfox' && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-cyber-border/60 pb-4 mb-4">
                  <div>
                    <h2 className="text-xs text-cyber-cyan font-bold tracking-wider uppercase flex items-center gap-2">
                      <AlertOctagon className="w-4 h-4 text-cyber-cyan animate-pulse" />
                      ThreatFox Indicator of Compromise (IOC) Feed
                    </h2>
                    <p className="text-[9px] text-slate-400 mt-1 uppercase">
                      Real-time indicators (hashes, domains, IPs) associated with active malware campaigns.
                    </p>
                  </div>
                  {/* Search bar */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      placeholder="FILTER THREATFOX DATA..."
                      value={threatfoxSearch}
                      onChange={(e) => setThreatfoxSearch(e.target.value)}
                      className="w-full bg-cyber-bg/90 border border-cyber-border rounded px-3 py-1.5 pl-8 text-[9px] focus:outline-none focus:border-cyber-cyan focus:shadow-[0_0_8px_rgba(0,240,255,0.15)] transition-all placeholder:text-slate-600 text-cyber-cyan uppercase font-bold"
                    />
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                    {threatfoxSearch && (
                      <button onClick={() => setThreatfoxSearch('')} className="absolute right-2.5 top-2 text-slate-500 hover:text-white">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto min-h-0 relative">
                  {threatfoxLoading ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin text-cyber-cyan" />
                      <span className="text-[9px] font-bold uppercase tracking-widest">FETCHING LIVE IOC LOGS...</span>
                    </div>
                  ) : (
                    <table className="w-full border-collapse text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-cyber-border text-slate-400 text-[9px] uppercase tracking-wider font-extrabold bg-cyber-card-light/45">
                          <th className="py-2.5 px-3">Indicator</th>
                          <th className="py-2.5 px-3">Type</th>
                          <th className="py-2.5 px-3">Malware / Threat</th>
                          <th className="py-2.5 px-3">Reporter</th>
                          <th className="py-2.5 px-3 text-right">Timestamp</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threatfoxData
                          .filter(item => 
                            item.ioc_value?.toLowerCase().includes(threatfoxSearch.toLowerCase()) ||
                            item.malware_printable?.toLowerCase().includes(threatfoxSearch.toLowerCase()) ||
                            item.ioc_type?.toLowerCase().includes(threatfoxSearch.toLowerCase()) ||
                            item.reporter?.toLowerCase().includes(threatfoxSearch.toLowerCase())
                          )
                          .map((item, idx) => (
                            <tr key={idx} className="border-b border-cyber-border/40 hover:bg-cyber-card-light/20 transition-all">
                              <td className="py-2 px-3 font-bold text-slate-200">
                                <div className="flex items-center gap-2">
                                  <span className="truncate max-w-[250px]">{item.ioc_value}</span>
                                  <button
                                    onClick={() => {
                                      navigator.clipboard.writeText(item.ioc_value);
                                      setCopiedRulesKey(item.ioc_value);
                                      setTimeout(() => setCopiedRulesKey(null), 2000);
                                    }}
                                    className="p-1 hover:bg-cyber-bg border border-transparent hover:border-cyber-border rounded text-slate-500 hover:text-cyber-cyan cursor-pointer transition-all"
                                    title="Copy Indicator"
                                  >
                                    {copiedRulesKey === item.ioc_value ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                                  </button>
                                </div>
                              </td>
                              <td className="py-2 px-3">
                                <span className="text-[8px] border border-cyber-cyan/30 bg-cyber-cyan/5 text-cyber-cyan px-1.5 py-0.5 rounded font-extrabold uppercase">
                                  {item.ioc_type}
                                </span>
                              </td>
                              <td className="py-2 px-3">
                                <span className="font-extrabold text-cyber-pink">{item.malware_printable || 'Unknown'}</span>
                                <span className="text-[9px] text-slate-500 ml-1.5">({item.threat_type})</span>
                              </td>
                              <td className="py-2 px-3 text-slate-400">{item.reporter || 'Anonymous'}</td>
                              <td className="py-2 px-3 text-right text-slate-500 text-[10px]">{item.first_seen_utc}</td>
                            </tr>
                          ))}
                        {threatfoxData.length === 0 && (
                          <tr>
                            <td colSpan="5" className="py-8 text-center text-slate-500 uppercase text-[9px]">
                              No ThreatFox IOC indicators found in live telemetry feed.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}

            {/* 2. URLHAUS MALWARE URLS FEED */}
            {feedTab === 'urlhaus' && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-cyber-border/60 pb-4 mb-4">
                  <div>
                    <h2 className="text-xs text-cyber-green font-bold tracking-wider uppercase flex items-center gap-2">
                      <AlertOctagon className="w-4 h-4 text-cyber-green animate-pulse" />
                      URLhaus Active Malware URL Feed
                    </h2>
                    <p className="text-[9px] text-slate-400 mt-1 uppercase">
                      Recently added active URLs serving malicious binary payloads and exploit campaigns.
                    </p>
                  </div>
                  {/* Search bar */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      placeholder="FILTER URLHAUS DATA..."
                      value={urlhausSearch}
                      onChange={(e) => setUrlhausSearch(e.target.value)}
                      className="w-full bg-cyber-bg/90 border border-cyber-border rounded px-3 py-1.5 pl-8 text-[9px] focus:outline-none focus:border-cyber-green focus:shadow-[0_0_8px_rgba(57,255,20,0.15)] transition-all placeholder:text-slate-600 text-cyber-green uppercase font-bold"
                    />
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                    {urlhausSearch && (
                      <button onClick={() => setUrlhausSearch('')} className="absolute right-2.5 top-2 text-slate-500 hover:text-white">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto min-h-0 relative">
                  {urlhausLoading ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin text-cyber-green" />
                      <span className="text-[9px] font-bold uppercase tracking-widest">FETCHING LIVE URL LOGS...</span>
                    </div>
                  ) : (
                    <table className="w-full border-collapse text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-cyber-border text-slate-400 text-[9px] uppercase tracking-wider font-extrabold bg-cyber-card-light/45">
                          <th className="py-2.5 px-3">Malicious URL</th>
                          <th className="py-2.5 px-3">Status</th>
                          <th className="py-2.5 px-3">Threat & Tags</th>
                          <th className="py-2.5 px-3">Reporter</th>
                          <th className="py-2.5 px-3 text-right">Date Added</th>
                        </tr>
                      </thead>
                      <tbody>
                        {urlhausData
                          .filter(item => 
                            item.url?.toLowerCase().includes(urlhausSearch.toLowerCase()) ||
                            item.threat?.toLowerCase().includes(urlhausSearch.toLowerCase()) ||
                            item.reporter?.toLowerCase().includes(urlhausSearch.toLowerCase()) ||
                            (item.tags && item.tags.some(t => t.toLowerCase().includes(urlhausSearch.toLowerCase())))
                          )
                          .map((item, idx) => (
                            <tr key={idx} className="border-b border-cyber-border/40 hover:bg-cyber-card-light/20 transition-all">
                              <td className="py-2 px-3 font-bold text-slate-200">
                                <div className="flex items-center gap-2">
                                  <span className="truncate max-w-[300px]" title={item.url}>{item.url}</span>
                                  <button
                                    onClick={() => {
                                      navigator.clipboard.writeText(item.url);
                                      setCopiedRulesKey(item.url);
                                      setTimeout(() => setCopiedRulesKey(null), 2000);
                                    }}
                                    className="p-1 hover:bg-cyber-bg border border-transparent hover:border-cyber-border rounded text-slate-500 hover:text-cyber-green cursor-pointer transition-all"
                                    title="Copy URL"
                                  >
                                    {copiedRulesKey === item.url ? <Check className="w-3.5 h-3.5 text-cyber-green" /> : <Copy className="w-3.5 h-3.5" />}
                                  </button>
                                </div>
                              </td>
                              <td className="py-2 px-3">
                                <span className={`text-[8px] px-1.5 py-0.5 rounded font-black uppercase border ${
                                  item.url_status === 'online'
                                    ? 'bg-cyber-pink/15 border-cyber-pink/30 text-cyber-pink'
                                    : 'bg-slate-800 border-slate-700 text-slate-500'
                                }`}>
                                  {item.url_status}
                                </span>
                              </td>
                              <td className="py-2 px-3">
                                <span className="font-extrabold text-cyber-yellow text-[10px] block">{item.threat}</span>
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {item.tags && item.tags.map((tag, tagIdx) => (
                                    <span key={tagIdx} className="text-[7px] bg-cyber-card-light border border-cyber-border text-slate-300 px-1 py-0.2 rounded font-semibold uppercase">
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="py-2 px-3 text-slate-400">{item.reporter || 'Anonymous'}</td>
                              <td className="py-2 px-3 text-right text-slate-500 text-[10px]">{item.dateadded}</td>
                            </tr>
                          ))}
                        {urlhausData.length === 0 && (
                          <tr>
                            <td colSpan="5" className="py-8 text-center text-slate-500 uppercase text-[9px]">
                              No URLhaus active malware URLs found in live telemetry feed.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}

            {/* 3. GITHUB ADVISORIES FEED */}
            {feedTab === 'github' && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-cyber-border/60 pb-4 mb-4">
                  <div>
                    <h2 className="text-xs text-cyber-purple font-bold tracking-wider uppercase flex items-center gap-2">
                      <AlertOctagon className="w-4 h-4 text-cyber-purple animate-pulse" />
                      GitHub Security Advisory Catalog
                    </h2>
                    <p className="text-[9px] text-slate-400 mt-1 uppercase">
                      Recent open-source package vulnerabilities and security advisories reported via GitHub.
                    </p>
                  </div>
                  {/* Search bar */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      placeholder="FILTER ADVISORIES..."
                      value={githubSearch}
                      onChange={(e) => setGithubSearch(e.target.value)}
                      className="w-full bg-cyber-bg/90 border border-cyber-border rounded px-3 py-1.5 pl-8 text-[9px] focus:outline-none focus:border-cyber-purple focus:shadow-[0_0_8px_rgba(157,0,255,0.15)] transition-all placeholder:text-slate-600 text-cyber-purple uppercase font-bold"
                    />
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                    {githubSearch && (
                      <button onClick={() => setGithubSearch('')} className="absolute right-2.5 top-2 text-slate-500 hover:text-white">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto min-h-0 relative">
                  {githubLoading ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin text-cyber-purple" />
                      <span className="text-[9px] font-bold uppercase tracking-widest">FETCHING LIVE ADVISORIES...</span>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-1">
                      {githubAdvisoriesData
                        .filter(item => 
                          item.summary?.toLowerCase().includes(githubSearch.toLowerCase()) ||
                          item.ghsa_id?.toLowerCase().includes(githubSearch.toLowerCase()) ||
                          (item.cve_id && item.cve_id.toLowerCase().includes(githubSearch.toLowerCase())) ||
                          (item.vulnerabilities && item.vulnerabilities.some(v => v.package?.name?.toLowerCase().includes(githubSearch.toLowerCase())))
                        )
                        .map((item, idx) => (
                          <div key={idx} className="border border-cyber-border bg-cyber-bg/40 p-3.5 rounded-lg flex flex-col justify-between hover:border-cyber-purple/45 transition-all">
                            <div>
                              <div className="flex justify-between items-center text-[10px] border-b border-cyber-border/40 pb-2 mb-2 font-mono">
                                <span className="font-black text-cyber-purple">{item.ghsa_id}</span>
                                {item.cve_id ? (
                                  <span className="text-cyber-yellow font-bold">{item.cve_id}</span>
                                ) : (
                                  <span className="text-slate-500 text-[8px]">NO CVE ASSIGNED</span>
                                )}
                              </div>
                              <h3 className="text-xs font-bold text-slate-200 mb-1 leading-snug">{item.summary}</h3>
                              <p className="text-[9px] text-slate-400 leading-relaxed font-semibold line-clamp-3 mb-3">
                                {item.description || "No description available."}
                              </p>
                            </div>

                            <div className="border-t border-cyber-border/30 pt-3 mt-1 flex justify-between items-center font-bold">
                              <div className="flex items-center gap-2">
                                <span className={`text-[8px] px-1.5 py-0.5 rounded uppercase border ${
                                  item.severity === 'critical'
                                    ? 'bg-cyber-pink/15 border-cyber-pink/20 text-cyber-pink'
                                    : item.severity === 'high'
                                    ? 'bg-cyber-yellow/15 border-cyber-yellow/20 text-cyber-yellow'
                                    : 'bg-cyber-cyan/15 border-cyber-cyan/20 text-cyber-cyan'
                                }`}>
                                  {item.severity}
                                </span>
                                <span className="text-[8px] text-slate-500">
                                  PKG: {item.vulnerabilities?.[0]?.package?.name || 'various'}
                                </span>
                              </div>
                              <a
                                href={item.html_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-[8px] text-cyber-purple hover:underline flex items-center gap-1 cursor-pointer"
                              >
                                DETAILS <ExternalLink className="w-2.5 h-2.5" />
                              </a>
                            </div>
                          </div>
                        ))}
                      {githubAdvisoriesData.length === 0 && (
                        <div className="col-span-full py-8 text-center text-slate-500 uppercase text-[9px]">
                          No GitHub Security Advisories found in live feed.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* 4. CIRCL CVE FEED */}
            {feedTab === 'circl' && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 border-b border-cyber-border/60 pb-4 mb-4">
                  <div>
                    <h2 className="text-xs text-cyber-yellow font-bold tracking-wider uppercase flex items-center gap-2">
                      <AlertOctagon className="w-4 h-4 text-cyber-yellow animate-pulse" />
                      CIRCL CVE Live Feed
                    </h2>
                    <p className="text-[9px] text-slate-400 mt-1 uppercase">
                      Recently published and updated Common Vulnerabilities and Exposures database catalog.
                    </p>
                  </div>
                  {/* Search bar */}
                  <div className="relative w-full sm:w-64">
                    <input
                      type="text"
                      placeholder="FILTER LIVE CVES..."
                      value={circlSearch}
                      onChange={(e) => setCirclSearch(e.target.value)}
                      className="w-full bg-cyber-bg/90 border border-cyber-border rounded px-3 py-1.5 pl-8 text-[9px] focus:outline-none focus:border-cyber-yellow focus:shadow-[0_0_8px_rgba(255,223,0,0.15)] transition-all placeholder:text-slate-600 text-cyber-yellow uppercase font-bold"
                    />
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                    {circlSearch && (
                      <button onClick={() => setCirclSearch('')} className="absolute right-2.5 top-2 text-slate-500 hover:text-white">
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto min-h-0 relative">
                  {circlLoading ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 text-slate-400">
                      <RefreshCw className="w-6 h-6 animate-spin text-cyber-yellow" />
                      <span className="text-[9px] font-bold uppercase tracking-widest">FETCHING LIVE CVE LOGS...</span>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-3.5">
                      {circlCvesData
                        .filter(item => {
                          const cveId = item.cveMetadata?.cveId || item.id || "";
                          const summary = item.containers?.cna?.descriptions?.[0]?.value || item.summary || "";
                          return (
                            cveId.toLowerCase().includes(circlSearch.toLowerCase()) ||
                            summary.toLowerCase().includes(circlSearch.toLowerCase())
                          );
                        })
                        .map((item, idx) => {
                          const cveId = item.cveMetadata?.cveId || item.id || "CVE-UNKNOWN";
                          const summary = item.containers?.cna?.descriptions?.[0]?.value || item.summary || "No description available.";
                          const date = item.cveMetadata?.datePublished || item.Published || "Recent";
                          const shortDate = date.split('T')[0];
                          const metrics = item.containers?.cna?.metrics?.[0];
                          const cvss = metrics?.cvssV3_1?.baseScore || metrics?.cvssV3_0?.baseScore || item.cvss || "N/A";
                          
                          return (
                            <div key={idx} className="border border-cyber-border bg-cyber-bg/40 p-4 rounded-lg flex flex-col gap-2 hover:border-cyber-yellow/45 transition-all">
                              <div className="flex justify-between items-center text-[10px] border-b border-cyber-border/40 pb-1.5 font-mono">
                                <div className="flex items-center gap-2">
                                  <span className="font-black text-cyber-yellow text-xs">{cveId}</span>
                                  {cvss !== "N/A" && (
                                    <span className={`text-[8px] font-black px-1.5 py-0.5 rounded-full border ${
                                      parseFloat(cvss) >= 9.0
                                        ? 'bg-cyber-pink/15 border-cyber-pink/20 text-cyber-pink'
                                        : parseFloat(cvss) >= 7.0
                                        ? 'bg-cyber-yellow/15 border-cyber-yellow/20 text-cyber-yellow'
                                        : 'bg-cyber-cyan/15 border-cyber-cyan/20 text-cyber-cyan'
                                    }`}>
                                      CVSS {cvss}
                                    </span>
                                  )}
                                </div>
                                <span className="text-slate-500 font-bold uppercase text-[8px]">PUBLISHED: {shortDate}</span>
                              </div>
                              <p className="text-[10px] text-slate-300 leading-relaxed font-semibold">
                                {summary}
                              </p>
                            </div>
                          );
                        })}
                      {circlCvesData.length === 0 && (
                        <div className="py-8 text-center text-slate-500 uppercase text-[9px]">
                          No CIRCL CVE records found in live feed.
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

          </div>
        </div>
      )}

      </main>

      {/* FOOTER */}
      <footer className="border-t border-cyber-border bg-cyber-card/40 px-6 py-3.5 flex flex-col sm:flex-row justify-between items-center gap-3 text-[9px] text-slate-500">
        <div>SYSTEM STATUS: CODES LOGGED SECURITY INTERFACE OK • SENSOR UPTIME: 100%</div>
        <div>&copy; {new Date().getFullYear()} CYBER SENTINEL THREAT INTELLIGENCE DASHBOARD</div>
      </footer>

      {/* ======================================================== */}
      {/* DETAILED MODALS (NATIVE DIALOGS) */}
      {/* ======================================================== */}

      {/* 1. Threat Log Inspection Dialog */}
      <dialog 
        ref={threatDialogRef}
        onClick={(e) => handleBackdropClick(e, threatDialogRef, closeThreatModal)}
        className="cyber-modal"
      >
        {selectedThreat && (
          <div className="flex flex-col">
            <div className="bg-cyber-card-light px-5 py-3.5 border-b border-cyber-border flex justify-between items-center">
              <span className="text-xs text-cyber-cyan font-bold tracking-widest flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyber-cyan" />
                THREAT PROFILE ANALYSIS
              </span>
              <X 
                onClick={closeThreatModal} 
                className="w-4 h-4 text-slate-400 hover:text-white cursor-pointer transition-colors"
              />
            </div>
            
            <div className="p-5 flex flex-col gap-4 text-xs">
              <div className="grid grid-cols-2 gap-4">
                <div className="border border-cyber-border/80 bg-cyber-bg/40 p-3 rounded">
                  <div className="text-[9px] text-slate-500 uppercase font-black mb-1">INTRUDER IP HOST</div>
                  <div className="text-sm font-black text-cyber-cyan select-all">{selectedThreat.indicator}</div>
                </div>
                <div className="border border-cyber-border/80 bg-cyber-bg/40 p-3 rounded">
                  <div className="text-[9px] text-slate-500 uppercase font-black mb-1">DETECTION RISK LEVEL</div>
                  <div className="text-sm font-black text-cyber-pink uppercase select-all">{selectedThreat.severity}</div>
                </div>
              </div>

              <div className="border border-cyber-border/80 bg-cyber-bg/40 p-3 rounded">
                <div className="text-[9px] text-slate-500 uppercase font-black mb-1">SIGNATURE DETECTED</div>
                <div className="text-xs font-extrabold text-slate-100">{selectedThreat.pulse_name}</div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-400 font-extrabold block text-[9px] uppercase">ORIGIN NATION</span>
                  <span className="text-slate-200 mt-1 block font-bold">{selectedThreat.country} ({selectedThreat.country_code})</span>
                </div>
                <div>
                  <span className="text-slate-400 font-extrabold block text-[9px] uppercase">UTC TIMESTAMP</span>
                  <span className="text-slate-200 mt-1 block font-bold">{new Date(selectedThreat.timestamp).toISOString()}</span>
                </div>
              </div>

              <div className="border-t border-cyber-border/40 pt-3">
                <span className="text-slate-400 font-extrabold block text-[9px] uppercase mb-1.5">FORENSIC REPORT</span>
                <p className="text-slate-300 leading-relaxed bg-cyber-bg/70 p-3 border border-cyber-border rounded">
                  {selectedThreat.description}
                </p>
              </div>

              <div className="flex gap-3 justify-end mt-2 pt-2 border-t border-cyber-border/30">
                <button
                  onClick={() => {
                    toggleToolkitIp(selectedThreat.indicator);
                    closeThreatModal();
                  }}
                  className={`px-4 py-2 border text-[10px] font-black rounded uppercase transition-all ${
                    selectedBlockedIps.has(selectedThreat.indicator)
                      ? 'bg-cyber-pink/20 border-cyber-pink text-cyber-pink'
                      : 'bg-cyber-cyan/10 border-cyber-cyan text-cyber-cyan hover:bg-cyber-cyan/20'
                  }`}
                >
                  {selectedBlockedIps.has(selectedThreat.indicator) ? 'Remove Block Rule' : 'Stage Block Rule'}
                </button>
                <button
                  onClick={closeThreatModal}
                  className="px-4 py-2 bg-transparent border border-cyber-border hover:border-slate-400 text-slate-400 hover:text-white text-[10px] font-black rounded uppercase transition-all"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        )}
      </dialog>

      {/* 2. APT Actor Inspect Dialog */}
      <dialog 
        ref={aptDialogRef}
        onClick={(e) => handleBackdropClick(e, aptDialogRef, closeAptModal)}
        className="cyber-modal shadow-[0_0_35px_rgba(157,0,255,0.25)] border-cyber-purple/50"
      >
        {selectedApt && (
          <div className="flex flex-col">
            <div className="bg-cyber-card-light px-5 py-3.5 border-b border-cyber-border flex justify-between items-center">
              <span className="text-xs text-cyber-purple font-bold tracking-widest flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyber-purple" />
                APT THREAT GROUP DETAILS
              </span>
              <X 
                onClick={closeAptModal} 
                className="w-4 h-4 text-slate-400 hover:text-white cursor-pointer transition-colors"
              />
            </div>
            
            <div className="p-5 flex flex-col gap-4 text-xs">
              <div className="flex justify-between items-center border-b border-cyber-border/60 pb-3">
                <div>
                  <h3 className="text-base font-black text-slate-100">{selectedApt.name}</h3>
                  <span className="text-[9px] text-slate-400 mt-1 block uppercase">ATTRIB. ORIGIN: <span className="text-cyber-cyan font-bold">{selectedApt.origin}</span></span>
                </div>
                <span className={`px-2 py-0.5 border text-[9px] font-black uppercase rounded-full ${
                  selectedApt.threat_level === 'Critical' 
                    ? 'text-cyber-pink bg-cyber-pink/10 border-cyber-pink/30 shadow-[0_0_8px_rgba(255,0,127,0.15)]' 
                    : 'text-cyber-yellow bg-cyber-yellow/10 border-cyber-yellow/30'
                }`}>
                  {selectedApt.threat_level} LEVEL
                </span>
              </div>

              <div className="flex flex-col gap-1.5">
                <span className="text-slate-400 font-extrabold text-[9px] uppercase">PROFILE OVERVIEW</span>
                <p className="text-slate-300 leading-relaxed bg-cyber-bg/70 p-3 border border-cyber-border rounded">
                  {selectedApt.description}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-400 font-extrabold text-[9px] uppercase block mb-1">TARGET SECTORS</span>
                  <div className="flex flex-col gap-1">
                    {selectedApt.sectors.map((s, idx) => (
                      <span key={idx} className="text-[10px] text-slate-300 font-semibold">• {s}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 font-extrabold text-[9px] uppercase block mb-1">TACTICS & METHODOLOGY</span>
                  <div className="flex flex-col gap-1">
                    {selectedApt.tactics.map((t, idx) => (
                      <span key={idx} className="text-[10px] text-slate-300 font-semibold">• {t}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 border-t border-cyber-border/40 pt-3">
                <div>
                  <span className="text-slate-400 font-extrabold text-[9px] uppercase block mb-1.5">SIGNATURE MALWARE</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedApt.malware.map((m, idx) => (
                      <span key={idx} className="text-[9px] bg-cyber-bg border border-cyber-border px-1.5 py-0.5 rounded text-cyber-purple font-bold uppercase">{m}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 font-extrabold text-[9px] uppercase block mb-1.5">TARGET EXPLOITS (CVE)</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedApt.cves.map((c, idx) => (
                      <span key={idx} className="text-[9px] bg-cyber-bg border border-cyber-border px-1.5 py-0.5 rounded text-cyber-yellow font-bold uppercase">{c}</span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex justify-end mt-4 pt-3 border-t border-cyber-border/30">
                <button
                  onClick={closeAptModal}
                  className="px-4 py-2 bg-cyber-purple/10 border border-cyber-purple hover:bg-cyber-purple/20 text-cyber-purple text-[10px] font-black rounded uppercase transition-all"
                >
                  Acknowledge Profile
                </button>
              </div>
            </div>
          </div>
        )}
      </dialog>

      {/* 3. CVE Mitigation Details Dialog */}
      <dialog 
        ref={cveDialogRef}
        onClick={(e) => handleBackdropClick(e, cveDialogRef, closeCveModal)}
        className="cyber-modal shadow-[0_0_35px_rgba(255,223,0,0.2)] border-cyber-yellow/50"
      >
        {selectedCve && (
          <div className="flex flex-col">
            <div className="bg-cyber-card-light px-5 py-3.5 border-b border-cyber-border flex justify-between items-center">
              <span className="text-xs text-cyber-yellow font-bold tracking-widest flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-cyber-yellow" />
                VULNERABILITY MITIGATION SCHEME
              </span>
              <X 
                onClick={closeCveModal} 
                className="w-4 h-4 text-slate-400 hover:text-white cursor-pointer transition-colors"
              />
            </div>
            
            <div className="p-5 flex flex-col gap-4 text-xs">
              <div className="flex justify-between items-start border-b border-cyber-border/60 pb-3">
                <div>
                  <h3 className="text-base font-black text-cyber-cyan">{selectedCve.id}</h3>
                  <span className="text-slate-100 font-extrabold mt-1 block">{selectedCve.title}</span>
                  <span className="text-[8px] text-slate-500 mt-1 block uppercase">PUBLISHED RECORD: {selectedCve.published}</span>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <span className="text-[8px] text-slate-500 uppercase font-black">CVSS METRIC</span>
                  <span className={`px-3 py-1 border text-sm font-black rounded ${
                    selectedCve.cvss >= 9.0 ? 'text-cyber-pink border-cyber-pink bg-cyber-pink/10' : 'text-cyber-yellow border-cyber-yellow bg-cyber-yellow/10'
                  }`}>
                    {selectedCve.cvss.toFixed(1)} / 10.0
                  </span>
                </div>
              </div>

              <div className="flex flex-col gap-1">
                <span className="text-slate-400 font-extrabold text-[9px] uppercase">VULNERABILITY DESCRIPTION</span>
                <p className="text-slate-300 leading-relaxed bg-cyber-bg/70 p-3 border border-cyber-border rounded">
                  {selectedCve.description}
                </p>
              </div>

              <div className="flex flex-col gap-1 border-t border-cyber-border/40 pt-3">
                <span className="text-cyber-pink font-extrabold text-[9px] uppercase">IMPACT VECTOR</span>
                <p className="text-slate-200 leading-relaxed font-semibold">
                  {selectedCve.impact}
                </p>
              </div>

              <div className="flex flex-col gap-1 border-t border-cyber-border/40 pt-3">
                <span className="text-cyber-green font-extrabold text-[9px] uppercase">REMEDIATION & MITIGATION ACTION</span>
                <p className="text-slate-300 leading-relaxed bg-cyber-green/5 p-3 border border-cyber-green/30 rounded font-semibold text-slate-200">
                  {selectedCve.mitigation}
                </p>
              </div>

              <div className="flex justify-end mt-4 pt-3 border-t border-cyber-border/30">
                <button
                  onClick={closeCveModal}
                  className="px-4 py-2 bg-cyber-yellow/15 border border-cyber-yellow/50 hover:border-cyber-yellow text-cyber-yellow text-[10px] font-black rounded uppercase transition-all"
                >
                  Mitigation Confirmed
                </button>
              </div>
            </div>
          </div>
        )}
      </dialog>

    </div>
  );
}
