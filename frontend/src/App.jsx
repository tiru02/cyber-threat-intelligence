import React, { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, Polyline } from 'react-leaflet';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { 
  Shield, Search, AlertTriangle, Activity, MapPin, Server, Globe, X, Clock, Cpu, 
  Play, Pause, FastForward, UserCheck, Terminal, Download, ShieldAlert, BookOpen, 
  Layers, Copy, Check, Filter, RefreshCw
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
  const [activeTab, setActiveTab] = useState('monitor'); // 'monitor' | 'apt' | 'cves' | 'toolkit'
  
  // Data States
  const [threats, setThreats] = useState([]);
  const [mapData, setMapData] = useState([]);
  const [aptGroups, setAptGroups] = useState([]);
  const [cves, setCves] = useState([]);
  
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

    fetch(`${API_BASE_URL}/api/cves`)
      .then(res => res.json())
      .then(data => setCves(data))
      .catch(err => console.error("Error fetching CVE database:", err));
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

  // Real-time Threat Stream Feed Simulator
  useEffect(() => {
    if (!isLive) return;

    const interval = setInterval(() => {
      // Pick random origin and target
      const origin = countries[Math.floor(Math.random() * countries.length)];
      const target = countries.filter(c => c.code !== origin.code)[Math.floor(Math.random() * (countries.length - 1))];
      
      const ip = `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`;
      const severities = ["high", "medium", "low"];
      const severity = severities[Math.floor(Math.random() * severities.length)];
      const pulse = threatTypes[Math.floor(Math.random() * threatTypes.length)];
      const attackType = pulse.includes("Ransomware") ? "Malware" : pulse.includes("C2") ? "Botnet C2" : "Exploit";
      const timestamp = new Date().toISOString();

      // Append new threat to feed
      const newThreat = {
        id: `threat-stream-${Date.now()}-${Math.random()}`,
        indicator: ip,
        type: "IPv4",
        pulse_name: pulse,
        severity: severity,
        country: origin.name,
        country_code: origin.code,
        timestamp: timestamp,
        description: `Real-time signature match: ${pulse}. Intrusion vectors traced to hosts in ${origin.name}.`
      };

      setThreats(prev => [newThreat, ...prev].slice(0, 80));

      // Append new vector to map & flying packets
      const newAttackId = `attack-stream-${Date.now()}-${Math.random()}`;
      const newAttack = {
        id: newAttackId,
        origin: { ...origin },
        target: { ...target },
        type: attackType,
        severity: severity,
        value: Math.floor(Math.random() * 90) + 10,
        timestamp: timestamp
      };

      setMapData(prev => [newAttack, ...prev].slice(0, 25));

      setFlyingPackets(prev => {
        const updated = [...prev];
        // replace oldest packet with the new threat packet
        updated.shift();
        updated.push({
          id: newAttackId,
          origin: [origin.lat, origin.lon],
          originCountry: origin.name,
          target: [target.lat, target.lon],
          targetCountry: target.name,
          current: [origin.lat, origin.lon],
          progress: 0,
          severity: severity,
          type: attackType,
          speed: 0.008 + Math.random() * 0.015
        });
        return updated;
      });

    }, 3500 / speedMultiplier);

    return () => clearInterval(interval);
  }, [isLive, speedMultiplier]);



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

      {/* DEFCON / Threat Status Banner */}
      <section className={`mx-6 mt-6 p-4 rounded-lg border flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 transition-all duration-500 ${defcon.color}`}>
        <div className="flex items-center gap-3">
          <div className="relative flex h-3 w-3 shrink-0">
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${defcon.badge}`}></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-current"></span>
          </div>
          <div>
            <h2 className="text-sm font-bold tracking-widest uppercase flex items-center gap-2">
              SYSTEM LEVEL Status: <span className="underline">{defcon.level}</span> — {defcon.label}
            </h2>
            <p className="text-[10px] text-slate-400 mt-0.5">{defcon.desc}</p>
          </div>
        </div>
        <div className="flex gap-4 items-center self-stretch justify-between sm:justify-end">
          <div className="text-right">
            <div className="text-[9px] text-slate-500 uppercase">ACTIVE THREAT LEVEL</div>
            <div className="text-sm font-black text-cyber-pink">{(threats.filter(t => t.severity === 'high').length / (threats.length || 1) * 100).toFixed(0)}% HIGH RISK</div>
          </div>
          <div className="h-8 w-px bg-cyber-border hidden sm:block" />
          <div>
            <div className="text-[9px] text-slate-500 uppercase">FEED PACKET STREAM</div>
            <div className="text-sm font-black text-cyber-cyan">{isLive ? 'ESTABLISHED (LIVE)' : 'STANDBY (PAUSED)'}</div>
          </div>
        </div>
      </section>

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
                    LIVE SENSOR INSTANCES
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
                  Common Vulnerabilities and Exposures (CVE) Search registry
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
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            
            {/* Left Column: Feed indicators selector */}
            <div className="lg:col-span-1 bg-cyber-card border border-cyber-border rounded-lg flex flex-col h-[650px] overflow-hidden">
              <div className="bg-cyber-card-light px-4 py-3 border-b border-cyber-border flex flex-col gap-2">
                <span className="text-xs text-cyber-cyan font-bold tracking-wider flex items-center gap-1.5">
                  <Layers className="w-4 h-4 text-cyber-cyan" />
                  INDICATOR SELECTOR
                </span>
                <p className="text-[9px] text-slate-500 uppercase leading-relaxed">
                  Stage suspicious hosts from sensor history for defensive firewall rule compiler deployment.
                </p>
                <div className="flex gap-2 mt-1">
                  <button
                    onClick={selectAllHighThreatIps}
                    className="flex-1 py-1 bg-cyber-pink/10 hover:bg-cyber-pink/20 border border-cyber-pink/30 hover:border-cyber-pink text-cyber-pink text-[8px] font-black uppercase rounded transition-all"
                  >
                    Select All High Risk
                  </button>
                  <button
                    onClick={clearToolkitIps}
                    className="flex-1 py-1 bg-transparent border border-cyber-border hover:border-slate-400 text-slate-400 hover:text-white text-[8px] font-black uppercase rounded transition-all"
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

            {/* Right Column: Code Generator */}
            <div className="lg:col-span-2 bg-cyber-card border border-cyber-border rounded-lg p-5 flex flex-col justify-between h-[650px] overflow-hidden">
              <div className="flex-1 flex flex-col overflow-hidden">
                
                {/* Title & Format bar */}
                <div className="border-b border-cyber-border pb-3 mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="text-xs text-cyber-pink font-bold tracking-wider uppercase flex items-center gap-2">
                      <Terminal className="w-4 h-4 text-cyber-pink" />
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
                        className={`text-[9px] font-extrabold px-2 py-0.5 rounded transition-all uppercase ${
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
                      className="absolute top-3 right-3 p-1.5 bg-cyber-card border border-cyber-border hover:border-cyber-pink text-slate-400 hover:text-cyber-pink rounded transition-all flex items-center gap-1 text-[9px] font-bold"
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
