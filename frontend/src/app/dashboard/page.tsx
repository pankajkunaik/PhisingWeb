"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { 
  Shield, 
  ArrowLeft, 
  Search, 
  Download, 
  AlertTriangle, 
  CheckCircle, 
  HelpCircle,
  Lock,
  Globe,
  Server,
  Terminal,
  Send,
  User,
  History,
  Info
} from "lucide-react";

interface ScanResponse {
  scan_id?: number;
  url: string;
  domain: string;
  risk_score: number;
  prediction: string;
  reasons: string[];
  xai_explanations: Array<{ factor: string; severity: string }>;
  lexical_features: Record<string, number>;
  html_features: {
    external_links_ratio: number;
    iframe_present: number;
    disables_right_click: number;
    has_unsafe_form: number;
    favicon_external: number;
  };
  whois_info: {
    domain_age_days: number;
    registrar: string;
    creation_date: string;
    expiration_date: string;
    country: string;
  };
  ssl_info: {
    valid: boolean;
    issuer: string;
    expiration_date: string;
    cipher: string;
    error?: string;
  };
  dns_info: {
    ips: string[];
    mx_servers: string[];
    ns_servers: string[];
    hosting_provider: string;
  };
}

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

function DashboardContent() {
  const searchParams = useSearchParams();
  const initialUrl = searchParams.get("url") || "";

  // Core App states
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  // AI chat states
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { role: "assistant", content: "Hello! I am your PhishGuard AI assistant. I can explain the threat markers of any website you scan. Just ask!" }
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  // Auth states
  const [jwt, setJwt] = useState<string | null>(null);
  const [emailInput, setEmailInput] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [history, setHistory] = useState<Array<{ id: number; url: string; risk_score: number; prediction: string; created_at: string }>>([]);

  // Load token on start
  useEffect(() => {
    const token = localStorage.getItem("pg_token");
    if (token) {
      setJwt(token);
      setIsLoggedIn(true);
      fetchHistory(token);
    }
    
    // Auto scan if url query exists
    if (initialUrl) {
      triggerScan(initialUrl);
    }
  }, [initialUrl]);

  // Auth API handlers
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    try {
      const res = await fetch("http://127.0.0.1:8000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailInput, password: passwordInput })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Invalid email or password");
      localStorage.setItem("pg_token", data.access_token);
      setJwt(data.access_token);
      setIsLoggedIn(true);
      setShowAuthModal(false);
      fetchHistory(data.access_token);
      // Clear inputs
      setEmailInput("");
      setPasswordInput("");
    } catch (err: any) {
      setErrorMsg(err.message || "Something went wrong");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("pg_token");
    setJwt(null);
    setIsLoggedIn(false);
    setHistory([]);
    alert("Logged out successfully.");
  };

  const fetchHistory = async (token: string) => {
    try {
      const res = await fetch("http://127.0.0.1:8000/api/history", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {}
  };

  // Scan Action trigger
  const triggerScan = async (urlToScan: string) => {
    if (!urlToScan.trim()) return;
    setIsLoading(true);
    setErrorMsg("");
    setScanResult(null);
    
    // Reset Chat messages for new context
    setChatMessages([
      { role: "assistant", content: `Analyzing threat factors for ${urlToScan}... Send me questions when ready.` }
    ]);

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (jwt) {
        headers["Authorization"] = `Bearer ${jwt}`;
      }

      const res = await fetch("http://127.0.0.1:8000/api/scan", {
        method: "POST",
        headers: headers,
        body: JSON.stringify({ url: urlToScan })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Scanning failed");
      }
      
      setScanResult(data);
      setUrlInput(data.url);
      
      // Refresh history if logged in
      if (jwt) {
        fetchHistory(jwt);
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to contact the PhishGuard scanning daemon.");
    } finally {
      setIsLoading(false);
    }
  };

  // Send AI message
  const handleSendChatMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;
    
    const userMsg = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setChatLoading(true);
    
    try {
      const res = await fetch("http://127.0.0.1:8000/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: [...chatMessages, { role: "user", content: userMsg }].map(m => ({ role: m.role, content: m.content })),
          url_context: scanResult?.url || urlInput || null
        })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error("Chat assistant failed");
      }
      
      setChatMessages(prev => [...prev, { role: "assistant", content: data.content }]);
    } catch (err) {
      setChatMessages(prev => [...prev, { role: "assistant", content: "Error communicating with AI security engine." }]);
    } finally {
      setChatLoading(false);
    }
  };

  // PDF Export downloader
  const handleDownloadPDF = async () => {
    if (!scanResult || !scanResult.scan_id) return;
    try {
      const url = `http://127.0.0.1:8000/api/report/${scanResult.scan_id}`;
      // Trigger file download directly by creating link element
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `PhishGuard_Report_${scanResult.scan_id}.pdf`);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    } catch (err) {
      alert("Failed to export PDF report.");
    }
  };

  // Circular gauge config
  const getGaugeParams = (score: number) => {
    const r = 40;
    const circ = 2 * Math.PI * r; // ~251.2
    const offset = circ - (circ * score) / 100;
    let color = "#10b981"; // Safe
    let bg = "bg-green-500/10 border-green-500/20 text-green-400";
    if (score >= 70) {
      color = "#ef4444"; // Danger
      bg = "bg-red-500/10 border-red-500/20 text-red-400";
    } else if (score >= 30) {
      color = "#f59e0b"; // Warning
      bg = "bg-amber-500/10 border-amber-500/20 text-amber-400";
    }
    return { circ, offset, color, bg };
  };

  const { circ, offset, color: gaugeColor, bg: badgeStyle } = getGaugeParams(scanResult?.risk_score || 0);

  return (
    <div className="relative min-h-screen flex flex-col bg-gray-950 text-gray-100 overflow-hidden">
      {/* Glow Orbs */}
      <div className="glow-orb-primary -top-40 right-[-100px] opacity-20"></div>
      <div className="glow-orb-secondary bottom-[-100px] left-[-100px] opacity-20"></div>

      {/* Header bar */}
      <header className="sticky top-0 z-40 w-full border-b border-gray-800 bg-gray-950/95 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="p-2 hover:bg-gray-900 border border-transparent hover:border-gray-800 rounded-lg transition-all">
              <ArrowLeft className="w-5 h-5 text-gray-400 hover:text-white" />
            </Link>
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-indigo-400" />
              <span className="font-bold tracking-tight text-white hidden sm:inline">PhishGuard Security Dashboard</span>
              <span className="font-bold tracking-tight text-white sm:hidden">PhishGuard</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {isLoggedIn ? (
              <div className="flex items-center gap-3">
                <span className="text-xs text-gray-400 font-mono hidden md:inline">User: {localStorage.getItem("pg_token") ? "Active Session" : ""}</span>
                <button 
                  onClick={handleLogout} 
                  className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 transition-all text-gray-300"
                >
                  Log Out
                </button>
              </div>
            ) : (
              <button 
                onClick={() => setShowAuthModal(true)} 
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-md shadow-indigo-600/10 flex items-center gap-1.5"
              >
                <User className="w-3.5 h-3.5" /> Sign In
              </button>
            )}
          </div>
        </div>
      </header>

      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full py-8 flex flex-col gap-8 relative z-10">
        {/* URL Input Bar */}
        <section className="w-full">
          <form onSubmit={(e) => { e.preventDefault(); triggerScan(urlInput); }} className="glass-card p-2.5 rounded-2xl flex items-center gap-3 border-gray-800 bg-gray-900/40">
            <Search className="w-5 h-5 text-gray-500 ml-3 flex-shrink-0" />
            <input 
              type="text" 
              placeholder="Enter domain or full URL to scan (e.g. facebook-signin-claim.org)" 
              className="flex-grow bg-transparent border-0 ring-0 focus:outline-none text-sm text-gray-200 py-2"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              disabled={isLoading}
            />
            <button 
              type="submit" 
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-xl transition-all flex items-center gap-2 shadow-lg shadow-indigo-700/10"
              disabled={isLoading || !urlInput.trim()}
            >
              {isLoading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  Analyzing...
                </>
              ) : (
                "Scan Site"
              )}
            </button>
          </form>
        </section>

        {errorMsg && (
          <div className="p-4 rounded-xl bg-red-950/25 border border-red-500/30 text-red-300 text-sm flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            {errorMsg}
          </div>
        )}

        {/* Loading placeholder */}
        {isLoading && (
          <div className="glass-card p-12 rounded-2xl border-gray-800 bg-gray-900/20 text-center flex flex-col items-center gap-4">
            <div className="relative w-16 h-16">
              <div className="absolute inset-0 rounded-full border-4 border-indigo-500/20"></div>
              <div className="absolute inset-0 rounded-full border-4 border-indigo-500 border-t-transparent animate-spin"></div>
            </div>
            <div className="font-semibold text-lg text-gray-200">PhishGuard Security Core Resolving Endpoint</div>
            <p className="text-xs text-gray-400 max-w-sm">
              Analyzing SSL handshake parameters, resolving DNS IP maps, testing brand similarity algorithms, and computing machine learning prediction matrices...
            </p>
          </div>
        )}

        {/* Diagnostic Dashboard Results Grid */}
        {scanResult && !isLoading && (
          <section className="grid grid-cols-1 lg:grid-cols-3 gap-8 w-full items-start">
            
            {/* Left Column: Risk Score & Explainable AI */}
            <div className="lg:col-span-1 flex flex-col gap-8">
              
              {/* Score Gauge Card */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 text-center flex flex-col items-center gap-4 relative overflow-hidden">
                <div className="absolute top-4 right-4">
                  <button 
                    onClick={handleDownloadPDF}
                    className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-400 hover:text-white transition-all"
                    title="Download PDF Report"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                </div>

                <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-400">Threat Risk score</h3>
                
                {/* SVG Gauge */}
                <div className="relative w-36 h-36 flex items-center justify-center my-2">
                  <svg className="w-full h-full" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="40" stroke="#1f2937" strokeWidth="7" fill="none" />
                    <circle 
                      cx="50" 
                      cy="50" 
                      r="40" 
                      stroke={gaugeColor} 
                      strokeWidth="7" 
                      fill="none"
                      strokeDasharray={circ} 
                      strokeDashoffset={offset}
                      strokeLinecap="round" 
                      className="transition-all duration-700 transform -rotate-90 origin-center" 
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-extrabold text-white">{Math.round(scanResult.risk_score)}</span>
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest mt-0.5">Rating</span>
                  </div>
                </div>

                <div className={`px-4 py-1.5 rounded-full border text-xs font-bold uppercase tracking-wider ${badgeStyle}`}>
                  {scanResult.prediction}
                </div>
                
                <div className="text-xs text-gray-400 text-center max-w-xs leading-relaxed mt-1">
                  Target: <strong className="font-mono text-gray-300 break-all">{scanResult.domain}</strong>
                </div>
              </div>

              {/* Explainable AI Factors */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Info className="w-4.5 h-4.5 text-indigo-400" />
                  AI Explanations (XAI)
                </h3>
                
                <div className="flex flex-col gap-3">
                  {scanResult.xai_explanations.length > 0 ? (
                    scanResult.xai_explanations.map((item, idx) => (
                      <div key={idx} className="flex gap-2.5 items-start text-xs bg-gray-950/40 border border-gray-900 p-3 rounded-xl">
                        <AlertTriangle className={`w-4 h-4 flex-shrink-0 mt-0.5 ${item.severity === "high" ? "text-red-400" : "text-amber-400"}`} />
                        <span className="text-gray-300 leading-relaxed">{item.factor}</span>
                      </div>
                    ))
                  ) : (
                    <div className="flex gap-2.5 items-start text-xs bg-gray-950/40 border border-gray-900 p-3 rounded-xl">
                      <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0 mt-0.5" />
                      <span className="text-gray-300 leading-relaxed">No significant risk indicators triggering models. The URL exhibits parameters consistent with safe domains.</span>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Middle Column: Detailed Technical Diagnostics */}
            <div className="lg:col-span-1 flex flex-col gap-8">
              
              {/* SSL Certificate Diagnostics */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Lock className="w-4.5 h-4.5 text-cyan-400" />
                  SSL Certificate Check
                </h3>
                
                <div className="grid grid-cols-1 gap-3.5 text-xs">
                  <div className="flex justify-between items-center p-2.5 rounded-lg bg-gray-950/30 border border-gray-900">
                    <span className="text-gray-400">Connection Trust:</span>
                    <span className={`font-semibold ${scanResult.ssl_info.valid ? "text-green-400" : "text-red-400"}`}>
                      {scanResult.ssl_info.valid ? "HTTPS Secure" : "Insecure (Failed)"}
                    </span>
                  </div>
                  
                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Issuer</span>
                    <span className="font-medium text-gray-300 font-mono truncate bg-gray-950/30 border border-gray-900 p-2 rounded">{scanResult.ssl_info.issuer}</span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Cipher Specs</span>
                    <span className="font-medium text-gray-300 font-mono truncate bg-gray-950/30 border border-gray-900 p-2 rounded">{scanResult.ssl_info.cipher}</span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Expiration Schedule</span>
                    <span className="font-medium text-gray-300 font-mono bg-gray-950/30 border border-gray-900 p-2 rounded">
                      {scanResult.ssl_info.expiration_date !== "None" 
                        ? new Date(scanResult.ssl_info.expiration_date).toLocaleDateString()
                        : "No Certificate Info"}
                    </span>
                  </div>
                </div>
              </div>

              {/* WHOIS Intelligence Card */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Globe className="w-4.5 h-4.5 text-indigo-400" />
                  WHOIS Registration Details
                </h3>
                
                <div className="grid grid-cols-1 gap-3.5 text-xs">
                  <div className="flex justify-between items-center p-2.5 rounded-lg bg-gray-950/30 border border-gray-900">
                    <span className="text-gray-400">Domain Age:</span>
                    <span className={`font-semibold ${scanResult.whois_info.domain_age_days >= 90 ? "text-green-400" : "text-amber-400"}`}>
                      {scanResult.whois_info.domain_age_days} Days Registered
                    </span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Registrar</span>
                    <span className="font-medium text-gray-300 font-mono truncate bg-gray-950/30 border border-gray-900 p-2 rounded">{scanResult.whois_info.registrar}</span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Registration Created</span>
                    <span className="font-medium text-gray-300 font-mono bg-gray-950/30 border border-gray-900 p-2 rounded">
                      {scanResult.whois_info.creation_date !== "Unknown" 
                        ? new Date(scanResult.whois_info.creation_date).toLocaleDateString() 
                        : "Unknown"}
                    </span>
                  </div>

                  <div className="flex justify-between items-center p-2 bg-gray-950/30 border border-gray-900 rounded">
                    <span className="text-gray-500 text-[10px] uppercase tracking-wider font-semibold">Registrar Country</span>
                    <span className="font-bold text-gray-300 uppercase">{scanResult.whois_info.country}</span>
                  </div>
                </div>
              </div>

              {/* DNS Query Telemetry */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <Server className="w-4.5 h-4.5 text-cyan-400" />
                  DNS Records Resolver
                </h3>
                
                <div className="grid grid-cols-1 gap-3.5 text-xs">
                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Resolved IP Addresses</span>
                    <div className="bg-gray-950/30 border border-gray-900 p-2 rounded flex flex-col gap-1 max-h-24 overflow-y-auto">
                      {scanResult.dns_info.ips.length > 0 ? (
                        scanResult.dns_info.ips.map((ip, idx) => <span key={idx} className="font-mono text-gray-300">{ip}</span>)
                      ) : (
                        <span className="text-gray-600 italic">No IP resolution found</span>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Hosting Provider / DNS Origin</span>
                    <span className="font-medium text-gray-300 bg-gray-950/30 border border-gray-900 p-2 rounded">{scanResult.dns_info.hosting_provider}</span>
                  </div>

                  <div className="flex flex-col gap-1">
                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Mail Exchange (MX) records</span>
                    <div className="bg-gray-950/30 border border-gray-900 p-2 rounded truncate max-h-24 overflow-y-auto">
                      {scanResult.dns_info.mx_servers.length > 0 ? (
                        scanResult.dns_info.mx_servers.map((mx, idx) => <span key={idx} className="font-mono text-gray-400 block truncate">{mx}</span>)
                      ) : (
                        <span className="text-gray-600 italic">No mail servers active</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

            </div>

            {/* Right Column: AI Co-pilot & History */}
            <div className="lg:col-span-1 flex flex-col gap-8 h-full">
              
              {/* AI Chat Security Widget */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4 h-[400px] justify-between">
                <div className="border-b border-gray-900 pb-3">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4.5 h-4.5 text-indigo-400" />
                    AI Security Co-pilot
                  </h3>
                  <span className="text-[10px] text-gray-500">Ask questions about threat parameters or security protocols.</span>
                </div>

                {/* Messages feed */}
                <div className="flex-grow my-4 overflow-y-auto pr-1 flex flex-col gap-3">
                  {chatMessages.map((msg, idx) => (
                    <div key={idx} className={`p-2.5 rounded-xl text-xs max-w-[85%] ${
                      msg.role === "user" 
                        ? "bg-indigo-600 text-white self-end" 
                        : "bg-gray-900 text-gray-300 border border-gray-850 self-start"
                    }`}>
                      {msg.content}
                    </div>
                  ))}
                  {chatLoading && (
                    <div className="bg-gray-900 border border-gray-850 text-gray-500 p-2.5 rounded-xl text-xs max-w-[80%] self-start animate-pulse">
                      Analyzing data...
                    </div>
                  )}
                </div>

                {/* Message input */}
                <form onSubmit={handleSendChatMessage} className="flex gap-2">
                  <input 
                    type="text" 
                    placeholder="Ask about this scan result..." 
                    className="flex-grow bg-gray-950 border border-gray-900 rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-indigo-500"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    disabled={chatLoading}
                  />
                  <button 
                    type="submit" 
                    className="p-2 bg-indigo-600 hover:bg-indigo-500 rounded-xl text-white transition-all flex items-center justify-center flex-shrink-0"
                    disabled={chatLoading}
                  >
                    <Send className="w-3.5 h-3.5" />
                  </button>
                </form>
              </div>

              {/* Developer Logs / User History */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4 flex-grow">
                <h3 className="text-base font-bold text-white flex items-center gap-2 border-b border-gray-900 pb-3">
                  <History className="w-4.5 h-4.5 text-cyan-400" />
                  Scan Logs history
                </h3>

                {isLoggedIn ? (
                  <div className="flex flex-col gap-2.5 max-h-64 overflow-y-auto pr-1">
                    {history.length > 0 ? (
                      history.map((record) => (
                        <div 
                          key={record.id} 
                          onClick={() => triggerScan(record.url)}
                          className="p-2.5 rounded-lg border border-gray-900 hover:border-gray-800 bg-gray-950/20 cursor-pointer flex items-center justify-between text-xs transition-all duration-200"
                        >
                          <div className="flex flex-col gap-0.5 truncate max-w-[70%]">
                            <span className="font-mono text-gray-300 font-bold truncate">{record.url}</span>
                            <span className="text-[10px] text-gray-500">{new Date(record.created_at).toLocaleDateString()}</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            record.prediction === "Safe" ? "bg-green-500/10 text-green-400" :
                            record.prediction === "Suspicious" ? "bg-amber-500/10 text-amber-400" :
                            "bg-red-500/10 text-red-400"
                          }`}>
                            Score: {Math.round(record.risk_score)}
                          </span>
                        </div>
                      ))
                    ) : (
                      <span className="text-xs text-gray-500 italic">No previous scans found. Enter a URL to start history logs.</span>
                    )}
                  </div>
                ) : (
                  <div className="p-4 rounded-xl border border-gray-900 bg-gray-950/30 text-center flex flex-col items-center gap-3">
                    <HelpCircle className="w-8 h-8 text-gray-600" />
                    <span className="text-xs text-gray-400 font-medium">Session History is Locked</span>
                    <p className="text-[10px] text-gray-500 leading-relaxed max-w-[200px]">Sign in with a developer profile to log scans and review threat telemetry archives.</p>
                    <button 
                      onClick={() => setShowAuthModal(true)}
                      className="text-[10px] font-semibold text-indigo-400 hover:text-indigo-300"
                    >
                      Authenticate Now &rarr;
                    </button>
                  </div>
                )}
              </div>

            </div>

          </section>
        )}

        {/* Empty State when no url is searched */}
        {!scanResult && !isLoading && (
          <div className="glass-card p-16 rounded-2xl border-gray-800 bg-gray-900/10 text-center flex flex-col items-center gap-4 max-w-xl mx-auto my-12">
            <Shield className="w-12 h-12 text-indigo-500/80 animate-pulse" />
            <h3 className="text-lg font-bold text-gray-200">Awaiting Search Input</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Enter a website domain address in the search input bar above. The scanning engine will resolve the endpoint, query certificates, check brand impersonations, and run machine learning predictions.
            </p>
          </div>
        )}
      </main>

      {/* Modern Credentials Auth Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-950/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm glass-card p-6 rounded-2xl border-gray-800 bg-gray-900 flex flex-col gap-4 shadow-xl shadow-black/80">
            <div className="flex items-center justify-between border-b border-gray-900 pb-3">
              <h3 className="text-base font-bold text-white">
                Developer Sign In
              </h3>
              <button 
                onClick={() => setShowAuthModal(false)} 
                className="text-gray-500 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>
            
            <form onSubmit={handleAuthSubmit} className="flex flex-col gap-3 text-xs">
              <div className="flex flex-col gap-1">
                <label className="text-gray-400">Email Address</label>
                <input 
                  type="email" 
                  required
                  placeholder="name@company.com" 
                  className="bg-gray-950 border border-gray-900 rounded-lg p-2.5 text-gray-200 focus:outline-none focus:border-indigo-500"
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                />
              </div>

              <div className="flex flex-col gap-1">
                <label className="text-gray-400">Password</label>
                <input 
                  type="password" 
                  required
                  placeholder="••••••••" 
                  className="bg-gray-950 border border-gray-900 rounded-lg p-2.5 text-gray-200 focus:outline-none focus:border-indigo-500"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                />
              </div>

              <button 
                type="submit" 
                className="mt-2 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold shadow-md shadow-indigo-600/15"
              >
                Log In
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-950 mt-auto py-6 text-gray-500 text-[10px]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            <span className="font-semibold text-gray-400">PhishGuard Security Dashboard console</span>
          </div>
          <div>
            &copy; {new Date().getFullYear()} PhishGuard AI. All diagnostic queries are secured.
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function DashboardPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center gap-3">
        <div className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
        <span className="text-xs text-gray-400 font-mono">Initializing Console...</span>
      </div>
    }>
      <DashboardContent />
    </Suspense>
  );
}
