"use client";

import React, { useState, useEffect, useRef, Suspense } from "react";
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
  Info,
  LogIn,
  UserPlus,
  LogOut,
  Eye,
  Trash2,
  Plus,
  Sparkles,
  LayoutDashboard,
  Cpu,
  FileText,
  Activity,
  Check,
  AlertCircle
} from "lucide-react";
import { 
  scanApi, 
  chatApi, 
  userApi,
  type ScanResult, 
  type HistoryItem,
  type UserStats,
  type WatchlistItem,
  type InspectResult
} from "@/lib/api";
import { useAuth } from "@/context/AuthContext";

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
  const { user, isLoggedIn, openAuthModal, logout } = useAuth();

  // Tracks which `initialUrl` value (from searchParams) has already triggered
  // an auto-scan so we never fire triggerScan() twice for the same param.
  const scannedInitialUrlRef = useRef<string>("");

  // Tracks the last URL actually submitted to the API, used for in-flight
  // deduplication inside triggerScan itself (separate from the param guard).
  const lastScannedUrlRef = useRef<string>("");

  // Active view tab: "scanner" | "user_hub"
  const [activeTab, setActiveTab] = useState<"scanner" | "user_hub">("scanner");

  // Core Scanner states
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [isLoading, setIsLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState("");

  // AI chat states
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { role: "assistant", content: "Hello! I am your PhishGuard AI security co-pilot. Ask me anything about your scan results or threat markers." }
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  // User Section / Real Telemetry states
  const [userStats, setUserStats] = useState<UserStats | null>(null);
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historySearch, setHistorySearch] = useState("");
  const [historyFilter, setHistoryFilter] = useState<string>("all");

  // Watchlist form states
  const [newDomainInput, setNewDomainInput] = useState("");
  const [newLabelInput, setNewLabelInput] = useState("");
  const [watchlistLoading, setWatchlistLoading] = useState(false);
  const [watchlistError, setWatchlistError] = useState("");

  // Grok Deep Content Inspector states
  const [inspectContent, setInspectContent] = useState("");
  const [inspectType, setInspectType] = useState("email_or_text");
  const [inspectLoading, setInspectLoading] = useState(false);
  const [inspectResult, setInspectResult] = useState<InspectResult | null>(null);

  // Load user data on auth change
  useEffect(() => {
    if (isLoggedIn) {
      loadUserData();
    } else {
      setUserStats(null);
      setWatchlist([]);
      setHistory([]);
    }
  }, [isLoggedIn]);

  // Auto-scan when the ?url= search param changes, but only once per unique
  // param value. Uses scannedInitialUrlRef so that manual scans from history
  // items (which update lastScannedUrlRef) never suppress this guard.
  useEffect(() => {
    if (initialUrl && initialUrl !== scannedInitialUrlRef.current) {
      scannedInitialUrlRef.current = initialUrl;
      triggerScan(initialUrl);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUrl]);

  const loadUserData = async () => {
    try {
      const [statsData, watchlistData, historyData] = await Promise.all([
        userApi.getStats().catch(() => null),
        userApi.getWatchlist().catch(() => []),
        scanApi.getHistory().catch(() => [])
      ]);
      if (statsData) setUserStats(statsData);
      setWatchlist(watchlistData);
      setHistory(historyData);
    } catch (err) {}
  };

  // Trigger URL Scan
  const triggerScan = async (urlToScan: string) => {
    const cleanUrl = urlToScan.trim().replace(/^["'<>\s]+|["'<>\s]+$/g, "");
    if (!cleanUrl) return;

    lastScannedUrlRef.current = cleanUrl;
    setIsLoading(true);
    setErrorMsg("");
    setScanResult(null);
    setActiveTab("scanner");

    // Sync browser address bar and Next.js router state so that if the user
    // pastes a new URL into the landing page input later, the ?url= param
    // reflects what is actually being scanned right now.
    const newPath = `/dashboard?url=${encodeURIComponent(cleanUrl)}`;
    if (typeof window !== "undefined") {
      window.history.replaceState(null, "", newPath);
      // Also keep scannedInitialUrlRef in sync so the useEffect guard does not
      // re-fire when Next.js eventually propagates the new searchParam value.
      scannedInitialUrlRef.current = cleanUrl;
    }

    setChatMessages([
      { role: "assistant", content: `Analyzing threat factors for ${cleanUrl}... Send me questions when ready.` }
    ]);

    try {
      const data = await scanApi.scanUrl(cleanUrl);
      setScanResult(data as ScanResult);
      setUrlInput(data.url);
      lastScannedUrlRef.current = data.url;
      if (isLoggedIn) {
        loadUserData();
      }
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to contact the PhishGuard scanning daemon. Please verify server is running.");
    } finally {
      setIsLoading(false);
    }
  };

  // Send AI Chat Message (powered by Grok API)
  const handleSendChatMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || chatLoading) return;
    
    const userMsg = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setChatLoading(true);
    
    try {
      const allMsgs = [...chatMessages, { role: "user" as const, content: userMsg }];
      const reply = await chatApi.sendMessage(allMsgs, scanResult?.url || urlInput || undefined);
      setChatMessages(prev => [...prev, { role: "assistant", content: reply.content }]);
    } catch (err) {
      setChatMessages(prev => [...prev, { role: "assistant", content: "Error communicating with AI security engine." }]);
    } finally {
      setChatLoading(false);
    }
  };

  // Grok Deep Payload Inspector
  const handleInspectContent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inspectContent.trim() || inspectLoading) return;
    setInspectLoading(true);
    setInspectResult(null);

    try {
      const result = await chatApi.inspectContent(inspectContent, inspectType);
      setInspectResult(result);
    } catch (err: any) {
      alert("Failed to analyze content: " + (err.message || "Unknown error"));
    } finally {
      setInspectLoading(false);
    }
  };

  // Add Domain to Watchlist
  const handleAddWatchlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomainInput.trim() || watchlistLoading) return;
    setWatchlistLoading(true);
    setWatchlistError("");

    try {
      const added = await userApi.addToWatchlist(newDomainInput.trim(), newLabelInput.trim() || undefined);
      setWatchlist(prev => [added, ...prev]);
      setNewDomainInput("");
      setNewLabelInput("");
      loadUserData();
    } catch (err: any) {
      setWatchlistError(err.message || "Failed to add domain to watchlist.");
    } finally {
      setWatchlistLoading(false);
    }
  };

  // Delete Domain from Watchlist
  const handleDeleteWatchlist = async (id: number) => {
    try {
      await userApi.deleteFromWatchlist(id);
      setWatchlist(prev => prev.filter(item => item.id !== id));
      loadUserData();
    } catch (err: any) {
      alert("Failed to remove domain: " + err.message);
    }
  };

  // Delete History Record
  const handleDeleteHistory = async (scanId: number) => {
    try {
      await userApi.deleteHistory(scanId);
      setHistory(prev => prev.filter(item => item.id !== scanId));
      loadUserData();
    } catch (err: any) {
      alert("Failed to delete record: " + err.message);
    }
  };

  // PDF Export downloader
  const handleDownloadPDF = async (scanId?: number) => {
    const targetId = scanId || scanResult?.scan_id;
    if (!targetId) return;
    try {
      const url = scanApi.getReportUrl(targetId);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `PhishGuard_Report_${targetId}.pdf`);
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
    const circ = 2 * Math.PI * r;
    const offset = circ - (circ * score) / 100;
    let color = "#10b981";
    let bg = "bg-green-500/10 border-green-500/20 text-green-400";
    if (score >= 70) {
      color = "#ef4444";
      bg = "bg-red-500/10 border-red-500/20 text-red-400";
    } else if (score >= 30) {
      color = "#f59e0b";
      bg = "bg-amber-500/10 border-amber-500/20 text-amber-400";
    }
    return { circ, offset, color, bg };
  };

  const { circ, offset, color: gaugeColor, bg: badgeStyle } = getGaugeParams(scanResult?.risk_score || 0);

  // Filtered history list
  const filteredHistory = history.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(historySearch.toLowerCase());
    const matchesFilter = historyFilter === "all" || item.prediction.toLowerCase() === historyFilter.toLowerCase();
    return matchesSearch && matchesFilter;
  });

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
              <span className="font-bold tracking-tight text-white hidden sm:inline">PhishGuard Security Console</span>
              <span className="font-bold tracking-tight text-white sm:hidden">PhishGuard</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {isLoggedIn ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300">
                  <User className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="font-mono max-w-[140px] truncate">{user?.email}</span>
                </div>
                <button 
                  onClick={logout} 
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 transition-all text-gray-300 flex items-center gap-1"
                >
                  <LogOut className="w-3.5 h-3.5" /> Sign Out
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                <div className="hidden sm:flex items-center gap-1 px-2.5 py-1 rounded-full bg-cyan-950/40 border border-cyan-500/20 text-[11px] font-semibold text-cyan-400">
                  <Eye className="w-3 h-3 text-cyan-400" />
                  Guest Mode
                </div>
                <button 
                  onClick={() => openAuthModal("login")} 
                  className="px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white transition-all shadow-md shadow-indigo-600/10 flex items-center gap-1.5"
                >
                  <LogIn className="w-3.5 h-3.5" /> Sign In
                </button>
                <button 
                  onClick={() => openAuthModal("signup")} 
                  className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-950/60 hover:bg-indigo-900/80 text-indigo-300 border border-indigo-500/30 transition-all"
                >
                  <UserPlus className="w-3.5 h-3.5" /> Sign Up
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Main Tab Controls Navigation */}
      <div className="border-b border-gray-800/80 bg-gray-900/30 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center gap-4 text-xs font-semibold py-2">
          <button
            onClick={() => setActiveTab("scanner")}
            className={`px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
              activeTab === "scanner"
                ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                : "text-gray-400 hover:text-white hover:bg-gray-800/50"
            }`}
          >
            <Cpu className="w-4 h-4" /> Live URL Scanner
          </button>

          <button
            onClick={() => {
              if (!isLoggedIn) {
                openAuthModal("login");
              } else {
                setActiveTab("user_hub");
              }
            }}
            className={`px-4 py-2 rounded-xl transition-all flex items-center gap-2 ${
              activeTab === "user_hub"
                ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                : "text-gray-400 hover:text-white hover:bg-gray-800/50"
            }`}
          >
            <LayoutDashboard className="w-4 h-4" /> 
            User Security Hub
            {isLoggedIn ? (
              <span className="px-1.5 py-0.5 rounded bg-indigo-950 border border-indigo-400/30 text-indigo-300 text-[10px]">
                {userStats?.security_grade || "Grade A"}
              </span>
            ) : (
              <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 text-[10px] flex items-center gap-0.5">
                <Lock className="w-2.5 h-2.5" /> Login
              </span>
            )}
          </button>
        </div>
      </div>

      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full py-8 flex flex-col gap-8 relative z-10">

        {/* ══════════════════════════════════════════════════════════════════════════
            TAB 1: LIVE URL SCANNER CONSOLE
           ══════════════════════════════════════════════════════════════════════════ */}
        {activeTab === "scanner" && (
          <>
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
                  Analyzing SSL handshake, querying Google Safe Browsing, testing brand typosquatting, resolving DNS, and computing AI risk matrices...
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
                        onClick={() => handleDownloadPDF()}
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
                          <span className="text-gray-300 leading-relaxed">No high-risk indicators triggering models. The URL exhibits parameters consistent with safe domains.</span>
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
                    </div>
                  </div>
                </div>

                {/* Right Column: AI Co-pilot & History */}
                <div className="lg:col-span-1 flex flex-col gap-8 h-full">
                  {/* AI Chat Security Widget (Grok Enabled) */}
                  <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4 h-[400px] justify-between">
                    <div className="border-b border-gray-900 pb-3 flex items-center justify-between">
                      <div>
                        <h3 className="text-base font-bold text-white flex items-center gap-2">
                          <Terminal className="w-4.5 h-4.5 text-indigo-400" />
                          AI Security Co-pilot
                        </h3>
                        <span className="text-[10px] text-gray-500">Ask questions about threat markers or mitigation.</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-[10px] text-indigo-300 flex items-center gap-1 font-mono">
                        <Sparkles className="w-2.5 h-2.5 text-cyan-400" /> Grok AI
                      </span>
                    </div>

                    {/* Messages feed */}
                    <div className="flex-grow my-4 overflow-y-auto pr-1 flex flex-col gap-3">
                      {chatMessages.map((msg, idx) => (
                        <div key={idx} className={`p-2.5 rounded-xl text-xs max-w-[85%] ${
                          msg.role === "user" 
                            ? "bg-indigo-600 text-white self-end" 
                            : "bg-gray-900 text-gray-300 border border-gray-850 self-start whitespace-pre-line"
                        }`}>
                          {msg.content}
                        </div>
                      ))}
                      {chatLoading && (
                        <div className="bg-gray-900 border border-gray-850 text-gray-400 p-2.5 rounded-xl text-xs max-w-[80%] self-start animate-pulse flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-indigo-400 animate-ping"></span>
                          Grok analyzing telemetry...
                        </div>
                      )}
                    </div>

                    {/* Message input */}
                    <form onSubmit={handleSendChatMessage} className="flex gap-2">
                      <input 
                        type="text" 
                        placeholder="Ask about this scan result or cyber defense..." 
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

                  {/* Scan History Quick Card */}
                  <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4 flex-grow">
                    <div className="flex items-center justify-between border-b border-gray-900 pb-3">
                      <h3 className="text-base font-bold text-white flex items-center gap-2">
                        <History className="w-4.5 h-4.5 text-cyan-400" />
                        Recent Scan Logs
                      </h3>
                      {isLoggedIn && (
                        <button
                          onClick={() => setActiveTab("user_hub")}
                          className="text-[11px] text-indigo-400 hover:underline"
                        >
                          View Full Hub &rarr;
                        </button>
                      )}
                    </div>

                    {isLoggedIn ? (
                      <div className="flex flex-col gap-2.5 max-h-64 overflow-y-auto pr-1">
                        {history.length > 0 ? (
                          history.slice(0, 5).map((record) => (
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
                        <p className="text-[10px] text-gray-500 leading-relaxed max-w-[200px]">Sign in or create an account to save scan telemetry archives across sessions.</p>
                        <div className="flex items-center gap-2 mt-1">
                          <button 
                            onClick={() => openAuthModal("login")}
                            className="px-3 py-1 text-[11px] font-semibold text-indigo-400 hover:text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 rounded-lg transition-colors"
                          >
                            Sign In
                          </button>
                          <button 
                            onClick={() => openAuthModal("signup")}
                            className="px-3 py-1 text-[11px] font-semibold text-gray-300 hover:text-white bg-gray-900 border border-gray-800 rounded-lg transition-colors"
                          >
                            Sign Up
                          </button>
                        </div>
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
                  Enter a website domain address in the search input bar above. The scanning engine will resolve the endpoint, check live Google Safe Browsing, query SSL certificates, and run AI prediction matrices.
                </p>
              </div>
            )}
          </>
        )}


        {/* ══════════════════════════════════════════════════════════════════════════
            TAB 2: USER SECURITY HUB & GROK DEEP INSPECTOR
           ══════════════════════════════════════════════════════════════════════════ */}
        {activeTab === "user_hub" && isLoggedIn && (
          <div className="flex flex-col gap-10">
            {/* User Telemetry Analytics Grid */}
            <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="glass-card p-5 rounded-2xl border-gray-800 bg-gray-900/30">
                <div className="text-xs text-gray-400 font-medium">Total Scans Executed</div>
                <div className="text-3xl font-extrabold text-white mt-1">{userStats?.total_scans ?? 0}</div>
                <div className="text-[10px] text-gray-500 mt-1">Logged to Neon PostgreSQL</div>
              </div>

              <div className="glass-card p-5 rounded-2xl border-gray-800 bg-gray-900/30">
                <div className="text-xs text-gray-400 font-medium">Threat Interception Rate</div>
                <div className="text-3xl font-extrabold text-red-400 mt-1">{userStats?.threat_rate ?? 0}%</div>
                <div className="text-[10px] text-gray-500 mt-1">{userStats?.phishing_scans ?? 0} Phishing, {userStats?.suspicious_scans ?? 0} Suspicious</div>
              </div>

              <div className="glass-card p-5 rounded-2xl border-gray-800 bg-gray-900/30">
                <div className="text-xs text-gray-400 font-medium">Monitored Watchlist Assets</div>
                <div className="text-3xl font-extrabold text-cyan-400 mt-1">{watchlist.length}</div>
                <div className="text-[10px] text-gray-500 mt-1">Real-time SSL & Threat tracking</div>
              </div>

              <div className="glass-card p-5 rounded-2xl border-gray-800 bg-gray-900/30">
                <div className="text-xs text-gray-400 font-medium">Security Posture Grade</div>
                <div className="text-3xl font-extrabold text-indigo-400 mt-1">{userStats?.security_grade || "A+"}</div>
                <div className="text-[10px] text-gray-500 mt-1">Member since {userStats?.member_since}</div>
              </div>
            </section>

            {/* Monitored Domain Watchlist & Grok Inspector Grid */}
            <section className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-start">
              
              {/* Monitored Domain Watchlist */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-5">
                <div className="flex items-center justify-between border-b border-gray-900 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <Globe className="w-4.5 h-4.5 text-cyan-400" />
                      Monitored Domain Watchlist
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">Track your critical infrastructure domains for SSL expiry and threat flags.</p>
                  </div>
                </div>

                {/* Add domain form */}
                <form onSubmit={handleAddWatchlist} className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    required
                    placeholder="Domain (e.g. company.com)"
                    className="flex-grow bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-indigo-500 text-gray-200"
                    value={newDomainInput}
                    onChange={(e) => setNewDomainInput(e.target.value)}
                  />
                  <input
                    type="text"
                    placeholder="Label (e.g. Auth Portal)"
                    className="w-full sm:w-36 bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 text-xs focus:outline-none focus:border-indigo-500 text-gray-200"
                    value={newLabelInput}
                    onChange={(e) => setNewLabelInput(e.target.value)}
                  />
                  <button
                    type="submit"
                    disabled={watchlistLoading}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-xl text-xs font-semibold flex items-center justify-center gap-1 shadow-md shadow-indigo-600/20 whitespace-nowrap"
                  >
                    {watchlistLoading ? <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin"></span> : <Plus className="w-3.5 h-3.5" />}
                    Add Domain
                  </button>
                </form>

                {watchlistError && (
                  <div className="p-2.5 rounded-lg bg-red-950/30 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
                    <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                    <span>{watchlistError}</span>
                  </div>
                )}

                {/* Watchlist items */}
                <div className="flex flex-col gap-3 max-h-80 overflow-y-auto pr-1">
                  {watchlist.length > 0 ? (
                    watchlist.map((item) => (
                      <div key={item.id} className="p-3.5 rounded-xl bg-gray-950/40 border border-gray-850 flex items-center justify-between gap-3 text-xs">
                        <div className="flex flex-col gap-0.5 truncate">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-gray-200">{item.domain}</span>
                            {item.label && (
                              <span className="px-2 py-0.5 rounded bg-gray-900 text-gray-400 text-[10px] border border-gray-800">
                                {item.label}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-gray-500 mt-1">
                            <span className={item.ssl_valid ? "text-green-400" : "text-red-400"}>
                              SSL: {item.ssl_valid ? `Valid (${item.ssl_days_left}d left)` : "Invalid"}
                            </span>
                            <span>•</span>
                            <span>Score: {item.risk_score}</span>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => triggerScan(item.domain)}
                            className="px-2.5 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white text-[11px] border border-gray-800"
                          >
                            Scan
                          </button>
                          <button
                            onClick={() => handleDeleteWatchlist(item.id)}
                            className="p-1.5 rounded-lg hover:bg-red-950/40 text-gray-500 hover:text-red-400 transition-colors"
                            title="Remove"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-gray-500 text-xs italic">
                      No domains added to watchlist yet. Add your critical websites above to monitor security posture.
                    </div>
                  )}
                </div>
              </div>

              {/* Grok AI Deep Content Inspector */}
              <div className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-5">
                <div className="flex items-center justify-between border-b border-gray-900 pb-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <Sparkles className="w-4.5 h-4.5 text-indigo-400" />
                      Grok AI Deep Threat Inspector
                    </h3>
                    <p className="text-xs text-gray-400 mt-0.5">Analyze suspicious phishing email bodies, SMS messages, or raw HTML scripts.</p>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-[10px] font-mono text-indigo-300">
                    xAI Grok
                  </span>
                </div>

                <form onSubmit={handleInspectContent} className="flex flex-col gap-3">
                  <div className="flex gap-2 text-xs">
                    <select
                      value={inspectType}
                      onChange={(e) => setInspectType(e.target.value)}
                      className="bg-gray-950 border border-gray-800 rounded-xl px-3 py-1.5 text-xs text-gray-300 focus:outline-none"
                    >
                      <option value="email_or_text">Email / SMS Message</option>
                      <option value="html_script">Raw HTML / JavaScript Snippet</option>
                      <option value="url_snippet">Suspicious URL / Header String</option>
                    </select>
                  </div>

                  <textarea
                    rows={4}
                    required
                    placeholder="Paste suspicious email text, SMS message, or login form script here..."
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-xs text-gray-200 focus:outline-none focus:border-indigo-500 resize-none font-mono"
                    value={inspectContent}
                    onChange={(e) => setInspectContent(e.target.value)}
                  />

                  <button
                    type="submit"
                    disabled={inspectLoading || !inspectContent.trim()}
                    className="py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white rounded-xl text-xs font-semibold flex items-center justify-center gap-2 shadow-lg shadow-indigo-600/20"
                  >
                    {inspectLoading ? (
                      <>
                        <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                        Grok Analyzing Payload...
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-3.5 h-3.5" />
                        Run Grok Deep Threat Analysis
                      </>
                    )}
                  </button>
                </form>

                {inspectResult && (
                  <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 flex flex-col gap-3 text-xs animate-in fade-in duration-200">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-gray-300">Grok Threat Evaluation:</span>
                      <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold ${
                        inspectResult.risk_level === "Safe" ? "bg-green-500/10 text-green-400 border border-green-500/20" :
                        inspectResult.risk_level === "Suspicious" ? "bg-amber-500/10 text-amber-400 border border-amber-500/20" :
                        "bg-red-500/10 text-red-400 border border-red-500/20"
                      }`}>
                        {inspectResult.risk_level}
                      </span>
                    </div>

                    <p className="text-gray-300 leading-relaxed">{inspectResult.analysis}</p>

                    {inspectResult.indicators.length > 0 && (
                      <div className="flex flex-col gap-1 mt-1">
                        <span className="text-[10px] uppercase font-bold text-gray-500">Triggered Indicators</span>
                        <div className="flex flex-wrap gap-1.5">
                          {inspectResult.indicators.map((ind, idx) => (
                            <span key={idx} className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] text-gray-400">
                              {ind}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="pt-2 border-t border-gray-900 text-gray-400 text-[11px]">
                      <strong>Recommendation:</strong> {inspectResult.recommendation}
                    </div>
                  </div>
                )}
              </div>

            </section>

            {/* Comprehensive Scan History Manager */}
            <section className="glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-900 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <History className="w-4.5 h-4.5 text-indigo-400" />
                    Personal Scan History Archives ({filteredHistory.length})
                  </h3>
                  <p className="text-xs text-gray-400">All security scans recorded to your Neon PostgreSQL database.</p>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Search URLs..."
                    className="bg-gray-950 border border-gray-800 rounded-xl px-3 py-1.5 text-xs text-gray-200 focus:outline-none"
                    value={historySearch}
                    onChange={(e) => setHistorySearch(e.target.value)}
                  />

                  <select
                    value={historyFilter}
                    onChange={(e) => setHistoryFilter(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-xl px-3 py-1.5 text-xs text-gray-300 focus:outline-none"
                  >
                    <option value="all">All Predictions</option>
                    <option value="safe">Safe Only</option>
                    <option value="suspicious">Suspicious Only</option>
                    <option value="phishing">Phishing Only</option>
                  </select>
                </div>
              </div>

              {/* History Table */}
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-400 uppercase text-[10px] tracking-wider">
                      <th className="pb-3 font-semibold">Target URL</th>
                      <th className="pb-3 font-semibold">Prediction</th>
                      <th className="pb-3 font-semibold">Risk Score</th>
                      <th className="pb-3 font-semibold">Date Scanned</th>
                      <th className="pb-3 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-900">
                    {filteredHistory.length > 0 ? (
                      filteredHistory.map((row) => (
                        <tr key={row.id} className="hover:bg-gray-900/30 transition-colors">
                          <td className="py-3 font-mono font-medium text-gray-200 max-w-xs truncate">{row.url}</td>
                          <td className="py-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              row.prediction === "Safe" ? "bg-green-500/10 text-green-400" :
                              row.prediction === "Suspicious" ? "bg-amber-500/10 text-amber-400" :
                              "bg-red-500/10 text-red-400"
                            }`}>
                              {row.prediction}
                            </span>
                          </td>
                          <td className="py-3 font-mono text-gray-300 font-bold">{Math.round(row.risk_score)}/100</td>
                          <td className="py-3 text-gray-500 text-[11px]">{new Date(row.created_at).toLocaleString()}</td>
                          <td className="py-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => triggerScan(row.url)}
                                className="p-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white"
                                title="Re-scan URL"
                              >
                                <Cpu className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDownloadPDF(row.id)}
                                className="p-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 text-gray-300 hover:text-white"
                                title="Download PDF Report"
                              >
                                <Download className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleDeleteHistory(row.id)}
                                className="p-1.5 rounded-lg hover:bg-red-950/40 text-gray-500 hover:text-red-400"
                                title="Delete Record"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-gray-500 italic">
                          No scan history records match your search query.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-950 mt-auto py-6 text-gray-500 text-[10px]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-indigo-400" />
            <span className="font-semibold text-gray-400">PhishGuard Security Intelligence Suite</span>
          </div>
          <div className="flex items-center gap-4">
            <span>Grok AI Intelligence Enabled</span>
            <span>&bull;</span>
            <span>Neon DB Connected</span>
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
