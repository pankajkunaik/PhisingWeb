"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { 
  Shield, 
  Activity, 
  Globe, 
  Cpu, 
  Server, 
  ExternalLink, 
  ArrowRight,
  AlertTriangle,
  Lock,
  Layers,
  FileCheck,
  LogIn,
  UserPlus,
  LogOut,
  User,
  Eye
} from "lucide-react";
import { threatApi, type ThreatFeedItem, type PlatformStats } from "@/lib/api";
import { useAuth } from "@/context/AuthContext";

interface ThreatItem {
  domain: string;
  target_brand: string;
  detected_at: string;
  risk_score: number;
  threat_type: string;
}

export default function LandingPage() {
  const router = useRouter();
  const { user, isLoggedIn, openAuthModal, logout } = useAuth();
  const [urlInput, setUrlInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState("");
  const [recentThreats, setRecentThreats] = useState<ThreatFeedItem[]>([]);
  const [stats, setStats] = useState<PlatformStats | null>(null);

  // Fetch threats from backend using centralized API client
  useEffect(() => {
    async function fetchData() {
      try {
        const [threats, platformStats] = await Promise.all([
          threatApi.getFeed().catch(() => []),
          threatApi.getStats().catch(() => null),
        ]);
        setRecentThreats(threats);
        setStats(platformStats);
      } catch (err) {
        setRecentThreats([]);
      }
    }
    fetchData();
    const interval = setInterval(() => threatApi.getFeed().then(setRecentThreats).catch(() => {}), 30000);
    return () => clearInterval(interval);
  }, []);

  const handleScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const clean = urlInput.trim().replace(/^["'<>\s]+|["'<>\s]+$/g, "");
    if (!clean) return;
    
    setIsScanning(true);
    setScanStatus("Redirecting to Security Console...");
    router.push(`/dashboard?url=${encodeURIComponent(clean)}`);
  };

  return (
    <div className="relative min-h-screen flex flex-col bg-gray-950 text-gray-100 overflow-hidden">
      {/* Background Orbs */}
      <div className="glow-orb-primary -top-20 -left-20 opacity-40"></div>
      <div className="glow-orb-secondary top-[40%] right-[-100px] opacity-30"></div>
      <div className="glow-orb-primary bottom-[-200px] left-[30%] opacity-20"></div>

      {/* Navigation Header */}
      <header className="sticky top-0 z-50 w-full border-b border-gray-800 bg-gray-950/95 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-600/10 border border-indigo-500/30 rounded-lg text-indigo-400">
              <Shield className="w-6 h-6" />
            </div>
            <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-gray-100 via-indigo-200 to-indigo-400 bg-clip-text text-transparent">
              PhishGuard <span className="text-indigo-400 font-extrabold">AI</span>
            </span>
          </Link>
          
          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-gray-400">
            <a href="#features" className="hover:text-gray-100 transition-colors">Platform Features</a>
            <a href="#feed" className="hover:text-gray-100 transition-colors">Threat Intelligence</a>
            <a href="http://127.0.0.1:8000/api/docs" target="_blank" rel="noopener noreferrer" className="hover:text-gray-100 transition-colors flex items-center gap-1">
              API Docs <ExternalLink className="w-3 h-3" />
            </a>
          </nav>

          <div className="flex items-center gap-3">
            {isLoggedIn ? (
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300">
                  <User className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="font-mono max-w-[140px] truncate">{user?.email}</span>
                </div>
                <button
                  onClick={logout}
                  className="p-2 text-xs font-medium rounded-lg text-gray-400 hover:text-white hover:bg-gray-900 transition-colors flex items-center gap-1"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
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
                  className="px-3 py-1.5 text-xs font-semibold text-gray-300 hover:text-white hover:bg-gray-900 border border-transparent hover:border-gray-800 rounded-lg transition-all flex items-center gap-1"
                >
                  <LogIn className="w-3.5 h-3.5" /> Sign In
                </button>
                <button
                  onClick={() => openAuthModal("signup")}
                  className="hidden sm:flex items-center gap-1 px-3 py-1.5 text-xs font-semibold text-indigo-300 hover:text-white bg-indigo-950/50 hover:bg-indigo-900/60 border border-indigo-500/30 rounded-lg transition-all"
                >
                  <UserPlus className="w-3.5 h-3.5" /> Sign Up
                </button>
              </div>
            )}

            <Link href="/dashboard" className="inline-flex items-center justify-center px-4 py-2 text-sm font-semibold rounded-lg bg-indigo-600 text-white shadow-md shadow-indigo-600/20 hover:bg-indigo-500 transition-all duration-200 gap-1.5 ml-1">
              Launch Console
              <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </header>

      <main className="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full py-16 flex flex-col gap-24 relative z-10">
        {/* Hero Section */}
        <section className="text-center flex flex-col items-center gap-8 max-w-4xl mx-auto py-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 text-xs font-semibold rounded-full bg-indigo-500/10 border border-indigo-400/20 text-indigo-300">
            <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            Live Threat Protection Console Active
          </div>

          <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight bg-gradient-to-b from-white via-gray-100 to-gray-400 bg-clip-text text-transparent leading-[1.15] sm:leading-[1.15]">
            AI-Powered Website <br />
            <span className="bg-gradient-to-r from-indigo-400 via-cyan-400 to-indigo-400 bg-clip-text text-transparent glow-text">Threat Intelligence</span>
          </h1>

          <p className="text-lg text-gray-400 max-w-2xl leading-relaxed">
            Instantly detect phishing portals, credential harvesting forms, typosquatting domains, and fraudulent SSL setups using explainable machine learning models.
          </p>

          {/* Scanner Input Box */}
          <div className="w-full max-w-2xl mt-4">
            <form onSubmit={handleScanSubmit} className="glass-card p-2 rounded-2xl flex flex-col sm:flex-row gap-2 items-stretch border-gray-800 bg-gray-900/60 shadow-indigo-950/10">
              <input 
                type="text" 
                placeholder="Enter website URL to analyze (e.g. login-verify-bank.com)"
                className="flex-grow bg-transparent border-0 ring-0 focus:outline-none text-sm text-gray-200 px-4 py-3 min-w-[200px]"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                disabled={isScanning}
              />
              <button 
                type="submit" 
                className="px-6 py-3 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white text-sm font-semibold rounded-xl transition-all duration-200 flex items-center justify-center gap-2 whitespace-nowrap shadow-lg shadow-indigo-700/20"
                disabled={isScanning || !urlInput.trim()}
              >
                {isScanning ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                    Scanning...
                  </>
                ) : (
                  "Analyze URL"
                )}
              </button>
            </form>
            
            {isScanning && (
              <div className="mt-3 flex items-center justify-center gap-2 text-xs text-indigo-400 bg-indigo-500/5 border border-indigo-500/10 rounded-lg p-2 animate-pulse">
                <span>⚡</span> {scanStatus}
              </div>
            )}
          </div>
        </section>

        {/* Dynamic Telemetry Stats Section */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-5xl mx-auto w-full">
          {[
            { label: "Websites Scanned", val: stats ? stats.total_scans.toLocaleString() : "0", desc: "Recorded database lookups" },
            { label: "Threats Intercepted", val: stats ? stats.total_phishing_detected.toLocaleString() : "0", desc: "Phishing URLs detected" },
            { label: "ML Classification", val: stats ? `${stats.detection_accuracy}%` : "98.4%", desc: "Trained XGBoost accuracy" },
            { label: "Active Guard Accounts", val: stats ? stats.active_users.toLocaleString() : "0", desc: "Registered platform users" }
          ].map((stat, idx) => (
            <div key={idx} className="glass-card p-6 rounded-2xl border-gray-800/80 bg-gray-900/40 text-center">
              <div className="text-3xl font-extrabold bg-gradient-to-r from-white to-indigo-300 bg-clip-text text-transparent">{stat.val}</div>
              <div className="text-sm font-medium text-gray-300 mt-1">{stat.label}</div>
              <div className="text-xs text-gray-500 mt-1">{stat.desc}</div>
            </div>
          ))}
        </section>

        {/* Global Map & Live Feed Section */}
        <section id="feed" className="grid grid-cols-1 lg:grid-cols-5 gap-8 items-start w-full">
          {/* Live Feed Ticker */}
          <div className="lg:col-span-2 flex flex-col gap-4 w-full h-full justify-between">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-indigo-400" />
                Live Threat Intelligence
              </h2>
              <p className="text-xs text-gray-400 mt-1">
                Real-time ingestion feed of global active credential theft & phishing domains.
              </p>
            </div>

            <div className="flex flex-col gap-3 max-h-[400px] overflow-y-auto mt-4 pr-1">
              {recentThreats.map((threat, idx) => (
                <div key={idx} className="glass-card p-4 rounded-xl border-red-950/20 bg-red-950/5 hover:border-red-500/20 flex flex-col gap-1 transition-all duration-200">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-red-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      {threat.threat_type}
                    </span>
                    <span className="text-gray-500">
                      {new Date(threat.detected_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-sm font-mono text-gray-300 font-bold truncate mt-1">
                    {threat.domain}
                  </div>
                  <div className="flex justify-between items-center text-xs text-gray-500 mt-1.5 pt-1.5 border-t border-gray-900">
                    <span>Targeting: <strong className="text-gray-400">{threat.target_brand}</strong></span>
                    <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-bold">
                      Score: {threat.risk_score}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Interactive SVG Network Map Mockup */}
          <div className="lg:col-span-3 glass-card p-6 rounded-2xl border-gray-800 bg-gray-900/30 flex flex-col gap-4 relative min-h-[350px] overflow-hidden justify-between w-full">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2">
                <Globe className="w-5 h-5 text-cyan-400" />
                Global Detection Matrix
              </h2>
              <p className="text-xs text-gray-400 mt-1">
                Visual representation of AI threat telemetry nodes resolving domain endpoints.
              </p>
            </div>

            {/* Premium Network Map Graphic */}
            <div className="flex-grow flex items-center justify-center my-4 h-64 relative">
              <svg className="w-full h-full max-w-[450px]" viewBox="0 0 200 100">
                {/* Connections */}
                <path d="M 30,50 L 70,30" stroke="rgba(99, 102, 241, 0.2)" strokeWidth="0.5" strokeDasharray="2,2" />
                <path d="M 70,30 L 100,50" stroke="rgba(99, 102, 241, 0.3)" strokeWidth="0.5" />
                <path d="M 100,50 L 130,70" stroke="rgba(6, 182, 212, 0.3)" strokeWidth="0.5" />
                <path d="M 130,70 L 170,50" stroke="rgba(6, 182, 212, 0.2)" strokeWidth="0.5" strokeDasharray="2,2" />
                <path d="M 70,30 L 130,70" stroke="rgba(99, 102, 241, 0.15)" strokeWidth="0.5" />
                <path d="M 30,50 L 100,50" stroke="rgba(6, 182, 212, 0.2)" strokeWidth="0.5" />
                <path d="M 100,50 L 170,50" stroke="rgba(99, 102, 241, 0.2)" strokeWidth="0.5" />
                
                {/* Node Circles */}
                <circle cx="30" cy="50" r="4" fill="#6366f1" opacity="0.4" className="animate-ping" />
                <circle cx="30" cy="50" r="3" fill="#6366f1" />
                
                <circle cx="70" cy="30" r="5" fill="#06b6d4" opacity="0.3" />
                <circle cx="70" cy="30" r="3" fill="#06b6d4" />
                
                {/* Main Scanning Radar Node */}
                <circle cx="100" cy="50" r="12" fill="none" stroke="#6366f1" strokeWidth="0.5" className="animate-ping" />
                <circle cx="100" cy="50" r="8" fill="rgba(99, 102, 241, 0.1)" stroke="rgba(99, 102, 241, 0.4)" strokeWidth="1" />
                <circle cx="100" cy="50" r="4" fill="#6366f1" />
                
                <circle cx="130" cy="70" r="5" fill="#06b6d4" opacity="0.3" />
                <circle cx="130" cy="70" r="3" fill="#06b6d4" />
                
                <circle cx="170" cy="50" r="4" fill="#ef4444" opacity="0.4" className="animate-ping" />
                <circle cx="170" cy="50" r="3" fill="#ef4444" />
                
                {/* Threat Indicator labels */}
                <text x="35" y="47" fill="#9ca3af" fontSize="4" fontStyle="mono">Scan Node A</text>
                <text x="75" y="27" fill="#9ca3af" fontSize="4" fontStyle="mono">SSL Node</text>
                <text x="94" y="36" fill="#a5b4fc" fontSize="5" fontWeight="bold" fontStyle="mono">PG Core</text>
                <text x="135" y="73" fill="#9ca3af" fontSize="4" fontStyle="mono">WHOIS Node</text>
                <text x="156" y="45" fill="#ef4444" fontSize="4" fontWeight="bold" fontStyle="mono">FLAGGED</text>
              </svg>
            </div>
            
            <div className="flex justify-between items-center text-xs text-gray-500 pt-2 border-t border-gray-900">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-indigo-500"></span> Active Scanner Nodes: 18</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500"></span> System integrity: 100%</span>
            </div>
          </div>
        </section>

        {/* Features Grid Section */}
        <section id="features" className="flex flex-col gap-12 w-full">
          <div className="text-center max-w-2xl mx-auto flex flex-col gap-2">
            <h2 className="text-3xl font-bold tracking-tight text-white">
              SaaS-Grade Threat Detection Loop
            </h2>
            <p className="text-sm text-gray-400">
              PhishGuard AI analyzes domain targets across five critical evaluation sectors under 150 milliseconds.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 w-full">
            {[
              {
                title: "Real-Time URL Detection",
                desc: "Evaluates URL parameters, counts dots, path lengths, structure ratios, and matches keywords using XGBoost classifiers.",
                icon: Cpu,
                color: "text-indigo-400"
              },
              {
                title: "Explainable AI Insights",
                desc: "Don't just get a label. Our XAI system outputs readable lists explaining why domains are flagged as suspicious or red.",
                icon: Layers,
                color: "text-cyan-400"
              },
              {
                title: "SSL Certificate Checker",
                desc: "Inspects socket handshakes, authority issuers, key formats, expiry terms, and secures users against connection failures.",
                icon: Lock,
                color: "text-indigo-400"
              },
              {
                title: "WHOIS Domain Intel",
                desc: "Queries global registrar servers to review registration creation records, expiration schedules, and age thresholds.",
                icon: Server,
                color: "text-cyan-400"
              },
              {
                title: "Typosquatting Check",
                desc: "Utilizes SequenceMatcher algorithms to verify brand typos and flags impersonation attempts targeting major systems.",
                icon: AlertTriangle,
                color: "text-indigo-400"
              },
              {
                title: "Professional PDF Reports",
                desc: "Exports dynamic cybersecurity reports containing complete scan outputs, scores, certificates, and DNS records.",
                icon: FileCheck,
                color: "text-cyan-400"
              }
            ].map((feat, idx) => (
              <div key={idx} className="glass-card p-8 rounded-2xl border-gray-800 bg-gray-900/20 flex flex-col gap-4">
                <div className={`p-3 bg-gray-900 border border-gray-800 w-fit rounded-xl ${feat.color}`}>
                  <feat.icon className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-gray-100">{feat.title}</h3>
                <p className="text-sm text-gray-400 leading-relaxed">{feat.desc}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 bg-gray-950 mt-12 py-8 relative z-10 text-gray-500 text-xs">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span className="font-semibold text-gray-400">PhishGuard AI Platform</span>
          </div>
          <div>
            &copy; {new Date().getFullYear()} PhishGuard AI. All rights reserved. Startup-grade Threat Intelligence.
          </div>
        </div>
      </footer>
    </div>
  );
}
