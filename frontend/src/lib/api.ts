/**
 * PhishGuard AI — Centralized API Client
 * All backend calls go through this module.
 * Base URL is driven by NEXT_PUBLIC_API_URL environment variable.
 */

function getBaseUrl(): string {
  if (typeof window !== "undefined") {
    // In production on Vercel or any live domain, ALWAYS use relative URLs ("/api/...")
    // Next.js rewrites in next.config.ts automatically proxy all /api/* calls to your Railway backend with zero CORS issues.
    if (window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
      return "";
    }
    // In local development, call the local backend server on 127.0.0.1:8000
    const hostname = window.location.hostname || "127.0.0.1";
    const host = hostname === "localhost" ? "127.0.0.1" : hostname;
    return `http://${host}:8000`;
  }
  // Server-side default
  if (process.env.NEXT_PUBLIC_API_URL && !process.env.NEXT_PUBLIC_API_URL.includes("127.0.0.1") && !process.env.NEXT_PUBLIC_API_URL.includes("localhost")) {
    return process.env.NEXT_PUBLIC_API_URL.replace(/\/+$/, "");
  }
  return "";
}

// ── Token helpers ──────────────────────────────────────────────────────────────
export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("phishguard_token");
}

export function setToken(token: string): void {
  localStorage.setItem("phishguard_token", token);
}

export function clearToken(): void {
  localStorage.removeItem("phishguard_token");
}

// ── Core fetch wrapper ─────────────────────────────────────────────────────────
async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  auth = false
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  const baseUrl = getBaseUrl();
  const res = await fetch(`${baseUrl}${path}`, { ...options, headers });

  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (Array.isArray(body.detail)) {
        detail = body.detail.map((err: any) => err.msg || JSON.stringify(err)).join(". ");
      } else if (typeof body.detail === "object" && body.detail !== null) {
        detail = JSON.stringify(body.detail);
      } else if (body.detail) {
        detail = String(body.detail);
      }
    } catch {}
    throw new Error(detail);
  }

  return res.json() as Promise<T>;
}

// ── Types ──────────────────────────────────────────────────────────────────────
export interface ScanResult {
  scan_id?: number;
  url: string;
  domain: string;
  risk_score: number;
  prediction: "Safe" | "Suspicious" | "Phishing";
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
  threat_feeds: {
    flagged: boolean;
    matched_feeds: string[];
  };
}

export interface ThreatFeedItem {
  domain: string;
  target_brand: string;
  detected_at: string;
  risk_score: number;
  threat_type: string;
}

export interface PlatformStats {
  total_scans: number;
  total_phishing_detected: number;
  total_safe: number;
  total_suspicious: number;
  detection_accuracy: number;
  active_users: number;
}

export interface HistoryItem {
  id: number;
  url: string;
  risk_score: number;
  prediction: string;
  created_at: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

// ── Auth API ───────────────────────────────────────────────────────────────────
export const authApi = {
  async register(email: string, password: string) {
    return apiFetch("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
  },

  async login(email: string, password: string): Promise<{ access_token: string; email: string }> {
    const data = await apiFetch<{ access_token: string; email: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setToken(data.access_token);
    return data;
  },

  async me() {
    return apiFetch("/api/auth/me", {}, true);
  },

  logout() {
    clearToken();
  },
};

// ── Scan API ───────────────────────────────────────────────────────────────────
export const scanApi = {
  async scanUrl(url: string, htmlContent?: string): Promise<ScanResult> {
    return apiFetch<ScanResult>(
      "/api/scan",
      { method: "POST", body: JSON.stringify({ url, html_content: htmlContent }) },
      true
    );
  },

  async getHistory(limit = 50, offset = 0): Promise<HistoryItem[]> {
    return apiFetch<HistoryItem[]>(`/api/history?limit=${limit}&offset=${offset}`, {}, true);
  },

  getReportUrl(scanId: number): string {
    return `${getBaseUrl()}/api/report/${scanId}`;
  },

  async whoisLookup(domain: string) {
    return apiFetch(`/api/whois?domain=${encodeURIComponent(domain)}`);
  },

  async sslCheck(domain: string) {
    return apiFetch(`/api/ssl?domain=${encodeURIComponent(domain)}`);
  },

  async dnsLookup(domain: string) {
    return apiFetch(`/api/dns?domain=${encodeURIComponent(domain)}`);
  },
};

// ── Threat Intel API ───────────────────────────────────────────────────────────
export const threatApi = {
  async getFeed(): Promise<ThreatFeedItem[]> {
    return apiFetch<ThreatFeedItem[]>("/api/threats/feed");
  },

  async getMap() {
    return apiFetch("/api/threats/map");
  },

  async getStats(): Promise<PlatformStats> {
    return apiFetch<PlatformStats>("/api/stats");
  },
};

export interface UserStats {
  total_scans: number;
  safe_scans: number;
  suspicious_scans: number;
  phishing_scans: number;
  threat_rate: number;
  security_grade: string;
  watchlist_count: number;
  member_since: string;
}

export interface WatchlistItem {
  id: number;
  domain: string;
  label?: string;
  status: "Active" | "Warning" | "Critical";
  ssl_valid: number;
  ssl_days_left: number;
  risk_score: number;
  last_checked: string;
  created_at: string;
}

export interface InspectResult {
  analysis: string;
  risk_level: string;
  indicators: string[];
  recommendation: string;
}

// ── User API ───────────────────────────────────────────────────────────────────
export const userApi = {
  async getStats(): Promise<UserStats> {
    return apiFetch<UserStats>("/api/user/stats", {}, true);
  },

  async getWatchlist(): Promise<WatchlistItem[]> {
    return apiFetch<WatchlistItem[]>("/api/user/watchlist", {}, true);
  },

  async addToWatchlist(domain: string, label?: string): Promise<WatchlistItem> {
    return apiFetch<WatchlistItem>(
      "/api/user/watchlist",
      { method: "POST", body: JSON.stringify({ domain, label }) },
      true
    );
  },

  async deleteFromWatchlist(id: number): Promise<{ message: string; id: number }> {
    return apiFetch<{ message: string; id: number }>(
      `/api/user/watchlist/${id}`,
      { method: "DELETE" },
      true
    );
  },

  async deleteHistory(scanId: number): Promise<{ message: string; scan_id: number }> {
    return apiFetch<{ message: string; scan_id: number }>(
      `/api/user/history/${scanId}`,
      { method: "DELETE" },
      true
    );
  },
};

// ── AI Chat API (Grok & Heuristic) ─────────────────────────────────────────────
export const chatApi = {
  async sendMessage(
    messages: ChatMessage[],
    urlContext?: string
  ): Promise<ChatMessage> {
    return apiFetch<ChatMessage>("/api/ai/chat", {
      method: "POST",
      body: JSON.stringify({ messages, url_context: urlContext }),
    });
  },

  async inspectContent(content: string, contentType = "email_or_text"): Promise<InspectResult> {
    return apiFetch<InspectResult>(
      "/api/ai/inspect-content",
      { method: "POST", body: JSON.stringify({ content, content_type: contentType }) },
      true
    );
  },
};

// ── Health ─────────────────────────────────────────────────────────────────────
export async function checkHealth(): Promise<boolean> {
  try {
    await apiFetch("/api/health");
    return true;
  } catch {
    return false;
  }
}
