"use client";

import React, { useState } from "react";
import { Shield, X, Mail, Lock, UserPlus, LogIn, AlertCircle, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

export function AuthModal() {
  const { showAuthModal, closeAuthModal, authModalMode, login, register } = useAuth();
  const [mode, setMode] = useState<"login" | "signup">(authModalMode || "login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  // Sync internal mode if prop mode changes when modal opens
  React.useEffect(() => {
    setMode(authModalMode);
    setErrorMsg("");
    setSuccessMsg("");
  }, [authModalMode, showAuthModal]);

  if (!showAuthModal) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    setSuccessMsg("");

    if (!email.trim() || !password) {
      setErrorMsg("Please fill in all required fields.");
      return;
    }

    if (!email.includes("@") || !email.includes(".")) {
      setErrorMsg("Please enter a valid email address.");
      return;
    }

    if (mode === "signup" && password !== confirmPassword) {
      setErrorMsg("Passwords do not match.");
      return;
    }

    if (mode === "signup" && password.length < 8) {
      setErrorMsg("Password must be at least 8 characters long.");
      return;
    }

    setIsLoading(true);

    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password);
      }
    } catch (err: any) {
      setErrorMsg(err.message || `Failed to ${mode === "login" ? "sign in" : "create account"}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-950/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
      <div className="w-full max-w-md glass-card p-8 rounded-2xl border-gray-800 bg-gray-900 shadow-2xl shadow-black/90 flex flex-col gap-6 relative overflow-hidden">
        {/* Decorative Top Gradient */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-indigo-500 via-cyan-400 to-indigo-600"></div>

        {/* Modal Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-600/10 border border-indigo-500/30 rounded-lg text-indigo-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">
                PhishGuard <span className="text-indigo-400">Account</span>
              </h2>
              <p className="text-xs text-gray-400">
                {mode === "login" ? "Sign in to save and review your threat scans" : "Create a developer profile to log scan telemetry"}
              </p>
            </div>
          </div>

          <button
            onClick={closeAuthModal}
            className="p-1.5 rounded-lg text-gray-500 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Mode Switcher Tabs */}
        <div className="grid grid-cols-2 p-1 bg-gray-950/80 rounded-xl border border-gray-800 text-xs font-semibold">
          <button
            type="button"
            onClick={() => { setMode("login"); setErrorMsg(""); setSuccessMsg(""); }}
            className={`py-2 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
              mode === "login"
                ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <LogIn className="w-3.5 h-3.5" /> Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode("signup"); setErrorMsg(""); setSuccessMsg(""); }}
            className={`py-2 rounded-lg transition-all flex items-center justify-center gap-1.5 ${
              mode === "signup"
                ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/20"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <UserPlus className="w-3.5 h-3.5" /> Sign Up
          </button>
        </div>

        {/* Alerts */}
        {errorMsg && (
          <div className="p-3 rounded-xl bg-red-950/30 border border-red-500/30 text-red-300 text-xs flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="p-3 rounded-xl bg-green-950/30 border border-green-500/30 text-green-300 text-xs flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Auth Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 text-xs">
          <div className="flex flex-col gap-1.5">
            <label className="text-gray-300 font-medium">Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-gray-500 absolute left-3 top-3" />
              <input
                type="email"
                required
                placeholder="developer@company.com"
                className="w-full bg-gray-950 border border-gray-800 rounded-xl pl-9 pr-3 py-2.5 text-gray-200 focus:outline-none focus:border-indigo-500 transition-colors"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-gray-300 font-medium">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-gray-500 absolute left-3 top-3" />
              <input
                type="password"
                required
                placeholder="••••••••"
                className="w-full bg-gray-950 border border-gray-800 rounded-xl pl-9 pr-3 py-2.5 text-gray-200 focus:outline-none focus:border-indigo-500 transition-colors"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          {mode === "signup" && (
            <div className="flex flex-col gap-1.5">
              <label className="text-gray-300 font-medium">Confirm Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-gray-500 absolute left-3 top-3" />
                <input
                  type="password"
                  required
                  placeholder="••••••••"
                  className="w-full bg-gray-950 border border-gray-800 rounded-xl pl-9 pr-3 py-2.5 text-gray-200 focus:outline-none focus:border-indigo-500 transition-colors"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="mt-2 py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-semibold shadow-lg shadow-indigo-600/20 transition-all flex items-center justify-center gap-2"
          >
            {isLoading ? (
              <>
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                {mode === "login" ? "Authenticating..." : "Creating Account..."}
              </>
            ) : mode === "login" ? (
              "Sign In to PhishGuard"
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        {/* Footer info */}
        <div className="text-[11px] text-gray-500 text-center border-t border-gray-850 pt-3">
          {mode === "login" ? (
            <span>
              Don&apos;t have an account?{" "}
              <button
                type="button"
                onClick={() => { setMode("signup"); setErrorMsg(""); }}
                className="text-indigo-400 hover:underline font-semibold"
              >
                Sign Up for free
              </button>
            </span>
          ) : (
            <span>
              Already have an account?{" "}
              <button
                type="button"
                onClick={() => { setMode("login"); setErrorMsg(""); }}
                className="text-indigo-400 hover:underline font-semibold"
              >
                Sign In
              </button>
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
