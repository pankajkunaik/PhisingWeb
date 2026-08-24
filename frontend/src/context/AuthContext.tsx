"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { authApi, getToken, setToken, clearToken } from "@/lib/api";

interface UserProfile {
  id?: number;
  email: string;
  created_at?: string;
}

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isLoggedIn: boolean;
  isLoading: boolean;
  showAuthModal: boolean;
  authModalMode: "login" | "signup";
  openAuthModal: (mode?: "login" | "signup") => void;
  closeAuthModal: () => void;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setTokenState] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [showAuthModal, setShowAuthModal] = useState<boolean>(false);
  const [authModalMode, setAuthModalMode] = useState<"login" | "signup">("login");

  // Load user profile if token exists on initial mount
  useEffect(() => {
    async function loadUser() {
      const storedToken = getToken();
      if (storedToken) {
        setTokenState(storedToken);
        try {
          const profile = await authApi.me();
          setUser(profile as UserProfile);
        } catch (err) {
          // Token invalid or expired
          clearToken();
          setTokenState(null);
          setUser(null);
        }
      }
      setIsLoading(false);
    }
    loadUser();
  }, []);

  const openAuthModal = (mode: "login" | "signup" = "login") => {
    setAuthModalMode(mode);
    setShowAuthModal(true);
  };

  const closeAuthModal = () => {
    setShowAuthModal(false);
  };

  const login = async (email: string, password: string) => {
    const data = await authApi.login(email, password);
    setTokenState(data.access_token);
    try {
      const profile = await authApi.me();
      setUser(profile as UserProfile);
    } catch {
      setUser({ email: data.email });
    }
    closeAuthModal();
  };

  const register = async (email: string, password: string) => {
    await authApi.register(email, password);
    // Auto login after successful registration
    await login(email, password);
  };

  const logout = () => {
    authApi.logout();
    setTokenState(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoggedIn: !!user,
        isLoading,
        showAuthModal,
        authModalMode,
        openAuthModal,
        closeAuthModal,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
