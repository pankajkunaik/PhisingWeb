"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/AuthContext";

export default function SignupPage() {
  const { openAuthModal, isLoggedIn } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (isLoggedIn) {
      router.push("/dashboard");
    } else {
      openAuthModal("signup");
    }
  }, [isLoggedIn, openAuthModal, router]);

  return (
    <div className="min-h-screen bg-gray-950 flex flex-col items-center justify-center gap-3">
      <div className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin"></div>
      <span className="text-xs text-gray-400 font-mono">Redirecting to Sign Up...</span>
    </div>
  );
}
