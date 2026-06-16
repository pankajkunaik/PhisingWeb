import type { Metadata } from "next";
import { Outfit } from "next/font/google";
import "./globals.css";

const outfit = Outfit({
  variable: "--font-sans",
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700", "800"],
});

export const metadata: Metadata = {
  title: "PhishGuard AI | AI-Powered Website Threat Intelligence",
  description: "Instantly detect phishing attacks, impersonation scams, typosquatting domains and malicious SSL setups using machine learning and explainable AI.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${outfit.variable} h-full scroll-smooth`}>
      <body className="min-h-full bg-gray-950 text-gray-50 antialiased flex flex-col">
        {children}
      </body>
    </html>
  );
}
