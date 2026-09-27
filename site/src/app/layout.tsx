import type { Metadata, Viewport } from "next";
import { JetBrains_Mono, Plus_Jakarta_Sans } from "next/font/google";
import "./globals.css";

const jakarta = Plus_Jakarta_Sans({ subsets: ["latin"], variable: "--font-jakarta", display: "swap" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });

export const metadata: Metadata = {
  title: "LATTICE",
  description:
    "Find every piece of cryptography, prove what really runs, and fix what a quantum computer breaks first. Built for SIH26164 by team DoodleByte.",
};

export const viewport: Viewport = { themeColor: "#F2F2EF" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${jakarta.variable} ${mono.variable}`}>
      <head>
        {/* Satoshi, the primary face, from Fontshare (Indian Type Foundry) */}
        <link rel="preconnect" href="https://api.fontshare.com" />
        <link rel="stylesheet" href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700,900&display=swap" />
      </head>
      <body>{children}</body>
    </html>
  );
}
