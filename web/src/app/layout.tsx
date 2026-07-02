import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { LayoutWrapper } from "./layout-wrapper";

export const metadata: Metadata = {
  title: "AppSecWatch — AppSec Orchestrator",
  description: "Point-in-time external AppSec audits: recon, TLS, CVEs, supply-chain, AI.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${GeistSans.variable} ${GeistMono.variable} font-sans`}
        suppressHydrationWarning
      >
        {/* Anti-FOUC: apply the stored theme before paint (light is the default,
            so this only matters for returning dark-mode users). Static-export safe. */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('theme')||'light';var d=t==='dark'||(t==='system'&&window.matchMedia('(prefers-color-scheme: dark)').matches);var c=d?'dark':'light';var e=document.documentElement;e.classList.remove('dark','light');e.classList.add(c);e.style.colorScheme=c;}catch(e){}})();`,
          }}
        />
        <ThemeProvider attribute="class" defaultTheme="light" enableSystem>
          <TooltipProvider delayDuration={200}>
            <LayoutWrapper>{children}</LayoutWrapper>
            <Toaster />
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
