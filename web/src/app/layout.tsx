import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import { LayoutWrapper } from "./layout-wrapper";

export const metadata: Metadata = {
  title: "WatchTower — AppSec Orchestrator",
  description: "Point-in-time external AppSec audits: recon, TLS, CVEs, supply-chain, AI.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          <TooltipProvider delayDuration={200}>
            <LayoutWrapper>{children}</LayoutWrapper>
            <Toaster />
          </TooltipProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
