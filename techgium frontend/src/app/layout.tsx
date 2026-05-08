import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";
import ClientProviders from "@/components/ClientProviders";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "GUARDIENT | Agentless EDR Dashboard",
  description: "Real-time SOC Monitoring for Guardient - Agentless Endpoint Protection",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-background text-foreground flex h-screen overflow-hidden`}>
        <ClientProviders>
          <Sidebar />
          <div className="flex-1 flex flex-col min-w-0">
            <TopBar />
            <main className="flex-1 overflow-y-auto p-6">
              {children}
            </main>
            <footer className="border-t border-border bg-card/50 px-6 py-3 shrink-0">
              <p className="text-xs text-gray-500 text-center">
                Guardient provides agentless endpoint protection by inferring risk from network, identity, and cloud signals — delivering explainable trust scores and safe, SOC-controlled response.
              </p>
            </footer>
          </div>
        </ClientProviders>
      </body>
    </html>
  );
}
