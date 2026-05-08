'use client';

import { usePolling } from '@/hooks/usePolling';
import { Wifi, WifiOff, Bell, User } from 'lucide-react';

export default function TopBar() {
  const { status } = usePolling('/entities/', 10000); // Check status every 10s

  const isOnline = status === 'online';

  return (
    <header className="h-16 border-b border-border bg-card/50 backdrop-blur-md flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center gap-4">
        <h1 className="text-lg font-semibold text-white">System Monitor</h1>
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${isOnline
            ? "bg-success/10 text-success border-success/20"
            : "bg-critical/10 text-critical border-critical/20"
          }`}>
          {isOnline ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
          {isOnline ? "Backend Live" : "Backend Offline"}
        </div>
      </div>

      <div className="flex items-center gap-4">
        <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-2 right-2 w-2 h-2 bg-primary rounded-full border border-card"></span>
        </button>
        <div className="flex items-center gap-3 pl-4 border-l border-border">
          <div className="text-right">
            <div className="text-sm font-medium text-white">SOC Analyst</div>
            <div className="text-xs text-gray-500">Admin Role</div>
          </div>
          <div className="w-9 h-9 rounded-full bg-primary/20 flex items-center justify-center border border-primary/30">
            <User className="w-5 h-5 text-primary" />
          </div>
        </div>
      </div>
    </header>
  );
}
