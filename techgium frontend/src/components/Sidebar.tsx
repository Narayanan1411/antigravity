'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  Shield,
  LayoutDashboard,
  Server,
  AlertTriangle,
  Search,
  ClipboardList,
  FileText,
  Activity,
  BookOpen,
  Brain,
  Target
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const navItems = [
  { name: 'Overview', href: '/', icon: LayoutDashboard },
  { name: 'Entities', href: '/entities', icon: Server },
  { name: 'Incidents', href: '/incidents', icon: AlertTriangle },
  { name: 'Investigations', href: '/investigations', icon: Search },
  { name: 'Responses', href: '/responses', icon: Activity },
  { name: 'Audit & Compliance', href: '/audit', icon: ClipboardList },
  { name: 'Adaptive Trust', href: '/adaptive-trust', icon: Brain },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Simulation Engine', href: '/simulation', icon: Target },
  { name: 'How It Works', href: '/how-it-works', icon: BookOpen },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="group w-16 hover:w-64 bg-card border-r border-border flex flex-col transition-all duration-300 ease-in-out shrink-0 z-50 overflow-hidden relative">
      <div className="p-4 flex items-center gap-3">
        <Shield className="text-primary w-8 h-8 shrink-0" />
        <span className="text-xl font-bold tracking-tight text-white whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300">
          GUARDIENT
        </span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname === item.href ||
            (item.href !== '/' && pathname.startsWith(item.href));
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-2 py-2.5 rounded-md transition-colors w-full group/item",
                isActive
                  ? "bg-primary/10 text-primary border border-primary/20"
                  : "text-gray-400 hover:text-white hover:bg-white/5"
              )}
            >
              <item.icon className="w-5 h-5 shrink-0" />
              <span className="font-medium whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                {item.name}
              </span>
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-border opacity-0 group-hover:opacity-100 transition-opacity duration-300 whitespace-nowrap">
        <p className="text-[10px] text-gray-500 leading-relaxed whitespace-break-spaces whitespace-normal w-56">
          Guardient infers risk from network, identity, and cloud signals natively.
        </p>
      </div>
    </aside>
  );
}
