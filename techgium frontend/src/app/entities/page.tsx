'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity } from '@/types';
import Link from 'next/link';
import { ExternalLink, Search, Filter, Wifi, Server, ChevronDown, Check, ShieldOff } from 'lucide-react';
import { useState, useMemo, useRef, useEffect } from 'react';

const ONLINE_THRESHOLD_MS = 5 * 60 * 1000;

const DEPARTMENTS = [
  'Unknown',
  'Engineering',
  'Human Resources',
  'Finance',
  'Marketing',
  'Sales',
  'Operations',
  'IT & Infrastructure',
  'Security',
  'Legal & Compliance',
  'Product Management',
  'Design & UX',
  'Customer Success',
  'Data & Analytics',
  'DevOps & Platform',
  'Research & Development',
  'Procurement',
  'Administration',
  'Executive',
];

const RISK_FILTERS = [
  { value: 'all', label: 'All Risk Levels' },
  { value: 'critical', label: 'Critical (<30)' },
  { value: 'alert', label: 'Alert (30-49)' },
  { value: 'monitor', label: 'Monitor (50-79)' },
  { value: 'trusted', label: 'Trusted (≥80)' },
];

function isOnline(lastSeen?: string): boolean {
  if (!lastSeen) return false;
  return Date.now() - new Date(lastSeen).getTime() < ONLINE_THRESHOLD_MS;
}

function OnlineDot({ lastSeen }: { lastSeen?: string }) {
  const online = isOnline(lastSeen);
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full shrink-0 ${online ? 'bg-emerald-500' : 'bg-gray-600'}`}
      title={online ? 'Online' : `Last seen ${lastSeen ? new Date(lastSeen).toLocaleString() : 'unknown'}`}
    />
  );
}

function DepartmentPicker({ entityId, current, onSave }: {
  entityId: string;
  current: string;
  onSave: (dept: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const select = async (dept: string) => {
    setOpen(false);
    if (dept === current) return;
    setSaving(true);
    try {
      await fetch(`/api/v1/devices/${entityId}/department`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ department: dept }),
      });
      onSave(dept);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        disabled={saving}
        className="flex items-center gap-1.5 px-2 py-1 rounded border border-white/10 bg-white/5 hover:border-primary/40 hover:bg-primary/10 transition-colors text-xs text-gray-300 hover:text-white min-w-[110px]"
      >
        <span className="flex-1 text-left truncate">{saving ? 'Saving…' : (current || 'Unknown')}</span>
        <ChevronDown className="w-3 h-3 shrink-0 text-gray-500" />
      </button>
      {open && (
        <div className="absolute z-50 top-full mt-1 left-0 w-52 bg-[#1a1a2e] border border-border rounded-lg shadow-xl py-1 max-h-64 overflow-y-auto">
          {DEPARTMENTS.map(dept => (
            <button
              key={dept}
              onClick={() => select(dept)}
              className="w-full flex items-center justify-between px-3 py-1.5 text-xs hover:bg-white/5 transition-colors text-left"
            >
              <span className={dept === current ? 'text-primary font-semibold' : 'text-gray-300'}>{dept}</span>
              {dept === current && <Check className="w-3 h-3 text-primary" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function EntitiesPage() {
  const { data: rawEntities, isLoading } = usePolling<Entity[]>('/entities/');
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  // Local department overrides so UI updates immediately after save
  const [deptOverrides, setDeptOverrides] = useState<Record<string, string>>({});

  const entities = useMemo(() => {
    if (!rawEntities) return [];
    return rawEntities.map(e => ({
      ...e,
      department: deptOverrides[e.entity_id] ?? e.department ?? 'Unknown',
    }));
  }, [rawEntities, deptOverrides]);

  const applyFilters = (list: Entity[]) => {
    return list.filter(e => {
      const matchesSearch = e.entity_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.metadata?.ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.metadata?.hostname?.toLowerCase().includes(searchTerm.toLowerCase());
      if (e.discovering) return matchesSearch;
      const s = e.trust_score ?? 0;
      let matchesRisk = true;
      if (riskFilter === 'critical') matchesRisk = s < 30;
      else if (riskFilter === 'alert') matchesRisk = s >= 30 && s < 50;
      else if (riskFilter === 'monitor') matchesRisk = s >= 50 && s < 80;
      else if (riskFilter === 'trusted') matchesRisk = s >= 80;
      return matchesSearch && matchesRisk;
    }).sort((a, b) => {
      if (a.discovering && !b.discovering) return -1;
      if (!a.discovering && b.discovering) return 1;
      return (a.trust_score ?? 100) - (b.trust_score ?? 100);
    });
  };

  const networkEntities = useMemo(() =>
    applyFilters(entities.filter(e => (e.device_source ?? 'network') === 'network')),
    [entities, searchTerm, riskFilter]
  );
  const hypervisorEntities = useMemo(() =>
    applyFilters(entities.filter(e => e.device_source === 'hypervisor')),
    [entities, searchTerm, riskFilter]
  );

  if (isLoading && !rawEntities) {
    return <div className="flex items-center justify-center h-full text-gray-400">Loading entities...</div>;
  }

  const tableHeaders = (isNetwork: boolean) => (
    <tr>
      <th>Entity ID</th>
      <th>TrustScore</th>
      <th>Confidence</th>
      <th>Decision State</th>
      {isNetwork && <th>Department</th>}
      <th>Last Updated</th>
      <th>Active Response</th>
      <th className="text-right">Actions</th>
    </tr>
  );

  const tableRow = (entity: Entity, isNetwork: boolean) => {
    const isDiscovering = entity.discovering || entity.decision === 'discovering';
    const isBlocked = entity.is_blocked === true;
    const score = entity.trust_score;
    const rowClass = isBlocked
      ? 'bg-red-500/5 border-l-2 border-red-500/40'
      : isDiscovering
        ? 'bg-blue-500/5'
        : '';
    return (
      <tr key={entity.entity_id} className={`hover:bg-white/[0.02] transition-colors ${rowClass}`}>
        <td className="w-1/4">
          <div className="flex flex-col gap-0.5">
            <span className="font-mono text-sm text-white flex items-center gap-2">
              <OnlineDot lastSeen={entity.last_seen} />
              {entity.entity_id}
              {entity.metadata?.owner === 'presenter' && (
                <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[10px] font-bold uppercase border border-primary/30">You</span>
              )}
              {isBlocked && (
                <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold uppercase border border-red-500/30 flex items-center gap-1">
                  <ShieldOff className="w-2.5 h-2.5" /> Blocked
                </span>
              )}
              {!isBlocked && isDiscovering && (
                <span className="px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 text-[10px] font-bold uppercase border border-blue-500/30 animate-pulse">New</span>
              )}
            </span>
            <span className="text-[10px] text-gray-600 ml-4">
              {isBlocked
                ? <span className="text-red-400/70">{entity.block_reason || 'Blocked by SOC'}</span>
                : isOnline(entity.last_seen)
                  ? 'Online'
                  : entity.last_seen
                    ? `Offline · ${new Date(entity.last_seen).toLocaleTimeString()}`
                    : 'No data'}
            </span>
            {entity.metadata?.ip && <span className="text-xs text-gray-500 font-mono ml-4">{entity.metadata.ip}</span>}
          </div>
        </td>
        <td>
          {isDiscovering ? (
            <div className="flex items-center gap-2">
              <div className="flex-1 h-1.5 w-24 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-blue-500/40 animate-pulse rounded-full" style={{ width: '100%' }} />
              </div>
              <span className="text-xs text-blue-400 font-medium">—</span>
            </div>
          ) : (
            <div className="flex items-center gap-3">
              <div className={`flex-1 h-1.5 w-24 rounded-full overflow-hidden ${isBlocked ? 'bg-red-500/10' : 'bg-white/5'}`}>
                <div className={`h-full transition-all duration-300 ${isBlocked ? 'bg-red-500/50' : getScoreColor(score)}`} style={{ width: `${score ?? 0}%` }} />
              </div>
              <span className={`text-sm font-bold w-10 ${isBlocked ? 'text-red-400' : (score ?? 0) >= 80 ? 'text-emerald-400' : (score ?? 0) >= 50 ? 'text-yellow-400' : (score ?? 0) >= 30 ? 'text-orange-400' : 'text-red-400'}`}>
                {score?.toFixed(0) ?? '—'}
              </span>
            </div>
          )}
        </td>
        <td>
          {isDiscovering
            ? <span className="text-xs text-blue-400 animate-pulse">analyzing…</span>
            : <span className={`text-sm ${isBlocked ? 'text-gray-600' : 'text-gray-300'}`}>{entity.confidence}%</span>}
        </td>
        <td>
          {isBlocked
            ? <span className="px-2 py-1 rounded text-[11px] font-bold uppercase border bg-red-500/10 text-red-400 border-red-500/20 flex items-center gap-1 w-fit"><ShieldOff className="w-3 h-3" />Blocked</span>
            : isDiscovering
              ? <span className="px-2 py-1 rounded text-[11px] font-bold uppercase border bg-blue-500/10 text-blue-400 border-blue-500/20 animate-pulse">Analyzing</span>
              : <DecisionBadge decision={entity.decision} score={score ?? 0} />}
        </td>
        {isNetwork && (
          <td>
            {isDiscovering ? (
              <span className="text-xs text-gray-600">—</span>
            ) : (
              <DepartmentPicker
                entityId={entity.entity_id}
                current={entity.department ?? 'Unknown'}
                onSave={(dept) => setDeptOverrides(prev => ({ ...prev, [entity.entity_id]: dept }))}
              />
            )}
          </td>
        )}
        <td>
          <span className="text-xs text-gray-500" suppressHydrationWarning>
            {new Date(entity.last_updated).toLocaleTimeString()}
          </span>
        </td>
        <td>
          {isDiscovering ? (
            <span className="text-xs text-blue-400 animate-pulse">baseline collection…</span>
          ) : entity.active_actions.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {entity.active_actions.map(action => (
                <span key={action} className="px-1.5 py-0.5 bg-primary/10 text-primary text-[10px] rounded border border-primary/20">{action}</span>
              ))}
            </div>
          ) : (
            <span className="text-xs text-gray-600">—</span>
          )}
        </td>
        <td className="text-right">
          <Link href={`/entities/${entity.entity_id}`} className="inline-flex items-center gap-1.5 text-primary hover:text-primary/80 text-sm font-medium transition-colors">
            Details <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        </td>
      </tr>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Entity Monitoring</h2>
          <p className="text-gray-400">Manage and inspect all monitored assets</p>
        </div>
        <div className="text-sm text-gray-500">
          {networkEntities.length} network · {hypervisorEntities.length} hypervisor
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-4 items-end">
        <div className="flex-1 min-w-[200px] space-y-1.5">
          <label className="text-xs text-gray-500 font-medium">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search entity ID, IP, hostname..."
              className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
        <div className="w-48 space-y-1.5">
          <label className="text-xs text-gray-500 font-medium">Risk Level</label>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <select
              className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full appearance-none"
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
            >
              {RISK_FILTERS.map(f => (
                <option key={f.value} value={f.value}>{f.label}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Network Devices Section */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Wifi className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Network Devices</h3>
          <span className="text-xs text-gray-500 bg-white/5 px-2 py-0.5 rounded-full">{networkEntities.length}</span>
        </div>
        <div className="soc-card p-0 overflow-hidden">
          <table className="soc-table">
            <thead>{tableHeaders(true)}</thead>
            <tbody>
              {networkEntities.map(e => tableRow(e, true))}
              {networkEntities.length === 0 && (
                <tr><td colSpan={8} className="text-center py-8 text-gray-500 italic">No network devices matching filters</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Hypervisor Devices Section */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-purple-400" />
          <h3 className="text-sm font-semibold text-white uppercase tracking-wider">Hypervisor Devices</h3>
          <span className="text-xs text-gray-500 bg-white/5 px-2 py-0.5 rounded-full">{hypervisorEntities.length}</span>
        </div>
        <div className="soc-card p-0 overflow-hidden">
          <table className="soc-table">
            <thead>{tableHeaders(false)}</thead>
            <tbody>
              {hypervisorEntities.map(e => tableRow(e, false))}
              {hypervisorEntities.length === 0 && (
                <tr><td colSpan={7} className="text-center py-8 text-gray-500 italic">No hypervisor devices detected</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function getScoreColor(score: number | null) {
  if (score === null) return 'bg-blue-500/40';
  if (score >= 80) return 'bg-success';
  if (score >= 50) return 'bg-warning';
  if (score >= 30) return 'bg-alert';
  return 'bg-critical';
}

function DecisionBadge({ decision, score }: { decision: string, score: number | null }) {
  const s = score ?? 0;
  let colors = "bg-gray-500/10 text-gray-500 border-gray-500/20";
  if (s >= 80) colors = "bg-success/10 text-success border-success/20";
  else if (s >= 50) colors = "bg-warning/10 text-warning border-warning/20";
  else if (s >= 30) colors = "bg-alert/10 text-alert border-alert/20";
  else colors = "bg-critical/10 text-critical border-critical/20";
  return (
    <span className={`px-2 py-1 rounded text-[11px] font-bold uppercase border ${colors}`}>
      {decision}
    </span>
  );
}
