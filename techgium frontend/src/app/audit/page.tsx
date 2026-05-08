'use client';

import { usePolling } from '@/hooks/usePolling';
import { AuditLog } from '@/types';
import { Filter, Search, Download, FlaskConical } from 'lucide-react';
import { useState } from 'react';

export default function AuditPage() {
  const { data: logs, isLoading } = usePolling<AuditLog[]>('/audit/');
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [simulatedFilter, setSimulatedFilter] = useState<'all' | 'simulated' | 'real'>('all');

  const filteredLogs = logs?.filter(log => {
    const matchesSearch = log.entity_id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = typeFilter === 'all' || log.action_type === typeFilter;
    const matchesSimulated = simulatedFilter === 'all' ||
      (simulatedFilter === 'simulated' && log.simulated) ||
      (simulatedFilter === 'real' && !log.simulated);
    return matchesSearch && matchesType && matchesSimulated;
  }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const actionTypes = Array.from(new Set(logs?.map(l => l.action_type) || []));

  const handleExport = () => {
    if (!filteredLogs || filteredLogs.length === 0) {
      alert('No logs available to export');
      return;
    }

    const headers = ['Timestamp', 'Entity ID', 'Action Type', 'Status', 'Mode', 'Reason', 'Approved By'];
    const csvContent = [
      headers.join(','),
      ...filteredLogs.map(log => [
        new Date(log.timestamp).toISOString(),
        log.entity_id,
        log.action_type,
        log.status,
        log.simulated ? 'SIMULATED' : 'REAL',
        `"${log.reason?.replace(/"/g, '""') || ''}"`, // Escape quotes in CSV
        log.approved_by || 'SYSTEM'
      ].join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    if (link.download !== undefined) {
      const url = URL.createObjectURL(blob);
      link.setAttribute('href', url);
      link.setAttribute('download', `guardient_audit_logs_${new Date().toISOString().split('T')[0]}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  if (isLoading && !logs) {
    return <div className="flex items-center justify-center h-full text-gray-400">Loading audit records...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Audit & Compliance</h2>
          <p className="text-gray-400">Immutable record of system and SOC actions</p>
        </div>
        <button
          onClick={handleExport}
          className="flex items-center gap-2 px-4 py-2 bg-white/5 border border-border rounded-md text-sm font-medium hover:bg-white/10 transition-colors"
        >
          <Download className="w-4 h-4" />
          Export Logs
        </button>
      </div>

      <div className="flex gap-4 items-end">
        <div className="flex-1 space-y-1.5">
          <label className="text-xs text-gray-500 font-medium">Search Entity</label>
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Entity ID..."
              className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>
        <div className="w-48 space-y-1.5">
          <label className="text-xs text-gray-500 font-medium">Filter Action</label>
          <div className="relative">
            <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <select
              className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full appearance-none"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
            >
              <option value="all">All Actions</option>
              {actionTypes.map(type => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="w-40 space-y-1.5">
          <label className="text-xs text-gray-500 font-medium">Mode</label>
          <div className="relative">
            <FlaskConical className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <select
              className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full appearance-none"
              value={simulatedFilter}
              onChange={(e) => setSimulatedFilter(e.target.value as 'all' | 'simulated' | 'real')}
            >
              <option value="all">All Modes</option>
              <option value="simulated">Simulated</option>
              <option value="real">Real</option>
            </select>
          </div>
        </div>
      </div>

      <div className="soc-card p-0 overflow-hidden">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Entity ID</th>
              <th>Action Type</th>
              <th>Status</th>
              <th>Mode</th>
              <th>Reason / Trigger</th>
              <th>Approved By</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs?.map((log, i) => (
              <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                <td className="text-xs font-mono text-gray-400" suppressHydrationWarning>
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="text-sm font-medium text-white">{log.entity_id}</td>
                <td>
                  <span className="text-xs px-2 py-0.5 bg-white/5 border border-white/10 rounded uppercase font-semibold">
                    {log.action_type}
                  </span>
                </td>
                <td>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${log.status === 'success' ? 'bg-success/10 text-success border-success/20' : 'bg-critical/10 text-critical border-critical/20'
                    }`}>
                    {log.status.toUpperCase()}
                  </span>
                </td>
                <td>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1 w-fit ${log.simulated
                    ? 'bg-primary/10 text-primary border-primary/20'
                    : 'bg-success/10 text-success border-success/20'
                    }`}>
                    {log.simulated && <FlaskConical className="w-3 h-3" />}
                    {log.simulated ? 'SIMULATED' : 'REAL'}
                  </span>
                </td>
                <td className="text-sm text-gray-400 max-w-xs truncate" title={log.reason}>
                  {log.reason}
                </td>
                <td>
                  {log.approved_by ? (
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded-full bg-primary/20 flex items-center justify-center">
                        <span className="text-[10px] font-bold text-primary">S</span>
                      </div>
                      <span className="text-xs text-gray-300">{log.approved_by}</span>
                    </div>
                  ) : (
                    <span className="text-xs text-gray-600 italic">SYSTEM</span>
                  )}
                </td>
              </tr>
            ))}
            {filteredLogs?.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center py-12 text-gray-500 italic">
                  No logs matching criteria
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
