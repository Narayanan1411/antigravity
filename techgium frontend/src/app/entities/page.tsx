'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity } from '@/types';
import Link from 'next/link';
import { ExternalLink, Search, Filter, FlaskConical } from 'lucide-react';
import { useState, useMemo } from 'react';

const RISK_FILTERS = [
  { value: 'all', label: 'All Risk Levels' },
  { value: 'critical', label: 'Critical (<30)' },
  { value: 'alert', label: 'Alert (30-49)' },
  { value: 'monitor', label: 'Monitor (50-79)' },
  { value: 'trusted', label: 'Trusted (≥80)' },
];

export default function EntitiesPage() {
  const { data: entities, isLoading } = usePolling<Entity[]>('/entities/');
  const [searchTerm, setSearchTerm] = useState('');
  const [showMyDeviceOnly, setShowMyDeviceOnly] = useState(false);
  const [showSimulatedOnly, setShowSimulatedOnly] = useState(false);
  const [riskFilter, setRiskFilter] = useState('all');

  const filteredEntities = useMemo(() => {
    if (!entities) return [];

    return entities.filter(e => {
      const matchesSearch = e.entity_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.metadata?.ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        e.metadata?.hostname?.toLowerCase().includes(searchTerm.toLowerCase());
      const isMyDevice = e.metadata?.owner === 'presenter';
      const isSimulated = e.metadata?.simulated === 'true';

      // Risk level filter
      let matchesRisk = true;
      if (riskFilter === 'critical') matchesRisk = e.trust_score < 30;
      else if (riskFilter === 'alert') matchesRisk = e.trust_score >= 30 && e.trust_score < 50;
      else if (riskFilter === 'monitor') matchesRisk = e.trust_score >= 50 && e.trust_score < 80;
      else if (riskFilter === 'trusted') matchesRisk = e.trust_score >= 80;

      return matchesSearch &&
        (!showMyDeviceOnly || isMyDevice) &&
        (!showSimulatedOnly || isSimulated) &&
        matchesRisk;
    });
  }, [entities, searchTerm, showMyDeviceOnly, showSimulatedOnly, riskFilter]);

  if (isLoading && !entities) {
    return <div className="flex items-center justify-center h-full text-gray-400">Loading entities...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Entity Monitoring</h2>
          <p className="text-gray-400">Manage and inspect all monitored assets</p>
        </div>
      </div>

      {/* Filters Row */}
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

        <button
          onClick={() => setShowMyDeviceOnly(!showMyDeviceOnly)}
          className={`px-3 py-2 rounded-md text-sm font-medium border transition-colors ${showMyDeviceOnly
            ? "bg-primary/20 border-primary text-primary"
            : "bg-white/5 border-white/10 text-gray-400 hover:text-white"
            }`}
        >
          {showMyDeviceOnly ? "My Device Only" : "All Devices"}
        </button>

        <button
          onClick={() => setShowSimulatedOnly(!showSimulatedOnly)}
          className={`px-3 py-2 rounded-md text-sm font-medium border transition-colors flex items-center gap-2 ${showSimulatedOnly
            ? "bg-primary/20 border-primary text-primary"
            : "bg-white/5 border-white/10 text-gray-400 hover:text-white"
            }`}
        >
          <FlaskConical className="w-4 h-4" />
          {showSimulatedOnly ? "Simulated Only" : "All Modes"}
        </button>
      </div>

      {/* Results Count */}
      <div className="text-sm text-gray-500">
        Showing {filteredEntities.length} of {entities?.length || 0} entities
      </div>

      <div className="soc-card p-0 overflow-hidden">
        <table className="soc-table">
          <thead>
            <tr>
              <th>Entity ID</th>
              <th>Type</th>
              <th>TrustScore</th>
              <th>Confidence</th>
              <th>Decision State</th>
              <th>Last Updated</th>
              <th>Active Response</th>
              <th className="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredEntities.map((entity) => (
              <tr key={entity.entity_id} className="hover:bg-white/[0.02] transition-colors">
                <td className="w-1/4">
                  <div className="flex flex-col">
                    <span className="font-mono text-sm text-white flex items-center gap-2">
                      {entity.entity_id}
                      {entity.metadata?.owner === 'presenter' && (
                        <span className="px-1.5 py-0.5 rounded bg-primary/20 text-primary text-[10px] font-bold uppercase border border-primary/30">
                          You
                        </span>
                      )}
                    </span>
                    {entity.metadata?.ip && <span className="text-xs text-gray-500 font-mono mt-0.5">{entity.metadata.ip}</span>}
                  </div>
                </td>
                <td>
                  <div className="flex flex-col gap-1">
                    <span className="text-xs px-2 py-0.5 bg-white/5 border border-white/10 rounded w-fit uppercase font-medium text-gray-400">
                      {entity.metadata?.type || 'workstation'}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border w-fit flex items-center gap-1 ${entity.metadata?.simulated === 'true'
                      ? "bg-primary/10 border-primary/20 text-primary"
                      : "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
                      }`}>
                      {entity.metadata?.simulated === 'true' && <FlaskConical className="w-2.5 h-2.5" />}
                      {entity.metadata?.simulated === 'true' ? "Simulated" : "Real"}
                    </span>
                  </div>
                </td>
                <td>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-1.5 w-24 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${getScoreColor(entity.trust_score)}`}
                        style={{ width: `${entity.trust_score}%` }}
                      />
                    </div>
                    <span className="text-sm font-bold w-6">{entity.trust_score}</span>
                  </div>
                </td>
                <td>
                  <span className="text-sm text-gray-300">{entity.confidence}%</span>
                </td>
                <td>
                  <DecisionBadge decision={entity.decision} score={entity.trust_score} />
                </td>
                <td>
                  <span className="text-xs text-gray-500" suppressHydrationWarning>
                    {new Date(entity.last_updated).toLocaleTimeString()}
                  </span>
                </td>
                <td>
                  {entity.active_actions.length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {entity.active_actions.map(action => (
                        <span key={action} className="px-1.5 py-0.5 bg-primary/10 text-primary text-[10px] rounded border border-primary/20">
                          {action}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs text-gray-600">—</span>
                  )}
                </td>
                <td className="text-right">
                  <Link
                    href={`/entities/${entity.entity_id}`}
                    className="inline-flex items-center gap-1.5 text-primary hover:text-primary/80 text-sm font-medium transition-colors"
                  >
                    Details <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                </td>
              </tr>
            ))}
            {filteredEntities.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center py-12 text-gray-500 italic">
                  No entities matching your filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function getScoreColor(score: number) {
  if (score >= 80) return 'bg-success';
  if (score >= 50) return 'bg-warning';
  if (score >= 30) return 'bg-alert';
  return 'bg-critical';
}

function DecisionBadge({ decision, score }: { decision: string, score: number }) {
  let colors = "bg-gray-500/10 text-gray-500 border-gray-500/20";

  if (score >= 80) colors = "bg-success/10 text-success border-success/20";
  else if (score >= 50) colors = "bg-warning/10 text-warning border-warning/20";
  else if (score >= 30) colors = "bg-alert/10 text-alert border-alert/20";
  else colors = "bg-critical/10 text-critical border-critical/20";

  return (
    <span className={`px-2 py-1 rounded text-[11px] font-bold uppercase border ${colors}`}>
      {decision}
    </span>
  );
}
