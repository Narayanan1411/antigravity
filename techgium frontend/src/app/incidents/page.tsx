'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity } from '@/types';
import Link from 'next/link';
import { AlertTriangle, ExternalLink, Clock, ShieldAlert } from 'lucide-react';

export default function IncidentsPage() {
    const { data: entities, isLoading } = usePolling<Entity[]>('/entities/');

    // Derive incidents from entities where decision !== 'trusted'
    // An incident is when TrustScore dropped and triggered a non-trusted state
    const incidents = entities?.filter(e => e.decision !== 'trusted')
        .map(entity => ({
            incident_id: `INC-${entity.entity_id.slice(0, 8).toUpperCase()}`,
            entity,
            severity: (entity.trust_score ?? 0) < 30 ? 'critical' : (entity.trust_score ?? 0) < 50 ? 'high' : 'medium',
            status: entity.approval_required ? 'pending_approval' : 'active',
            actions: entity.active_actions,
        }))
        .sort((a, b) => (a.entity.trust_score ?? 0) - (b.entity.trust_score ?? 0));

    if (isLoading && !entities) {
        return <div className="flex items-center justify-center h-full text-gray-400">Loading incidents...</div>;
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                        <AlertTriangle className="w-7 h-7 text-alert" />
                        Active Incidents
                    </h2>
                    <p className="text-gray-400">Entities with TrustScore degradation requiring attention</p>
                </div>
                <div className="text-sm text-gray-500 flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    Auto-refreshes every 3s
                </div>
            </div>

            {incidents && incidents.length === 0 ? (
                <div className="soc-card flex flex-col items-center justify-center py-16 text-center">
                    <div className="p-4 bg-success/10 rounded-full mb-4">
                        <ShieldAlert className="w-12 h-12 text-success" />
                    </div>
                    <h3 className="text-xl font-bold text-white mb-2">All Clear</h3>
                    <p className="text-gray-400 max-w-md">
                        No active incidents detected. All monitored entities are in a trusted state.
                    </p>
                </div>
            ) : (
                <div className="soc-card p-0 overflow-hidden">
                    <table className="soc-table">
                        <thead>
                            <tr>
                                <th>Incident ID</th>
                                <th>Entity</th>
                                <th>Severity</th>
                                <th>TrustScore</th>
                                <th>Status</th>
                                <th>Actions Taken</th>
                                <th className="text-right">Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {incidents?.map((incident) => (
                                <tr key={incident.incident_id} className="hover:bg-white/[0.02] transition-colors">
                                    <td>
                                        <span className="font-mono text-sm font-bold text-white">{incident.incident_id}</span>
                                    </td>
                                    <td>
                                        <div className="flex flex-col">
                                            <span className="font-mono text-sm text-white">{incident.entity.entity_id}</span>
                                            {incident.entity.metadata?.ip && (
                                                <span className="text-xs text-gray-500">{incident.entity.metadata.ip}</span>
                                            )}
                                        </div>
                                    </td>
                                    <td>
                                        <SeverityBadge severity={incident.severity} />
                                    </td>
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                                                <div
                                                    className={`h-full ${getScoreColor(incident.entity.trust_score ?? 0)}`}
                                                    style={{ width: `${incident.entity.trust_score ?? 0}%` }}
                                                />
                                            </div>
                                            <span className="text-sm font-bold">{incident.entity.trust_score ?? '—'}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <StatusBadge status={incident.status} />
                                    </td>
                                    <td>
                                        {incident.actions.length > 0 ? (
                                            <div className="flex flex-wrap gap-1">
                                                {incident.actions.slice(0, 2).map(action => (
                                                    <span key={action} className="px-1.5 py-0.5 bg-primary/10 text-primary text-[10px] rounded border border-primary/20">
                                                        {action}
                                                    </span>
                                                ))}
                                                {incident.actions.length > 2 && (
                                                    <span className="text-xs text-gray-500">+{incident.actions.length - 2}</span>
                                                )}
                                            </div>
                                        ) : (
                                            <span className="text-xs text-gray-600">—</span>
                                        )}
                                    </td>
                                    <td className="text-right">
                                        <Link
                                            href={`/entities/${incident.entity.entity_id}`}
                                            className="inline-flex items-center gap-1 text-primary hover:text-primary/80 text-sm font-medium"
                                        >
                                            Investigate <ExternalLink className="w-3.5 h-3.5" />
                                        </Link>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function SeverityBadge({ severity }: { severity: string }) {
    const colors = {
        critical: 'bg-critical/10 text-critical border-critical/20',
        high: 'bg-alert/10 text-alert border-alert/20',
        medium: 'bg-warning/10 text-warning border-warning/20',
    };
    return (
        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase border ${colors[severity as keyof typeof colors] || colors.medium}`}>
            {severity}
        </span>
    );
}

function StatusBadge({ status }: { status: string }) {
    const isApprovalPending = status === 'pending_approval';
    return (
        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase border ${isApprovalPending
                ? 'bg-alert/10 text-alert border-alert/20 animate-pulse'
                : 'bg-primary/10 text-primary border-primary/20'
            }`}>
            {isApprovalPending ? 'Awaiting Approval' : 'Active'}
        </span>
    );
}

function getScoreColor(score: number) {
    if (score >= 80) return 'bg-success';
    if (score >= 50) return 'bg-warning';
    if (score >= 30) return 'bg-alert';
    return 'bg-critical';
}
