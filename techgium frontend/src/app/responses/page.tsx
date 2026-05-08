'use client';

import { usePolling } from '@/hooks/usePolling';
import { AuditLog } from '@/types';
import { Activity, Clock, CheckCircle2, XCircle, RotateCcw, Filter, FlaskConical } from 'lucide-react';
import { useState, useMemo } from 'react';

export default function ResponsesPage() {
    const { data: logs, isLoading } = usePolling<AuditLog[]>('/audit/');
    const [statusFilter, setStatusFilter] = useState('all');
    const [simulatedFilter, setSimulatedFilter] = useState<'all' | 'simulated' | 'real'>('all');

    // Filter for response-related actions only
    const responseActions = useMemo(() => {
        if (!logs) return [];

        return logs.filter(log => {
            // Filter for actual response actions (not TrustScore updates)
            const isResponseAction = log.action_type.includes('isolate') ||
                log.action_type.includes('block') ||
                log.action_type.includes('revoke') ||
                log.action_type.includes('snapshot') ||
                log.action_type.includes('notify') ||
                log.action_type === 'approval' ||
                log.action_type === 'network_isolate';

            const matchesStatus = statusFilter === 'all' || log.status === statusFilter;
            const matchesSimulated = simulatedFilter === 'all' ||
                (simulatedFilter === 'simulated' && log.simulated) ||
                (simulatedFilter === 'real' && !log.simulated);

            return matchesStatus && matchesSimulated;
        }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }, [logs, statusFilter, simulatedFilter]);

    // Count stats
    const stats = useMemo(() => {
        if (!logs) return { pending: 0, executed: 0, rejected: 0, total: 0 };

        return {
            pending: logs.filter(l => l.status === 'pending').length,
            executed: logs.filter(l => l.status === 'success' || l.status === 'executed').length,
            rejected: logs.filter(l => l.status === 'rejected' || l.status === 'failed').length,
            total: logs.length,
        };
    }, [logs]);

    if (isLoading && !logs) {
        return <div className="flex items-center justify-center h-full text-gray-400">Loading response actions...</div>;
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                        <Activity className="w-7 h-7 text-primary" />
                        Response Center
                    </h2>
                    <p className="text-gray-400">SOC-controlled actions and their execution status</p>
                </div>
                <div className="text-sm text-gray-500 flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    Auto-refreshes every 3s
                </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-4 gap-4">
                <StatCard
                    title="Total Actions"
                    value={stats.total}
                    icon={Activity}
                    color="text-primary"
                />
                <StatCard
                    title="Pending Approval"
                    value={stats.pending}
                    icon={Clock}
                    color="text-warning"
                />
                <StatCard
                    title="Executed"
                    value={stats.executed}
                    icon={CheckCircle2}
                    color="text-success"
                />
                <StatCard
                    title="Rejected/Failed"
                    value={stats.rejected}
                    icon={XCircle}
                    color="text-critical"
                />
            </div>

            {/* Filters */}
            <div className="flex gap-4 items-end">
                <div className="w-48 space-y-1.5">
                    <label className="text-xs text-gray-500 font-medium">Status</label>
                    <div className="relative">
                        <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                        <select
                            className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full appearance-none"
                            value={statusFilter}
                            onChange={(e) => setStatusFilter(e.target.value)}
                        >
                            <option value="all">All Statuses</option>
                            <option value="pending">Pending</option>
                            <option value="success">Executed</option>
                            <option value="rejected">Rejected</option>
                            <option value="failed">Failed</option>
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

            {/* Actions Table */}
            <div className="soc-card p-0 overflow-hidden">
                <table className="soc-table">
                    <thead>
                        <tr>
                            <th>Action Type</th>
                            <th>Entity</th>
                            <th>Status</th>
                            <th>Mode</th>
                            <th>Human Approval</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        {responseActions.length === 0 ? (
                            <tr>
                                <td colSpan={6} className="text-center py-12 text-gray-500 italic">
                                    No response actions recorded
                                </td>
                            </tr>
                        ) : (
                            responseActions.slice(0, 50).map((action, i) => (
                                <tr key={i} className="hover:bg-white/[0.02] transition-colors">
                                    <td>
                                        <div className="flex items-center gap-2">
                                            <ActionIcon action={action.action_type} />
                                            <span className="text-sm font-medium text-white uppercase">{action.action_type}</span>
                                        </div>
                                    </td>
                                    <td>
                                        <span className="font-mono text-sm text-gray-300">{action.entity_id}</span>
                                    </td>
                                    <td>
                                        <StatusBadge status={action.status} />
                                    </td>
                                    <td>
                                        <span className={`text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1 w-fit ${action.simulated
                                            ? 'bg-primary/10 text-primary border-primary/20'
                                            : 'bg-success/10 text-success border-success/20'
                                            }`}>
                                            {action.simulated && <FlaskConical className="w-2.5 h-2.5" />}
                                            {action.simulated ? 'SIM' : 'REAL'}
                                        </span>
                                    </td>
                                    <td>
                                        {action.approved_by ? (
                                            <div className="flex items-center gap-2">
                                                <CheckCircle2 className="w-3.5 h-3.5 text-success" />
                                                <span className="text-xs text-gray-300">{action.approved_by}</span>
                                            </div>
                                        ) : (
                                            <span className="text-xs text-gray-600 italic">SYSTEM</span>
                                        )}
                                    </td>
                                    <td>
                                        <span className="text-xs text-gray-500" suppressHydrationWarning>
                                            {new Date(action.timestamp).toLocaleString()}
                                        </span>
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function StatCard({ title, value, icon: Icon, color }: { title: string; value: number; icon: any; color: string }) {
    return (
        <div className="soc-card flex items-start justify-between">
            <div>
                <p className="text-sm text-gray-400 font-medium">{title}</p>
                <p className="text-3xl font-bold text-white mt-1">{value}</p>
            </div>
            <div className={`p-2 rounded-lg bg-white/5 ${color}`}>
                <Icon className="w-6 h-6" />
            </div>
        </div>
    );
}

function ActionIcon({ action }: { action: string }) {
    if (action.includes('isolate')) return <XCircle className="w-4 h-4 text-critical" />;
    if (action.includes('block')) return <XCircle className="w-4 h-4 text-alert" />;
    if (action.includes('revoke')) return <RotateCcw className="w-4 h-4 text-warning" />;
    return <Activity className="w-4 h-4 text-primary" />;
}

function StatusBadge({ status }: { status: string }) {
    const configs: Record<string, string> = {
        pending: 'bg-warning/10 text-warning border-warning/20',
        success: 'bg-success/10 text-success border-success/20',
        executed: 'bg-success/10 text-success border-success/20',
        rejected: 'bg-critical/10 text-critical border-critical/20',
        failed: 'bg-critical/10 text-critical border-critical/20',
    };

    return (
        <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase border ${configs[status] || 'bg-gray-500/10 text-gray-500 border-gray-500/20'}`}>
            {status}
        </span>
    );
}
