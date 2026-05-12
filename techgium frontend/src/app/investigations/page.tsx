'use client';

import { usePolling } from '@/hooks/usePolling';
import { AuditLog } from '@/types';
import { Search, Clock, Calendar } from 'lucide-react';
import { useState, useMemo } from 'react';

const TIME_RANGES = [
    { label: 'Last 1 hour', hours: 1 },
    { label: 'Last 6 hours', hours: 6 },
    { label: 'Last 24 hours', hours: 24 },
    { label: 'Last 7 days', hours: 168 },
    { label: 'All time', hours: 0 },
];

const CATEGORIES = ['all', 'network', 'identity', 'cloud', 'hardware', 'temporal'];

export default function InvestigationsPage() {
    const { data: logs, isLoading } = usePolling<AuditLog[]>('/audit/');
    const [searchTerm, setSearchTerm] = useState('');
    const [categoryFilter, setCategoryFilter] = useState('all');
    const [severityFilter, setSeverityFilter] = useState('all');
    const [timeRangeHours, setTimeRangeHours] = useState(24);

    const filteredLogs = useMemo(() => {
        if (!logs) return [];

        const now = new Date();
        const cutoff = timeRangeHours > 0
            ? new Date(now.getTime() - timeRangeHours * 60 * 60 * 1000)
            : new Date(0);

        return logs.filter(log => {
            const logDate = new Date(log.timestamp);
            const matchesTime = logDate >= cutoff;
            const matchesSearch = log.entity_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                log.action_type.toLowerCase().includes(searchTerm.toLowerCase());
            return matchesTime && matchesSearch;
        }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }, [logs, searchTerm, categoryFilter, severityFilter, timeRangeHours]);

    // Group logs by entity for cross-entity analysis
    const entityGroups = useMemo(() => {
        const groups: Record<string, AuditLog[]> = {};
        filteredLogs.forEach(log => {
            if (!groups[log.entity_id]) groups[log.entity_id] = [];
            groups[log.entity_id].push(log);
        });
        return groups;
    }, [filteredLogs]);

    if (isLoading && !logs) {
        return <div className="flex items-center justify-center h-full text-gray-400">Loading investigation data...</div>;
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                        <Search className="w-7 h-7 text-primary" />
                        Investigations
                    </h2>
                    <p className="text-gray-400">Cross-entity event timeline analysis</p>
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
                            placeholder="Entity ID or action type..."
                            className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full"
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                        />
                    </div>
                </div>

                <div className="w-48 space-y-1.5">
                    <label className="text-xs text-gray-500 font-medium">Time Range</label>
                    <div className="relative">
                        <Calendar className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                        <select
                            className="bg-card border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary w-full appearance-none"
                            value={timeRangeHours}
                            onChange={(e) => setTimeRangeHours(Number(e.target.value))}
                        >
                            {TIME_RANGES.map(range => (
                                <option key={range.hours} value={range.hours}>{range.label}</option>
                            ))}
                        </select>
                    </div>
                </div>

            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-2 gap-4">
                <div className="soc-card text-center">
                    <div className="text-3xl font-bold text-white">{filteredLogs.length.toLocaleString()}</div>
                    <div className="text-xs text-gray-500 mt-1">Total Events</div>
                </div>
                <div className="soc-card text-center">
                    <div className="text-3xl font-bold text-white">{Object.keys(entityGroups).length}</div>
                    <div className="text-xs text-gray-500 mt-1">Entities Involved</div>
                </div>
            </div>

            {/* Cross-Entity Timeline */}
            <div className="soc-card">
                <h3 className="font-semibold text-lg mb-6 flex items-center gap-2">
                    <Clock className="w-5 h-5 text-primary" />
                    Event Timeline
                </h3>

                {filteredLogs.length === 0 ? (
                    <div className="text-center py-12 text-gray-500 italic">
                        No events matching criteria
                    </div>
                ) : (
                    <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
                        {filteredLogs.slice(0, 500).map((log, i) => (
                            <div key={i} className="relative pl-8 pb-4 border-l border-border last:border-0 last:pb-0">
                                <div className="absolute left-[-9px] top-0 w-4 h-4 rounded-full border-2 bg-card border-primary" />
                                <div className="flex items-start justify-between mb-1">
                                    <div>
                                        <span className="text-sm font-semibold text-white">{log.action_type}</span>
                                        <span className="text-xs text-gray-500 ml-2">on</span>
                                        <span className="text-sm font-mono text-primary ml-2">{log.entity_id}</span>
                                    </div>
                                    <span className="text-xs text-gray-500" suppressHydrationWarning>{new Date(log.timestamp).toLocaleString()}</span>
                                </div>
                                <p className="text-sm text-gray-400">{log.reason}</p>
                                <div className="mt-2 flex items-center gap-3">
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${log.status === 'success'
                                        ? 'bg-success/10 text-success border-success/20'
                                        : 'bg-critical/10 text-critical border-critical/20'
                                        }`}>
                                        {log.status.toUpperCase()}
                                    </span>
                                    {log.approved_by && (
                                        <span className="text-[10px] text-gray-500">by {log.approved_by}</span>
                                    )}
                                </div>
                            </div>
                        ))}
                        {filteredLogs.length > 500 && (
                            <div className="text-center py-4 text-xs text-gray-500">
                                Showing 500 of {filteredLogs.length.toLocaleString()} events — narrow the time range to see more
                            </div>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
