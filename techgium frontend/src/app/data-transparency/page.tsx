'use client';

import { usePolling } from '@/hooks/usePolling';
import { TrustScoreGauge } from '@/components/TrustScoreGauge';
import { Entity } from '@/types';
import {
    Database,
    Shield,
    Network,
    Key,
    Cloud,
    Cpu,
    Clock,
    TrendingUp,
    Activity,
    AlertTriangle,
    Users
} from 'lucide-react';
import { useState, useMemo } from 'react';

const CATEGORY_ICONS: Record<string, any> = {
    network: Network,
    identity: Key,
    cloud: Cloud,
    hardware: Cpu,
    temporal: Clock,
};

const TYPE_COLORS: Record<string, string> = {
    REAL: 'bg-success/20 text-success border-success/30',
    HYBRID: 'bg-warning/20 text-warning border-warning/30',
    SIMULATED: 'bg-alert/20 text-alert border-alert/30',
    COMPUTED: 'bg-primary/20 text-primary border-primary/30',
};

interface EventStats {
    total_events: number;
    by_category: Record<string, number>;
    by_source_type: Record<string, number>;
    by_event_type: Record<string, number>;
    category_severity: Record<string, number>;
    source_activity: Record<string, {
        name: string;
        category: string;
        event_count: number;
        last_event_time: string | null;
        avg_severity: number;
        type: string;
    }>;
    recent_events: Array<{
        event_id: string;
        entity_id: string;
        category: string;
        event_type: string;
        severity: number;
        timestamp: string;
        simulated: boolean;
    }>;
    high_severity_count: number;
    last_updated: string;
}

// Animated counter component
function AnimatedCounter({ value }: { value: number }) {
    return <span>{value}</span>;
}

// Time ago helper
function timeAgo(timestamp: string | number | null): string {
    if (!timestamp) return 'Never';
    const now = Date.now();
    const then = typeof timestamp === 'string' ? new Date(timestamp).getTime() : timestamp;
    const seconds = Math.floor((now - then) / 1000);

    if (seconds < 5) return 'Just now';
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

export default function DataTransparencyPage() {
    const [selectedEntity, setSelectedEntity] = useState<string>('all');

    // Real data from backend
    const { data: realStats } = usePolling<EventStats>('/transparency/stats', 3000);
    const { data: entities } = usePolling<Entity[]>('/entities/');

    // Calculate aggregated TrustScore for real mode
    const aggregatedTrustScore = useMemo(() => {
        if (!entities || entities.length === 0) return 100;

        if (selectedEntity !== 'all') {
            const entity = entities.find(e => e.entity_id === selectedEntity);
            return entity?.trust_score || 100;
        }

        // Average TrustScore across all entities
        const avgScore = entities.reduce((sum, e) => sum + e.trust_score, 0) / entities.length;
        return Math.round(avgScore);
    }, [entities, selectedEntity]);

    // Determine risk level for real mode
    const realRiskLevel = useMemo(() => {
        const score = aggregatedTrustScore;
        if (score >= 80) return 'LOW';
        if (score >= 60) return 'MEDIUM';
        if (score >= 40) return 'HIGH';
        return 'CRITICAL';
    }, [aggregatedTrustScore]);

    const stats = realStats;
    const trustScore = aggregatedTrustScore;
    const riskLevel = realRiskLevel;

    const categories = ['network', 'identity', 'cloud', 'hardware', 'temporal'];

    // Filter events by selected entity in real mode
    const filteredEvents = useMemo(() => {
        if (!stats) return [];
        if (selectedEntity === 'all') return stats.recent_events;
        return stats.recent_events.filter(e => e.entity_id === selectedEntity);
    }, [stats, selectedEntity]);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="border-b border-border pb-6">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <Shield className="w-8 h-8 text-primary" />
                            <h1 className="text-3xl font-bold text-white">
                                Agentless Endpoint Protection
                            </h1>
                        </div>
                        <h2 className="text-xl text-gray-300 font-medium">
                            Data Collection Transparency Console
                        </h2>
                    </div>
                </div>

                <div className="flex items-center gap-4 mt-4">
                    <div className="flex items-center gap-2">
                        <Users className="w-5 h-5 text-gray-400" />
                        <span className="text-sm text-gray-400">Showing data for:</span>
                    </div>
                    <select
                        value={selectedEntity}
                        onChange={(e) => setSelectedEntity(e.target.value)}
                        className="bg-background border border-border rounded-lg px-4 py-2 text-white focus:outline-none focus:ring-2 focus:ring-primary"
                    >
                        <option value="all">All Entities ({entities?.length || 0})</option>
                        {entities?.map(e => (
                            <option key={e.entity_id} value={e.entity_id}>
                                {e.entity_id} (Score: {e.trust_score})
                            </option>
                        ))}
                    </select>
                    {stats && (
                        <div className="text-sm text-gray-400">
                            Total Events: <span className="text-white font-bold">{stats.total_events}</span>
                        </div>
                    )}
                </div>
            </div>

            {/* Attack Banner */}
            {trustScore < 80 && (
                <div className={`soc-card border-2 ${riskLevel === 'CRITICAL' ? 'bg-critical/10 border-critical animate-pulse' : 'bg-alert/10 border-alert'}`}>
                    <div className="flex items-center gap-3">
                        <AlertTriangle className={`w-6 h-6 ${riskLevel === 'CRITICAL' ? 'text-critical' : 'text-alert'}`} />
                        <div>
                            <div className="font-bold text-white text-lg">
                                {riskLevel === 'CRITICAL' ? '⚠️ CRITICAL: ' : '🚨 '}
                                High Risk Detected
                            </div>
                            <div className="text-sm text-gray-300 mt-1">
                                TrustScore: {Math.round(trustScore)} - {riskLevel} risk level
                                {selectedEntity !== 'all' && ` for ${selectedEntity}`}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* TrustScore Gauge + Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* TrustScore Gauge */}
                <div className="soc-card flex items-center justify-center">
                    <TrustScoreGauge score={trustScore} riskLevel={riskLevel} />
                </div>

                {/* Mode-specific Controls */}
                <div className="soc-card flex flex-col justify-center gap-4">
                    <>
                        <div>
                            <h3 className="text-lg font-semibold text-white mb-2">Live Data</h3>
                            <p className="text-sm text-gray-400">
                                Displaying real-time data from {selectedEntity === 'all' ? 'all tracked entities' : selectedEntity}.
                            </p>
                        </div>

                        {entities && entities.length > 0 && (
                            <div className="grid grid-cols-2 gap-3">
                                <div className="bg-background border border-border rounded-lg p-3">
                                    <div className="text-xs text-gray-400 mb-1">Total Entities</div>
                                    <div className="text-2xl font-bold text-white">{entities.length}</div>
                                </div>
                                <div className="bg-background border border-border rounded-lg p-3">
                                    <div className="text-xs text-gray-400 mb-1">High Risk</div>
                                    <div className="text-2xl font-bold text-alert">
                                        {entities.filter(e => e.trust_score < 40).length}
                                    </div>
                                </div>
                            </div>
                        )}
                    </>
                </div>
            </div>

            {/* Live Event Statistics */}
            {stats && (
                <div className="soc-card bg-primary/5 border-primary/20">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                            <Activity className="w-5 h-5 text-primary" />
                            Live Event Statistics
                        </h3>
                        <div className="text-xs text-gray-500">
                            Updated: {timeAgo(stats.last_updated)}
                        </div>
                    </div>

                    {/* Category Event Counts */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                        {categories.map((categoryName) => {
                            const Icon = CATEGORY_ICONS[categoryName] || Database;
                            const count = stats?.by_category[categoryName] || 0;
                            const avgSeverity = stats?.category_severity[categoryName] || 0;

                            return (
                                <div
                                    key={categoryName}
                                    className="bg-background border border-border rounded-lg p-3 transition-all duration-300"
                                >
                                    <div className="flex items-center gap-2 mb-1">
                                        <Icon className="w-4 h-4 text-primary" />
                                        <span className="text-xs text-gray-400 capitalize">{categoryName}</span>
                                    </div>
                                    <div className="flex items-baseline gap-2">
                                        <span className="text-2xl font-bold text-white">
                                            <AnimatedCounter value={count} />
                                        </span>
                                        {count > 0 && (
                                            <TrendingUp className="w-4 h-4 text-success" />
                                        )}
                                    </div>
                                    <div className="text-[10px] text-gray-500 mt-1">
                                        Avg Severity: {avgSeverity.toFixed(2)}
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Total Stats Row */}
                    <div className="grid grid-cols-3 gap-3 pt-3 border-t border-border">
                        <div className="text-center">
                            <div className="text-xs text-gray-400 mb-1">Total Events</div>
                            <div className="text-xl font-bold text-white">
                                <AnimatedCounter value={stats?.total_events || 0} />
                            </div>
                        </div>
                        <div className="text-center">
                            <div className="text-xs text-gray-400 mb-1">High Severity</div>
                            <div className="text-xl font-bold text-alert">
                                <AnimatedCounter value={stats?.high_severity_count || 0} />
                            </div>
                        </div>
                        <div className="text-center">
                            <div className="text-xs text-gray-400 mb-1">Simulated</div>
                            <div className="text-xl font-bold text-warning">
                                <AnimatedCounter value={stats?.by_source_type['SIMULATED'] || 0} />
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* Data Source Activity Table */}
            {stats && (
                <div className="soc-card">
                    <h3 className="text-lg font-semibold text-white mb-4">Data Source Activity</h3>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                            <thead>
                                <tr className="border-b border-border">
                                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Source</th>
                                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Category</th>
                                    <th className="text-right py-2 px-3 text-gray-400 font-medium">Events</th>
                                    <th className="text-right py-2 px-3 text-gray-400 font-medium">Avg Severity</th>
                                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Last Event</th>
                                    <th className="text-left py-2 px-3 text-gray-400 font-medium">Type</th>
                                </tr>
                            </thead>
                            <tbody>
                                {Object.entries(stats.source_activity)
                                    .filter(([_, activity]) => activity.event_count > 0)
                                    .map(([sourceId, activity]) => (
                                        <tr key={sourceId} className="border-b border-border/50 hover:bg-white/5 transition-colors">
                                            <td className="py-2 px-3 text-white font-medium">{activity.name}</td>
                                            <td className="py-2 px-3 text-gray-400 capitalize">{activity.category}</td>
                                            <td className="py-2 px-3 text-right text-white font-bold">
                                                <AnimatedCounter value={activity.event_count} />
                                            </td>
                                            <td className="py-2 px-3 text-right">
                                                <span className={`font-mono ${activity.avg_severity >= 0.7 ? 'text-critical' :
                                                    activity.avg_severity >= 0.5 ? 'text-alert' :
                                                        activity.avg_severity >= 0.3 ? 'text-warning' : 'text-success'
                                                    }`}>
                                                    {activity.avg_severity.toFixed(2)}
                                                </span>
                                            </td>
                                            <td className="py-2 px-3 text-gray-400 text-xs">
                                                {timeAgo(activity.last_event_time)}
                                            </td>
                                            <td className="py-2 px-3">
                                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${TYPE_COLORS[activity.type]}`}>
                                                    {activity.type}
                                                </span>
                                            </td>
                                        </tr>
                                    ))}
                            </tbody>
                        </table>

                        {stats.total_events === 0 && (
                            <div className="text-center py-8 text-gray-500">
                                No events yet. Connect your backend system to view events.
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Recent Events Stream */}
            {filteredEvents.length > 0 && (
                <div className="soc-card">
                    <h3 className="text-lg font-semibold text-white mb-4">
                        Recent Events Stream
                        {selectedEntity !== 'all' && (
                            <span className="text-sm text-gray-400 ml-2">for {selectedEntity}</span>
                        )}
                    </h3>
                    <div className="space-y-2 max-h-[400px] overflow-y-auto">
                        {filteredEvents.slice(0, 20).map((event) => (
                            <div
                                key={event.event_id}
                                className="flex items-center justify-between p-2 bg-white/5 rounded border border-border/50 hover:border-primary/30 transition-colors"
                            >
                                <div className="flex items-center gap-3 flex-1">
                                    <div className={`w-2 h-2 rounded-full ${event.severity >= 0.7 ? 'bg-critical' :
                                        event.severity >= 0.5 ? 'bg-alert' :
                                            event.severity >= 0.3 ? 'bg-warning' : 'bg-success'
                                        }`} />
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2">
                                            <span className="text-white font-medium text-sm">{event.event_type}</span>
                                            <span className="px-2 py-0.5 bg-primary/10 border border-primary/30 rounded text-[10px] text-primary capitalize">
                                                {event.category}
                                            </span>
                                        </div>
                                        <div className="text-xs text-gray-500 mt-0.5">
                                            Entity: {event.entity_id} • Severity: {event.severity.toFixed(2)}
                                        </div>
                                    </div>
                                </div>
                                <div className="text-xs text-gray-500">
                                    {timeAgo(event.timestamp)}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
