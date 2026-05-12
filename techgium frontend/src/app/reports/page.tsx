'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity, AuditLog } from '@/types';
import { FileText, BarChart3, PieChart, TrendingDown, Shield, Download } from 'lucide-react';
import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart as RechartsPie, Pie, Cell } from 'recharts';


export default function ReportsPage() {
    const { data: entities, isLoading: entitiesLoading } = usePolling<Entity[]>('/entities/');
    const { data: logs, isLoading: logsLoading } = usePolling<AuditLog[]>('/audit/');

    const isLoading = entitiesLoading || logsLoading;

    // Risk distribution data for chart
    const riskDistribution = useMemo(() => {
        if (!entities) return [];
        return [
            { name: 'Trusted (≥80)', value: entities.filter(e => (e.trust_score ?? 0) >= 80).length, color: '#22c55e' },
            { name: 'Monitor (50-79)', value: entities.filter(e => (e.trust_score ?? 0) >= 50 && (e.trust_score ?? 0) < 80).length, color: '#eab308' },
            { name: 'Alert (30-49)', value: entities.filter(e => (e.trust_score ?? 0) >= 30 && (e.trust_score ?? 0) < 50).length, color: '#f97316' },
            { name: 'Critical (<30)', value: entities.filter(e => (e.trust_score ?? 0) < 30).length, color: '#ef4444' },
        ];
    }, [entities]);

    // Action type summary
    const actionSummary = useMemo(() => {
        if (!logs) return [];
        const actionCounts: Record<string, number> = {};
        logs.forEach(log => {
            actionCounts[log.action_type] = (actionCounts[log.action_type] || 0) + 1;
        });
        return Object.entries(actionCounts)
            .map(([name, value]) => ({ name, value }))
            .sort((a, b) => b.value - a.value)
            .slice(0, 10);
    }, [logs]);

    // Decision distribution
    const decisionDistribution = useMemo(() => {
        if (!entities) return [];
        const decisionCounts: Record<string, number> = {};
        entities.forEach(e => {
            decisionCounts[e.decision] = (decisionCounts[e.decision] || 0) + 1;
        });
        return Object.entries(decisionCounts).map(([name, value]) => ({ name, value }));
    }, [entities]);

    if (isLoading && (!entities || !logs)) {
        return <div className="flex items-center justify-center h-full text-gray-400">Loading reports...</div>;
    }

    const totalEntities = entities?.length || 0;
    const avgTrustScore = entities ? Math.round(entities.reduce((sum, e) => sum + (e.trust_score ?? 0), 0) / totalEntities) : 0;
    const totalActions = logs?.length || 0;
    const simulatedCount = logs?.filter(l => l.simulated).length || 0;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-3">
                        <FileText className="w-7 h-7 text-primary" />
                        Security Reports
                    </h2>
                    <p className="text-gray-400">Summary analytics and compliance reporting</p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-md text-sm font-medium hover:bg-primary/90 transition-colors">
                    <Download className="w-4 h-4" />
                    Export Report
                </button>
            </div>

            {/* Summary Stats */}
            <div className="grid grid-cols-4 gap-4">
                <SummaryCard
                    title="Total Entities"
                    value={totalEntities}
                    icon={Shield}
                    color="text-primary"
                />
                <SummaryCard
                    title="Avg TrustScore"
                    value={avgTrustScore}
                    icon={TrendingDown}
                    color={avgTrustScore >= 70 ? 'text-success' : avgTrustScore >= 50 ? 'text-warning' : 'text-critical'}
                />
                <SummaryCard
                    title="Total Actions"
                    value={totalActions}
                    icon={BarChart3}
                    color="text-primary"
                />
                <SummaryCard
                    title="Simulated Actions"
                    value={simulatedCount}
                    icon={PieChart}
                    color="text-primary"
                    subtitle={`${Math.round((simulatedCount / totalActions) * 100) || 0}% of total`}
                />
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Risk Distribution Pie */}
                <div className="soc-card">
                    <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
                        <PieChart className="w-5 h-5 text-primary" />
                        Risk Distribution
                    </h3>
                    <div className="h-[300px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <RechartsPie>
                                <Pie
                                    data={riskDistribution.filter(d => d.value > 0)}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={100}
                                    paddingAngle={2}
                                    dataKey="value"
                                    label={({ name, value, percent }) =>
                                        value > 0 ? `${name}: ${value} (${(percent * 100).toFixed(0)}%)` : ''
                                    }
                                    labelLine={true}
                                >
                                    {riskDistribution.filter(d => d.value > 0).map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        backgroundColor: '#141414',
                                        border: '1px solid #262626',
                                        borderRadius: '8px'
                                    }}
                                />
                            </RechartsPie>
                        </ResponsiveContainer>
                    </div>
                    <div className="flex flex-wrap justify-center gap-4 mt-4">
                        {riskDistribution.map((item) => (
                            <div key={item.name} className="flex items-center gap-2 text-xs">
                                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                                <span className="text-gray-400">{item.name}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Action Types Bar Chart */}
                <div className="soc-card">
                    <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
                        <BarChart3 className="w-5 h-5 text-primary" />
                        Actions by Type
                    </h3>
                    <div className="h-[300px]">
                        {actionSummary.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={actionSummary} layout="vertical">
                                    <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
                                    <XAxis type="number" stroke="#666" />
                                    <YAxis dataKey="name" type="category" width={120} stroke="#666" tick={{ fontSize: 11 }} />
                                    <Tooltip
                                        contentStyle={{
                                            backgroundColor: '#141414',
                                            border: '1px solid #262626',
                                            borderRadius: '8px'
                                        }}
                                    />
                                    <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="flex items-center justify-center h-full text-gray-500 italic">
                                No action data available
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Decision Summary Table */}
            <div className="soc-card">
                <h3 className="font-semibold text-lg mb-4">Decision State Summary</h3>
                <div className="grid grid-cols-4 gap-4">
                    {decisionDistribution.map((item) => (
                        <div key={item.name} className="p-4 bg-white/5 rounded-lg border border-white/10 text-center">
                            <div className="text-2xl font-bold text-white">{item.value}</div>
                            <div className={`text-sm font-medium uppercase mt-1 ${item.name === 'trusted' ? 'text-success' :
                                    item.name === 'monitor' ? 'text-warning' :
                                        item.name === 'isolate' ? 'text-alert' :
                                            'text-critical'
                                }`}>
                                {item.name}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}

function SummaryCard({ title, value, icon: Icon, color, subtitle }: {
    title: string;
    value: number;
    icon: any;
    color: string;
    subtitle?: string;
}) {
    return (
        <div className="soc-card flex items-start justify-between">
            <div>
                <p className="text-sm text-gray-400 font-medium">{title}</p>
                <p className="text-3xl font-bold text-white mt-1">{value}</p>
                {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
            </div>
            <div className={`p-2 rounded-lg bg-white/5 ${color}`}>
                <Icon className="w-6 h-6" />
            </div>
        </div>
    );
}
