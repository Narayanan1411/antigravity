'use client';

import React, { useState } from 'react';
import { usePolling } from '@/hooks/usePolling';
import { Entity } from '@/types';
import useSWR from 'swr';
import {
    LineChart, Line, AreaChart, Area, BarChart, Bar,
    XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid
} from 'recharts';
import {
    Server, Shield, Laptop, Activity, ChevronDown, ChevronRight,
    AlertTriangle, CheckCircle, XCircle, Zap, Clock, Cpu,
    Network, User, Cloud, HardDrive, Wifi, WifiOff, Database,
    Brain
} from 'lucide-react';

// ─── Types ────────────────────────────────────────────────────────────
interface TrustPoint { time: string; score: number; adjusted_risk: number }
interface AnomalyPoint { time: string; score: number; reasons: string[] }
interface RiskPoint { time: string; score: number; severity: string }

interface EntityDetail extends Omit<Entity, 'trust_history'> {
    trust_history: TrustPoint[];
    anomaly_history: AnomalyPoint[];
    risk_history: RiskPoint[];
    ml_state: Record<string, any> | null;
    category_risks: { N: number; I: number; C: number; V: number };
}

// ─── Colors ───────────────────────────────────────────────────────────
function trustColor(score: number): string {
    if (score >= 80) return '#22c55e';
    if (score >= 60) return '#eab308';
    if (score >= 40) return '#f97316';
    return '#ef4444';
}
function riskColor(v: number): string {
    if (v < 0.2) return '#22c55e';
    if (v < 0.5) return '#eab308';
    if (v < 0.8) return '#f97316';
    return '#ef4444';
}

// ─── Pipeline stages ──────────────────────────────────────────────────
const STAGES = [
    { name: 'Network Sniffer', icon: Wifi, desc: 'Captures real packets from network interface → pushes flows to /network/telemetry every 3s.' },
    { name: 'Normalize + Enrich', icon: Database, desc: 'enrichment_service.py: adds GeoIP, reverse DNS, MAC vendor, device class, byte totals, after-hours flag.' },
    { name: 'Feature Engineering', icon: Zap, desc: 'feature_engine.py: converts enriched events to 30+ numeric features (dns_entropy, port_risk, cpu_percent, …).' },
    { name: 'ML Anomaly Detection', icon: Brain, desc: 'ml_monitor.py: Welford online algorithm computes per-device z-scores; rule-based fallback during warmup (<10 events).' },
    { name: 'Risk Scoring', icon: AlertTriangle, desc: 'risk_engine.py: composite risk = severity × anomaly × confidence × device_impact (0–100). Classifies to I/C/V/N.' },
    { name: 'Trust Engine', icon: Shield, desc: 'trust_engine.py: 9-step math model — AR, CAF, CI, RV → adjusted trust score (0–100) with adaptive decay.' },
    { name: 'Decision Engine', icon: CheckCircle, desc: 'decision_engine.py: trust → action (allow/monitor/MFA/restrict/isolate). Fires alerts when trust < threshold.' },
    { name: 'Response Engine', icon: XCircle, desc: 'TBD — simulated. SOC approvals logged to alerts table. Real enforcement coming.' },
];

// ─── Gauge ────────────────────────────────────────────────────────────
function RiskGauge({ label, value, icon: Icon, color }: { label: string; value: number; icon: any; color: string }) {
    const pct = Math.min(100, value * 100);
    return (
        <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between text-[10px]">
                <span className="flex items-center gap-1 text-gray-400"><Icon className="w-3 h-3" />{label}</span>
                <span className="font-mono font-bold" style={{ color }}>{pct.toFixed(1)}%</span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: color }} />
            </div>
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────────────
export default function AdaptiveTrustPage() {
    const { data: entities, status } = usePolling<Entity[]>('/entities/');
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [expandedStage, setExpandedStage] = useState<number | null>(null);

    const activeId = selectedId || entities?.[0]?.entity_id || null;

    // Per-entity deep fetch (polls every 5s)
    const { data: detail } = useSWR<EntityDetail>(
        activeId ? `/entities/${activeId}` : null,
        (url: string) => fetch(`http://localhost:8000/api/v1${url}`).then(r => r.json()),
        { refreshInterval: 5000, revalidateOnFocus: false }
    );

    const isOnline = status === 'online';
    const trust = detail?.trust_score ?? 80;

    return (
        <div className="flex flex-col h-full -m-6 overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-card/80 backdrop-blur-sm shrink-0">
                <div className="flex items-center gap-3">
                    <Shield className="w-7 h-7 text-primary" />
                    <h1 className="text-lg font-bold tracking-tight">
                        Guardient <span className="text-gray-400 font-normal">— Adaptive Trust Engine</span>
                    </h1>
                </div>
                <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium border ${isOnline ? 'bg-success/10 text-success border-success/20' : 'bg-critical/10 text-critical border-critical/20'}`}>
                    {isOnline ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
                    {isOnline ? 'LIVE' : 'OFFLINE'}
                </div>
            </div>

            {/* Entity banner */}
            {activeId && (
                <div className="flex items-center gap-3 px-5 py-2 border-b border-border/50 bg-primary/5 shrink-0">
                    <Shield className="w-4 h-4 text-primary" />
                    <span className="text-xs text-gray-400">Inspecting:</span>
                    <span className="text-sm font-bold text-white font-mono">{activeId}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full" style={{
                        background: `${trustColor(trust)}15`,
                        color: trustColor(trust),
                        border: `1px solid ${trustColor(trust)}40`,
                    }}>
                        TrustScore: {trust.toFixed(1)}
                    </span>
                    {detail?.metadata?.ip && (
                        <span className="text-xs text-gray-500 font-mono">{detail.metadata.ip}</span>
                    )}
                    {detail?.metadata?.hostname && (
                        <span className="text-xs text-gray-500">{detail.metadata.hostname}</span>
                    )}
                </div>
            )}

            <div className="flex flex-1 min-h-0">
                {/* LEFT — Entity List */}
                <div className="w-[220px] shrink-0 border-r border-border bg-card/50 flex flex-col overflow-y-auto">
                    <div className="px-3 pt-3 pb-2">
                        <h2 className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">
                            Live Entities ({entities?.length ?? 0})
                        </h2>
                    </div>
                    <div className="space-y-1 px-2 pb-3">
                        {entities?.map(ep => {
                            const isSelected = ep.entity_id === activeId;
                            return (
                                <div
                                    key={ep.entity_id}
                                    onClick={() => setSelectedId(ep.entity_id)}
                                    className={`flex items-center gap-2 px-2 py-2 rounded-lg cursor-pointer transition-all ${isSelected
                                        ? 'bg-primary/10 border border-primary/30'
                                        : 'bg-background/50 border border-border/50 hover:border-gray-600'
                                        }`}
                                >
                                    <Server className={`w-3.5 h-3.5 shrink-0 ${isSelected ? 'text-primary' : 'text-gray-500'}`} />
                                    <div className="flex-1 min-w-0">
                                        <div className={`text-[10px] truncate ${isSelected ? 'text-white font-semibold' : 'text-gray-300'}`}>
                                            {ep.entity_id.slice(0, 14)}…
                                        </div>
                                        <div className="text-[9px] text-gray-500 uppercase">{ep.metadata?.type || 'device'}</div>
                                    </div>
                                    <div className="flex flex-col items-end gap-0.5">
                                        <span className="text-[11px] font-mono font-bold" style={{ color: trustColor(ep.trust_score) }}>
                                            {ep.trust_score.toFixed(0)}
                                        </span>
                                        <span className={`w-1.5 h-1.5 rounded-full`} style={{ backgroundColor: trustColor(ep.trust_score) }} />
                                    </div>
                                </div>
                            );
                        })}
                        {(!entities || entities.length === 0) && (
                            <div className="text-center py-8 text-xs text-gray-500 italic">
                                Waiting for devices...
                            </div>
                        )}
                    </div>
                </div>

                {/* CENTER — Pipeline + Charts */}
                <div className="flex-1 overflow-y-auto px-4 py-3 space-y-4">

                    {/* Trust Score Timeline */}
                    <div className="soc-card">
                        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                            <Activity className="w-3.5 h-3.5 text-primary" />
                            Trust Score Timeline
                            <span className="text-gray-600 normal-case font-normal">({detail?.trust_history?.length ?? 0} points)</span>
                        </h3>
                        <div className="h-[120px]">
                            {(detail?.trust_history?.length ?? 0) > 1 ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <AreaChart data={detail!.trust_history}>
                                        <defs>
                                            <linearGradient id="trustGrad" x1="0" y1="0" x2="0" y2="1">
                                                <stop offset="5%" stopColor={trustColor(trust)} stopOpacity={0.3} />
                                                <stop offset="95%" stopColor={trustColor(trust)} stopOpacity={0} />
                                            </linearGradient>
                                        </defs>
                                        <YAxis domain={[0, 100]} hide />
                                        <XAxis dataKey="time" hide />
                                        <Tooltip
                                            contentStyle={{ backgroundColor: '#141414', border: '1px solid #262626', borderRadius: '8px', fontSize: '11px' }}
                                            formatter={(v: number) => [`${v.toFixed(1)}`, 'Trust']}
                                            labelFormatter={() => ''}
                                        />
                                        <Area type="monotone" dataKey="score" stroke={trustColor(trust)} fill="url(#trustGrad)" strokeWidth={2} dot={false} isAnimationActive={false} />
                                    </AreaChart>
                                </ResponsiveContainer>
                            ) : (
                                <div className="h-full flex items-center justify-center text-xs text-gray-500 italic">
                                    Accumulating trust data… (warmup period)
                                </div>
                            )}
                        </div>
                    </div>

                    {/* ML Anomaly + Risk side by side */}
                    <div className="grid grid-cols-2 gap-4">
                        <div className="soc-card">
                            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <Brain className="w-3.5 h-3.5 text-primary" />
                                ML Anomaly Score
                            </h3>
                            <div className="h-[100px]">
                                {(detail?.anomaly_history?.length ?? 0) > 1 ? (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <AreaChart data={detail!.anomaly_history}>
                                            <defs>
                                                <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                                                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                                </linearGradient>
                                            </defs>
                                            <YAxis domain={[0, 1]} hide />
                                            <XAxis dataKey="time" hide />
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#141414', border: '1px solid #262626', borderRadius: '6px', fontSize: '10px' }}
                                                formatter={(v: number) => [`${(v * 100).toFixed(1)}%`, 'Anomaly']}
                                                labelFormatter={() => ''}
                                            />
                                            <Area type="monotone" dataKey="score" stroke="#ef4444" fill="url(#anomalyGrad)" strokeWidth={1.5} dot={false} isAnimationActive={true} animationDuration={800} />
                                        </AreaChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div className="h-full flex items-center justify-center text-[10px] text-gray-500 italic">Warmup in progress…</div>
                                )}
                            </div>
                        </div>

                        <div className="soc-card">
                            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <AlertTriangle className="w-3.5 h-3.5 text-alert" />
                                Risk Score History
                            </h3>
                            <div className="h-[100px]">
                                {(detail?.risk_history?.length ?? 0) > 1 ? (
                                    <ResponsiveContainer width="100%" height="100%">
                                        <BarChart data={detail!.risk_history}>
                                            <YAxis domain={[0, 100]} hide />
                                            <XAxis dataKey="time" hide />
                                            <Tooltip
                                                contentStyle={{ backgroundColor: '#141414', border: '1px solid #262626', borderRadius: '6px', fontSize: '10px' }}
                                                formatter={(v: number) => [`${v.toFixed(1)}`, 'Risk']}
                                                labelFormatter={() => ''}
                                            />
                                            <Bar dataKey="score" fill="#f97316" radius={[2, 2, 0, 0]} isAnimationActive={true} animationDuration={800} />
                                        </BarChart>
                                    </ResponsiveContainer>
                                ) : (
                                    <div className="h-full flex items-center justify-center text-[10px] text-gray-500 italic">Awaiting risk events…</div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Pipeline stages */}
                    <div className="soc-card">
                        <h2 className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-3">Processing Pipeline</h2>
                        <div className="space-y-1">
                            {STAGES.map((stage, i) => {
                                const Icon = stage.icon;
                                const isExpanded = expandedStage === i;
                                // stages 0-6 are "active" once we have live data
                                const isActive = isOnline && i < 7;
                                return (
                                    <React.Fragment key={i}>
                                        <div
                                            onClick={() => setExpandedStage(isExpanded ? null : i)}
                                            className={`cursor-pointer rounded-lg border transition-all duration-300 ${isActive ? 'shadow-lg shadow-blue-500/10' : ''}`}
                                            style={{
                                                background: isActive ? 'rgba(59,130,246,0.08)' : 'rgba(255,255,255,0.02)',
                                                borderColor: isActive ? 'rgba(59,130,246,0.3)' : 'rgba(255,255,255,0.05)',
                                                transform: isActive && isExpanded ? 'scale(1.02)' : 'scale(1)',
                                            }}
                                        >
                                            <div className="flex items-center gap-3 px-3 py-2">
                                                <div className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold shrink-0 transition-colors"
                                                    style={{ background: isActive ? 'rgba(59,130,246,0.2)' : 'rgba(255,255,255,0.05)', color: isActive ? '#60a5fa' : '#6b7280' }}>
                                                    {i + 1}
                                                </div>
                                                <Icon className={`w-3.5 h-3.5 shrink-0 transition-colors ${isActive ? (i === 3 ? 'animate-pulse text-red-400' : 'text-blue-400') : 'text-gray-600'}`} />
                                                <span className="text-[11px] font-semibold flex-1 transition-colors" style={{ color: isActive ? '#e0e7ff' : '#6b7280' }}>{stage.name}</span>
                                                {isActive && <span className="w-1.5 h-1.5 rounded-full bg-success animate-ping" />}
                                                {i === 7 && <span className="text-[9px] text-gray-500 px-1.5 py-0.5 rounded border border-gray-700 bg-gray-800/50">SIM</span>}
                                                {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-gray-400" /> : <ChevronRight className="w-3.5 h-3.5 text-gray-600" />}
                                            </div>
                                            {isExpanded && (
                                                <div className="px-4 pb-3 pt-1 border-t border-border/20 text-[11px] text-gray-400 leading-relaxed animate-in fade-in slide-in-from-top-1 duration-200">
                                                    {stage.desc}
                                                </div>
                                            )}
                                        </div>
                                        {i < STAGES.length - 1 && (
                                            <div className="flex justify-center py-0.5">
                                                <div className={`w-0.5 h-3 rounded-full ${isActive ? 'bg-gradient-to-b from-blue-500 to-transparent opacity-80' : 'bg-gray-800'}`} />
                                            </div>
                                        )}
                                    </React.Fragment>
                                );
                            })}
                        </div>
                    </div>
                </div>

                {/* RIGHT — Metrics panel */}
                <div className="w-[260px] shrink-0 border-l border-border bg-card/50 p-3 flex flex-col gap-4 overflow-y-auto">
                    <h2 className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Real-Time Metrics</h2>

                    {/* Trust score big number */}
                    <div className="p-4 rounded-xl bg-background/50 border border-border/50 text-center">
                        <p className="text-[10px] text-gray-500 uppercase font-semibold mb-2">Trust Score</p>
                        <p className="text-4xl font-black font-mono" style={{ color: trustColor(trust) }}>{trust.toFixed(1)}</p>
                        <div className="w-full bg-white/5 h-2 rounded-full mt-3 overflow-hidden">
                            <div className="h-full rounded-full transition-all duration-500" style={{ width: `${trust}%`, backgroundColor: trustColor(trust) }} />
                        </div>
                        <p className="text-[10px] text-gray-500 mt-2 uppercase font-semibold">{detail?.decision ?? '...'}</p>
                    </div>

                    {/* Confidence */}
                    <div className="p-3 rounded-xl bg-background/50 border border-border/50 text-center">
                        <p className="text-[10px] text-gray-500 uppercase mb-1">Inference Confidence</p>
                        <p className="text-2xl font-bold text-white">{detail?.confidence ?? 100}%</p>
                    </div>

                    {/* Category Risk gauges — I/C/V/N */}
                    <div className="p-3 rounded-xl bg-background/50 border border-border/50 space-y-3">
                        <p className="text-[10px] text-gray-500 uppercase font-semibold">Category Risk (I/C/V/N)</p>
                        <RiskGauge label="Network (N)" value={detail?.category_risks?.N ?? 0} icon={Network} color={riskColor(detail?.category_risks?.N ?? 0)} />
                        <RiskGauge label="Identity (I)" value={detail?.category_risks?.I ?? 0} icon={User} color={riskColor(detail?.category_risks?.I ?? 0)} />
                        <RiskGauge label="Cloud (C)" value={detail?.category_risks?.C ?? 0} icon={Cloud} color={riskColor(detail?.category_risks?.C ?? 0)} />
                        <RiskGauge label="Hardware (V)" value={detail?.category_risks?.V ?? 0} icon={HardDrive} color={riskColor(detail?.category_risks?.V ?? 0)} />
                    </div>

                    {/* Device metadata */}
                    {detail?.metadata && (
                        <div className="p-3 rounded-xl bg-background/50 border border-border/50 space-y-2">
                            <p className="text-[10px] text-gray-500 uppercase font-semibold">Device Info</p>
                            {detail.metadata.hostname && <div className="flex justify-between text-[10px]"><span className="text-gray-500">Hostname</span><span className="text-white font-mono truncate max-w-[130px]">{detail.metadata.hostname}</span></div>}
                            {detail.metadata.ip && <div className="flex justify-between text-[10px]"><span className="text-gray-500">IP</span><span className="text-white font-mono">{detail.metadata.ip}</span></div>}
                            {detail.metadata.mac && <div className="flex justify-between text-[10px]"><span className="text-gray-500">MAC</span><span className="text-white font-mono truncate max-w-[130px]">{detail.metadata.mac}</span></div>}
                            {detail.metadata.os && <div className="flex justify-between text-[10px]"><span className="text-gray-500">OS</span><span className="text-white">{detail.metadata.os}</span></div>}
                            <div className="flex justify-between text-[10px]"><span className="text-gray-500">Type</span><span className="text-white uppercase">{detail.metadata.type}</span></div>
                        </div>
                    )}

                    {/* ML warmup notice */}
                    {(detail?.trust_history?.length ?? 0) < 10 && (
                        <div className="p-3 rounded-xl border border-dashed border-yellow-500/20 bg-yellow-500/5">
                            <p className="text-[10px] text-yellow-400/80 font-semibold mb-1">⏳ ML Warmup</p>
                            <p className="text-[9px] text-gray-500 leading-relaxed">
                                Device needs ~10 events before ML baselines are established. Trust defaults to 80 during warmup.
                            </p>
                            <div className="mt-2 h-1 bg-white/5 rounded-full overflow-hidden">
                                <div className="h-full bg-yellow-500/60 rounded-full transition-all" style={{ width: `${Math.min(100, ((detail?.trust_history?.length ?? 0) / 10) * 100)}%` }} />
                            </div>
                            <p className="text-[9px] text-gray-600 mt-1">{detail?.trust_history?.length ?? 0}/10 events</p>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
