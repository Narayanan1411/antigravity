'use client';

import { useState, useEffect, useRef } from 'react';
import {
    ShieldAlert, Play, Square, Activity, Terminal,
    Target, Zap, ChevronRight, Clock, AlertTriangle,
} from 'lucide-react';
import {
    LineChart, Line, XAxis, YAxis, CartesianGrid,
    Tooltip, ResponsiveContainer, ReferenceLine,
} from 'recharts';
import { usePolling } from '@/hooks/usePolling';

// ── Types ─────────────────────────────────────────────────────────────────────

interface DeviceItem {
    device_id: string;
    hostname:  string;
    device_type: string;
    last_seen?: string;
}

interface TrajectoryPoint {
    round:          number;
    time:           number;
    score:          number;
    decision:       string;
    active_signals: string[];
}

interface TriggeredExecution {
    action:       string;
    at_trust:     number;
    execution_id: string;
    status:       string;
}

interface SimResult {
    run_id:                string;
    device_id:             string;
    hostname:              string;
    attack_type:           string;
    profile:               { name: string; description: string; severity: string };
    trajectory:            TrajectoryPoint[];
    triggered_executions:  TriggeredExecution[];
    interval_ms:           number;
}

interface ResponseExecution {
    execution_id:      string;
    device_id:         string;
    action:            string;
    status:            string;
    triggered_by:      string;
    trust_score:       number | null;
    severity:          string | null;
    requires_approval: boolean;
    created_at:        string;
}

// ── Online detection ──────────────────────────────────────────────────────────

const ONLINE_MS = 5 * 60 * 1000;
function isOnline(lastSeen?: string): boolean {
    return !!lastSeen && Date.now() - new Date(lastSeen).getTime() < ONLINE_MS;
}

// ── Static config ─────────────────────────────────────────────────────────────

const ATTACK_TYPES = [
    {
        id:       'c2_beaconing',
        label:    'C2 Beaconing',
        desc:     'DNS tunneling + periodic HTTPS beacons to C2 server',
        severity: 'HIGH',
        color:    'text-alert border-alert/40 bg-alert/10',
        triggers: ['require_mfa', 'restrict_network', 'firewall_block'],
        signals:  ['network'],
    },
    {
        id:       'credential_abuse',
        label:    'Credential Abuse',
        desc:     'Repeated login failures + privilege escalation',
        severity: 'HIGH',
        color:    'text-alert border-alert/40 bg-alert/10',
        triggers: ['require_mfa', 'restrict_network', 'lock_account'],
        signals:  ['identity'],
    },
    {
        id:       'lateral_movement',
        label:    'Lateral Movement',
        desc:     'SSH pivoting across internal network segments',
        severity: 'CRITICAL',
        color:    'text-critical border-critical/40 bg-critical/10',
        triggers: ['require_mfa', 'restrict_network', 'isolate_vlan'],
        signals:  ['network', 'cloud'],
    },
    {
        id:       'ransomware_activity',
        label:    'Ransomware Activity',
        desc:     'High CPU, mass file encryption, shadow copy deletion',
        severity: 'CRITICAL',
        color:    'text-critical border-critical/40 bg-critical/10',
        triggers: ['require_mfa', 'restrict_network', 'kill_process'],
        signals:  ['hardware', 'identity'],
    },
] as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(s: number) {
    if (s >= 70) return '#22c55e';
    if (s >= 40) return '#eab308';
    if (s >= 20) return '#f97316';
    return '#ef4444';
}

function decisionClass(d: string) {
    return ({
        trusted:   'text-success   border-success/40   bg-success/10',
        monitor:   'text-warning   border-warning/40   bg-warning/10',
        isolate:   'text-alert     border-alert/40     bg-alert/10',
        emergency: 'text-critical  border-critical/40  bg-critical/10',
    } as Record<string, string>)[d] ?? 'text-gray-400 border-gray-600 bg-gray-600/10';
}

function statusClass(s: string) {
    return ({
        pending:  'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
        running:  'text-blue-400   border-blue-500/40   bg-blue-500/10',
        success:  'text-green-400  border-green-500/40  bg-green-500/10',
        failed:   'text-red-400    border-red-500/40    bg-red-500/10',
        rejected: 'text-gray-400   border-gray-500/40   bg-gray-500/10',
    } as Record<string, string>)[s] ?? 'text-gray-400 border-gray-600 bg-gray-600/10';
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function SimulationPage() {
    const [selectedDevice, setSelectedDevice] = useState('');
    const [attackType,     setAttackType]     = useState<string>(ATTACK_TYPES[0].id);
    const [simResult,      setSimResult]      = useState<SimResult | null>(null);
    const [isRunning,      setIsRunning]      = useState(false);
    const [currentRound,   setCurrentRound]   = useState(0);
    const [log,            setLog]            = useState<{ text: string; type: 'info' | 'action' | 'ok' | 'err' | 'dim' }[]>([]);

    const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const logRef   = useRef<HTMLDivElement>(null);

    // Real device list — only pipeline-processed devices (filtered server-side)
    const { data: devices } = usePolling<DeviceItem[]>('/devices', 15000);

    // Poll response executions — only while a simulation has been started
    const { data: allExecs } = usePolling<ResponseExecution[]>(
        simResult ? '/response/executions?limit=100' : null,
        2000,
    );

    // Filter to just this run's executions (tagged triggered_by="sim:<run_id>:...")
    const simExecs = (allExecs ?? []).filter(
        e => simResult && e.triggered_by.includes(simResult.run_id),
    );

    // Visible trajectory slice for the chart
    const visiblePoints = (simResult?.trajectory ?? []).slice(0, currentRound + 1);
    const latestPoint   = visiblePoints[visiblePoints.length - 1];
    const currentScore  = latestPoint?.score ?? 100;

    const profile = ATTACK_TYPES.find(a => a.id === attackType) ?? ATTACK_TYPES[0];

    // ── Log helpers ───────────────────────────────────────────────────────────
    const addLog = (text: string, type: 'info' | 'action' | 'ok' | 'err' | 'dim' = 'info') =>
        setLog(prev => [...prev.slice(-29), { text, type }]);

    // Auto-scroll log
    useEffect(() => {
        if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    }, [log]);

    // ── Animation loop ────────────────────────────────────────────────────────
    useEffect(() => {
        if (!simResult || !isRunning) return;

        setCurrentRound(0);
        let round = 0;
        const total = simResult.trajectory.length;

        timerRef.current = setInterval(() => {
            round += 1;
            setCurrentRound(round);

            const pt = simResult.trajectory[round];
            if (pt) {
                const sigStr = pt.active_signals.length ? pt.active_signals.join(', ') : 'baseline';
                addLog(`[T+${round * 3}s] trust=${pt.score.toFixed(1)}  decision=${pt.decision.toUpperCase()}  signals=[${sigStr}]`, 'dim');
            }

            // Announce action triggers as they hit thresholds
            simResult.triggered_executions.forEach(te => {
                if (pt && Math.abs(pt.score - te.at_trust) < 8 && round > 0) {
                    addLog(`⚡ TRIGGERED: ${te.action.replace(/_/g, ' ').toUpperCase()}  (trust=${te.at_trust.toFixed(1)})`, 'action');
                }
            });

            if (round >= total - 1) {
                clearInterval(timerRef.current!);
                setIsRunning(false);
                addLog('✓ Simulation complete — check Response Center for pending approvals', 'ok');
            }
        }, simResult.interval_ms);

        return () => { if (timerRef.current) clearInterval(timerRef.current); };
    }, [simResult]);                    // eslint-disable-line react-hooks/exhaustive-deps

    // ── Actions ───────────────────────────────────────────────────────────────
    const startSim = async () => {
        if (!selectedDevice || isRunning) return;
        setSimResult(null);
        setCurrentRound(0);
        setLog([]);
        setIsRunning(true);

        const devName = devices?.find(d => d.device_id === selectedDevice)?.hostname ?? selectedDevice.slice(0, 12);
        addLog(`▶ Launching ${profile.label} against ${devName}...`, 'info');

        try {
            const res = await fetch('/api/v1/simulation/run', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ device_id: selectedDevice, attack_type: attackType }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: res.statusText }));
                addLog(`✗ ${err.detail ?? 'Simulation failed'}`, 'err');
                setIsRunning(false);
                return;
            }
            const result: SimResult = await res.json();
            setSimResult(result);
            addLog(`✓ Trajectory computed: ${result.trajectory.length} rounds  |  run_id=${result.run_id}`, 'ok');
            addLog(`⚠ ${result.triggered_executions.length} response action(s) queued as pending`, 'action');
        } catch (err) {
            addLog(`✗ Network error: ${String(err)}`, 'err');
            setIsRunning(false);
        }
    };

    const stopSim = () => {
        if (timerRef.current) clearInterval(timerRef.current);
        setIsRunning(false);
        addLog('■ Stopped by user', 'dim');
    };

    const resetSim = () => {
        if (timerRef.current) clearInterval(timerRef.current);
        setIsRunning(false);
        setSimResult(null);
        setCurrentRound(0);
        setLog([]);
    };

    // ── Render ────────────────────────────────────────────────────────────────
    return (
        <div className="space-y-5 max-w-[1600px] mx-auto">

            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                        <ShieldAlert className="w-6 h-6 text-alert" />
                        Attack Simulation Lab
                    </h2>
                    <p className="text-sm text-gray-500 mt-0.5">
                        Isolated sandbox · ML baselines protected · Response system activated
                    </p>
                </div>

                <div className="flex items-center gap-3">
                    {isRunning && (
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/30 animate-pulse">
                            <span className="w-2 h-2 rounded-full bg-red-500" />
                            <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Live</span>
                        </div>
                    )}
                    {simResult && !isRunning && (
                        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/30">
                            <span className="w-2 h-2 rounded-full bg-green-500" />
                            <span className="text-xs font-bold text-green-400 uppercase tracking-wider">Complete</span>
                        </div>
                    )}
                </div>
            </div>

            <div className="grid grid-cols-12 gap-5">

                {/* ── Left control panel ─────────────────────────────────── */}
                <div className="col-span-12 lg:col-span-3 space-y-4">

                    {/* Device selector */}
                    <div className="soc-card space-y-3">
                        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                            <Target className="w-3.5 h-3.5" /> Target Device
                        </h3>
                        <select
                            value={selectedDevice}
                            onChange={e => setSelectedDevice(e.target.value)}
                            disabled={isRunning}
                            className="w-full bg-black/50 border border-border rounded-md px-3 py-2 text-sm text-white outline-none focus:border-primary disabled:opacity-50 appearance-none cursor-pointer"
                        >
                            <option value="">— select device —</option>
                            {(devices ?? []).map(d => {
                                const online = isOnline(d.last_seen);
                                return (
                                    <option key={d.device_id} value={d.device_id}>
                                        {online ? '● ' : '○ '}{d.hostname || d.device_id.slice(0, 16)}{online ? '' : ' (offline)'}
                                    </option>
                                );
                            })}
                        </select>
                        {selectedDevice && (
                            <div className="text-[10px] text-gray-600 font-mono truncate">{selectedDevice}</div>
                        )}
                    </div>

                    {/* Attack type */}
                    <div className="soc-card space-y-2">
                        <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2">
                            <Zap className="w-3.5 h-3.5" /> Attack Scenario
                        </h3>
                        {ATTACK_TYPES.map(atk => (
                            <label
                                key={atk.id}
                                className={[
                                    'flex items-start gap-2.5 p-2.5 border rounded-md transition-all',
                                    isRunning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer',
                                    attackType === atk.id
                                        ? 'bg-primary/10 border-primary/50'
                                        : 'bg-black/20 border-border hover:border-white/20',
                                ].join(' ')}
                            >
                                <input
                                    type="radio"
                                    name="attack"
                                    value={atk.id}
                                    checked={attackType === atk.id}
                                    onChange={e => setAttackType(e.target.value)}
                                    disabled={isRunning}
                                    className="mt-0.5 shrink-0"
                                />
                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-1.5 flex-wrap">
                                        <span className="text-sm font-medium text-white">{atk.label}</span>
                                        <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${atk.color}`}>
                                            {atk.severity}
                                        </span>
                                    </div>
                                    <div className="text-xs text-gray-500 mt-0.5 leading-4">{atk.desc}</div>
                                </div>
                            </label>
                        ))}
                    </div>

                    {/* Expected response chain */}
                    <div className="soc-card space-y-2">
                        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                            Expected Response Chain
                        </h3>
                        {profile.triggers.map((t, i) => (
                            <div key={t} className="flex items-center gap-2 text-xs">
                                <span className="w-4 h-4 flex items-center justify-center rounded-full bg-white/5 border border-white/10 text-[9px] font-bold text-gray-400 shrink-0">{i + 1}</span>
                                <ChevronRight className="w-3 h-3 text-gray-600 shrink-0" />
                                <span className="font-mono text-gray-300">{t}</span>
                            </div>
                        ))}
                        <p className="text-[10px] text-gray-600 pt-1 leading-4">
                            Hard containment actions require SOC approval in the Response Center.
                        </p>
                    </div>

                    {/* Buttons */}
                    <div className="flex flex-col gap-2">
                        {!isRunning ? (
                            <button
                                onClick={startSim}
                                disabled={!selectedDevice}
                                className="flex items-center justify-center gap-2 w-full py-2.5 rounded-md font-semibold text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed bg-alert hover:bg-alert/80 text-white shadow-[0_0_20px_rgba(234,88,12,0.25)]"
                            >
                                <Play className="w-4 h-4 fill-current" />
                                Launch Simulation
                            </button>
                        ) : (
                            <button
                                onClick={stopSim}
                                className="flex items-center justify-center gap-2 w-full py-2.5 rounded-md font-semibold text-sm bg-red-700 hover:bg-red-600 text-white"
                            >
                                <Square className="w-4 h-4 fill-current" />
                                Stop
                            </button>
                        )}
                        <button
                            onClick={resetSim}
                            disabled={isRunning || (!simResult && log.length === 0)}
                            className="flex items-center justify-center gap-1.5 w-full py-2 rounded-md text-sm border border-border hover:border-white/20 text-gray-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                        >
                            Reset
                        </button>
                    </div>

                    {/* Isolation notice */}
                    <div className="flex items-start gap-2 p-3 rounded-md bg-emerald-500/5 border border-emerald-500/20">
                        <AlertTriangle className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                        <p className="text-[10px] text-emerald-600 leading-4">
                            Simulation is sandboxed. No events are written to the ML pipeline.
                            Entity, Audit, and Trust pages display real data only.
                        </p>
                    </div>
                </div>

                {/* ── Right live view ─────────────────────────────────────── */}
                <div className="col-span-12 lg:col-span-9 space-y-4">

                    {/* Trust score chart */}
                    <div className="soc-card">
                        <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-3">
                                <Activity className="w-4 h-4 text-primary" />
                                <span className="font-semibold text-sm">Simulated Trust Score</span>
                                {simResult && (
                                    <span className="text-xs text-gray-500">
                                        {simResult.hostname} · {simResult.profile.name}
                                    </span>
                                )}
                            </div>
                            <div className="flex items-center gap-3">
                                {latestPoint && (
                                    <span className={`px-2 py-0.5 text-[10px] font-bold uppercase rounded border ${decisionClass(latestPoint.decision)}`}>
                                        {latestPoint.decision}
                                    </span>
                                )}
                                <span className="text-3xl font-bold font-mono transition-colors duration-500"
                                    style={{ color: scoreColor(currentScore) }}>
                                    {currentScore.toFixed(1)}
                                </span>
                            </div>
                        </div>

                        <div className="h-52 bg-black/20 rounded-lg border border-border/50 p-2">
                            {simResult ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <LineChart data={visiblePoints}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#1a1a1a" vertical={false} />
                                        <XAxis
                                            dataKey="round"
                                            tickFormatter={r => `T+${Number(r) * 3}s`}
                                            stroke="#333"
                                            fontSize={10}
                                            tickLine={false}
                                        />
                                        <YAxis
                                            domain={[0, 100]}
                                            stroke="#333"
                                            fontSize={10}
                                            tickLine={false}
                                            axisLine={false}
                                            width={28}
                                        />
                                        <Tooltip
                                            contentStyle={{ backgroundColor: '#0a0a0a', border: '1px solid #262626', borderRadius: '8px', fontSize: '12px' }}
                                            formatter={(v: number) => [v.toFixed(1), 'Trust']}
                                            labelFormatter={r => `T+${Number(r) * 3}s`}
                                        />
                                        <ReferenceLine y={70} stroke="#f97316" strokeDasharray="4 2"
                                            label={{ value: 'MFA', fill: '#f97316', fontSize: 10, position: 'insideTopRight' }} />
                                        <ReferenceLine y={40} stroke="#dc2626" strokeDasharray="4 2"
                                            label={{ value: 'Restrict', fill: '#dc2626', fontSize: 10, position: 'insideTopRight' }} />
                                        <ReferenceLine y={20} stroke="#7f1d1d" strokeDasharray="4 2"
                                            label={{ value: 'Contain', fill: '#ef4444', fontSize: 10, position: 'insideTopRight' }} />
                                        <Line
                                            type="monotone"
                                            dataKey="score"
                                            stroke={scoreColor(currentScore)}
                                            strokeWidth={2.5}
                                            dot={{ r: 3, fill: scoreColor(currentScore), strokeWidth: 0 }}
                                            activeDot={{ r: 5, stroke: '#fff', strokeWidth: 1.5 }}
                                            isAnimationActive={false}
                                        />
                                    </LineChart>
                                </ResponsiveContainer>
                            ) : (
                                <div className="h-full flex flex-col items-center justify-center gap-2 text-gray-700">
                                    <Activity className="w-8 h-8 opacity-30" />
                                    <span className="text-sm">Select a device and launch a simulation</span>
                                </div>
                            )}
                        </div>

                        {/* Progress bar */}
                        {simResult && (
                            <div className="flex items-center gap-3 mt-3">
                                <Clock className="w-3 h-3 text-gray-600" />
                                <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-primary transition-all duration-300"
                                        style={{ width: `${(currentRound / Math.max(simResult.trajectory.length - 1, 1)) * 100}%` }}
                                    />
                                </div>
                                <span className="text-[10px] text-gray-600 font-mono w-14 text-right">
                                    {currentRound}/{simResult.trajectory.length - 1}
                                </span>
                            </div>
                        )}
                    </div>

                    {/* Response actions + log */}
                    <div className="grid grid-cols-2 gap-4">

                        {/* Response actions panel */}
                        <div className="soc-card flex flex-col" style={{ height: '280px' }}>
                            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2 pb-2 border-b border-border mb-3">
                                <ShieldAlert className="w-3.5 h-3.5 text-critical" />
                                Response Actions Triggered
                                {simExecs.length > 0 && (
                                    <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-white/5 border border-white/10 text-gray-400">
                                        {simExecs.length}
                                    </span>
                                )}
                            </h3>
                            <div className="flex-1 overflow-auto space-y-2 pr-0.5">
                                {simExecs.length > 0 ? (
                                    simExecs.map(ex => (
                                        <div key={ex.execution_id}
                                            className="flex items-start justify-between p-2.5 bg-black/30 border border-white/5 rounded-md gap-2">
                                            <div className="min-w-0">
                                                <div className="font-mono text-xs font-bold text-white">
                                                    {ex.action.replace(/_/g, ' ').toUpperCase()}
                                                </div>
                                                <div className="text-[10px] text-gray-600 mt-0.5 font-mono">
                                                    trust={ex.trust_score?.toFixed(1) ?? '—'}
                                                </div>
                                            </div>
                                            <div className="flex flex-col items-end gap-1 shrink-0">
                                                <span className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase ${statusClass(ex.status)}`}>
                                                    {ex.status}
                                                </span>
                                                {ex.requires_approval && ex.status === 'pending' && (
                                                    <span className="text-[9px] text-yellow-600">↗ Needs SOC approval</span>
                                                )}
                                            </div>
                                        </div>
                                    ))
                                ) : simResult ? (
                                    <div className="h-full flex items-center justify-center">
                                        <span className="text-xs text-gray-600 animate-pulse">
                                            Waiting for actions to register…
                                        </span>
                                    </div>
                                ) : (
                                    <div className="h-full flex items-center justify-center text-xs text-gray-700">
                                        Actions appear here once simulation starts
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Terminal log */}
                        <div className="soc-card flex flex-col bg-black/70" style={{ height: '280px' }}>
                            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider flex items-center gap-2 pb-2 border-b border-border mb-3">
                                <Terminal className="w-3.5 h-3.5 text-primary" />
                                Simulation Log
                            </h3>
                            <div ref={logRef}
                                className="flex-1 overflow-auto space-y-0.5 pr-0.5 font-mono text-[11px] leading-5">
                                {log.length > 0 ? log.map((line, i) => (
                                    <div key={i} className={{
                                        action: 'text-alert',
                                        ok:     'text-success',
                                        err:    'text-critical',
                                        info:   'text-gray-300',
                                        dim:    'text-gray-600',
                                    }[line.type]}>
                                        {line.text}
                                    </div>
                                )) : (
                                    <div className="text-gray-700 italic">Awaiting simulation…</div>
                                )}
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
}
