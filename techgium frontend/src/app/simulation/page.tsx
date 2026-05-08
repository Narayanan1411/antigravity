'use client';

import { useState } from 'react';
import { ShieldAlert, Play, RotateCcw, Activity, XCircle, Target } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import { usePolling } from '@/hooks/usePolling';

interface DeviceList {
    device_id: string;
    hostname: string;
    device_type: string;
}

export default function SimulationPage() {
    const [selectedDevice, setSelectedDevice] = useState<string>('');
    const [attackType, setAttackType] = useState<string>('c2_beaconing');
    const [isSimulating, setIsSimulating] = useState(false);
    const [activeRunId, setActiveRunId] = useState<string | null>(null);

    // Poll devices list slowly
    const { data: devices } = usePolling<DeviceList[]>('/devices', 10000);

    // Poll selected device fast (every 2s) to show live chart during simulation
    const { data: entityDetail } = usePolling<any>(
        selectedDevice ? `/entities/${selectedDevice}` : null,
        2000
    );

    // Poll response actions occasionally
    const { data: actions } = usePolling<any[]>('/response/actions', 3000);

    const startSimulation = async () => {
        if (!selectedDevice) return;
        setIsSimulating(true);

        try {
            // Simulation Controller runs on port 8001
            const res = await fetch('http://localhost:8001/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device_id: selectedDevice,
                    attack_type: attackType,
                    rounds: 5,
                    interval_sec: 3
                })
            });
            const data = await res.json();
            setActiveRunId(data.run_id);

            // Auto-reset UI state after the sim finishes (5 rounds * 3 sec = ~15s + buffer)
            setTimeout(() => setIsSimulating(false), 20000);
        } catch (err) {
            console.error('Failed to start simulation', err);
            setIsSimulating(false);
        }
    };

    const resetDevice = async () => {
        if (!selectedDevice) return;
        try {
            await fetch(`http://localhost:8001/simulation/device/${selectedDevice}`, {
                method: 'DELETE'
            });
            setIsSimulating(false);
            setActiveRunId(null);
        } catch (err) {
            console.error('Failed to reset device', err);
        }
    };

    const trustHistory = entityDetail?.trust_history || [];

    return (
        <div className="space-y-6 max-w-7xl mx-auto">
            <div>
                <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                    <Activity className="w-6 h-6 text-alert" />
                    Attack Simulation Engine
                </h2>
                <p className="text-gray-400 mt-1">Safely inject telemetry to validate AI detections and automated containment.</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                {/* Control Panel */}
                <div className="soc-card space-y-6 lg:col-span-1">
                    <h3 className="text-lg font-semibold flex items-center gap-2 border-b border-border pb-3">
                        <Target className="w-5 h-5 text-primary" />
                        Simulation Setup
                    </h3>

                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-1.5">Target Device</label>
                            <select
                                className="w-full bg-black/50 border border-border rounded-md px-3 py-2 text-white outline-none focus:border-primary transition-colors appearance-none"
                                value={selectedDevice}
                                onChange={(e) => setSelectedDevice(e.target.value)}
                            >
                                <option value="">-- Select a device --</option>
                                {devices?.map(d => (
                                    <option key={d.device_id} value={d.device_id}>
                                        {d.hostname} ({d.device_id.substring(0, 8)}...)
                                    </option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-400 mb-1.5">Attack Scenario</label>
                            <div className="space-y-2">
                                {[
                                    { id: 'c2_beaconing', label: 'C2 Beaconing', desc: 'Periodic DNS & HTTPS outbound' },
                                    { id: 'credential_abuse', label: 'Credential Abuse', desc: 'Failed logins & privilege escalation' },
                                    { id: 'lateral_movement', label: 'Lateral Movement', desc: 'SSH jumps to internal servers' },
                                    { id: 'ransomware_activity', label: 'Ransomware', desc: 'High CPU & mass file IO' }
                                ].map(atk => (
                                    <label key={atk.id} className={`flex items-start gap-3 p-3 border rounded-md cursor-pointer transition-all ${attackType === atk.id ? 'bg-primary/10 border-primary/50' : 'bg-black/20 border-border hover:border-white/20'}`}>
                                        <input
                                            type="radio"
                                            name="attack"
                                            value={atk.id}
                                            checked={attackType === atk.id}
                                            onChange={(e) => setAttackType(e.target.value)}
                                            className="mt-1"
                                        />
                                        <div>
                                            <div className="font-medium text-sm text-white">{atk.label}</div>
                                            <div className="text-xs text-gray-500 mt-0.5">{atk.desc}</div>
                                        </div>
                                    </label>
                                ))}
                            </div>
                        </div>

                        <div className="pt-4 flex flex-col gap-3 border-t border-border">
                            <button
                                onClick={startSimulation}
                                disabled={!selectedDevice || isSimulating}
                                className="flex items-center justify-center gap-2 w-full py-2.5 rounded-md font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed bg-alert hover:bg-alert/90 text-white shadow-[0_0_15px_rgba(234,88,12,0.3)]"
                            >
                                <Play className="w-4 h-4 bg-transparent outline-none fill-current" />
                                {isSimulating ? 'Injecting Telemetry...' : 'Start Simulation'}
                            </button>

                            <button
                                onClick={resetDevice}
                                disabled={!selectedDevice}
                                className="flex items-center justify-center gap-2 w-full py-2.5 rounded-md font-medium text-sm transition-all disabled:opacity-50 disabled:cursor-not-allowed bg-black/50 border border-border hover:border-white/20 text-white"
                            >
                                <RotateCcw className="w-4 h-4" />
                                Reset Device to Normal (Trust=100)
                            </button>
                        </div>
                    </div>
                </div>

                {/* Live Timeline & Logs */}
                <div className="lg:col-span-2 space-y-6">

                    <div className="soc-card h-[350px] flex flex-col">
                        <h3 className="text-lg font-semibold flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                                <Activity className="w-5 h-5 text-primary" />
                                Live Trust Score Drop
                            </div>
                            {selectedDevice && (
                                <div className="text-2xl font-bold font-mono">
                                    {entityDetail?.trust_score?.toFixed(1) || '100.0'}
                                </div>
                            )}
                        </h3>

                        <div className="flex-1 min-h-0 bg-black/20 rounded-lg p-2 border border-border">
                            {trustHistory.length > 0 ? (
                                <ResponsiveContainer width="100%" height="100%">
                                    <LineChart data={trustHistory}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#262626" vertical={false} />
                                        <XAxis
                                            dataKey="time"
                                            tickFormatter={(t) => new Date(t).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' })}
                                            stroke="#666"
                                            fontSize={11}
                                            tickLine={false}
                                        />
                                        <YAxis
                                            domain={[0, 100]}
                                            stroke="#666"
                                            fontSize={11}
                                            tickLine={false}
                                            axisLine={false}
                                        />
                                        <Tooltip
                                            contentStyle={{ backgroundColor: '#171717', border: '1px solid #262626', borderRadius: '8px' }}
                                            labelFormatter={(t) => new Date(t).toLocaleTimeString()}
                                        />
                                        <ReferenceLine y={40} stroke="#ea580c" strokeDasharray="3 3" label={{ position: 'insideTopLeft', value: 'MFA Threshold', fill: '#ea580c', fontSize: 11 }} />
                                        <ReferenceLine y={20} stroke="#dc2626" strokeDasharray="3 3" label={{ position: 'insideTopLeft', value: 'Containment Threshold', fill: '#dc2626', fontSize: 11 }} />
                                        <Line
                                            type="stepAfter"
                                            dataKey="score"
                                            stroke="#3b82f6"
                                            strokeWidth={3}
                                            dot={false}
                                            activeDot={{ r: 6, fill: '#3b82f6', stroke: '#fff', strokeWidth: 2 }}
                                            isAnimationActive={false}
                                        />
                                    </LineChart>
                                </ResponsiveContainer>
                            ) : (
                                <div className="h-full flex items-center justify-center text-gray-500 text-sm">
                                    Select a device to view live telemetry
                                </div>
                            )}
                        </div>
                    </div>

                    <div className="soc-card h-[300px] flex flex-col">
                        <h3 className="text-lg font-semibold flex items-center gap-2 border-b border-border pb-3 mb-3">
                            <ShieldAlert className="w-5 h-5 text-critical" />
                            Automated Containment Actions Triggered
                        </h3>
                        <div className="flex-1 overflow-auto space-y-2 pr-2">
                            {actions?.filter(a => activeRunId ? (new Date(a.triggered_at) >= new Date(Date.now() - 60000)) : true)
                                .map(action => (
                                    <div key={action.action_id} className="flex items-center justify-between p-3 bg-critical/5 border border-critical/20 rounded-md">
                                        <div className="flex items-center gap-3">
                                            <XCircle className="w-5 h-5 text-critical" />
                                            <div>
                                                <div className="font-bold text-critical uppercase text-sm tracking-widest">{action.action.replace('_', ' ')}</div>
                                                <div className="text-xs text-gray-400 mt-0.5">Device: {action.device_id.substring(0, 16)}</div>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className="text-xl font-bold text-white font-mono">{action.trust_score.toFixed(1)}</div>
                                            <div className="text-[10px] text-gray-500 uppercase mt-1">{new Date(action.triggered_at).toLocaleTimeString()}</div>
                                        </div>
                                    </div>
                                ))}
                            {(!actions || actions.length === 0) && (
                                <div className="h-full flex items-center justify-center text-gray-500 text-sm">
                                    No automated actions triggered recently
                                </div>
                            )}
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
}
