'use client';

import {
    Network,
    User,
    Cloud,
    Cpu,
    Clock,
    Shield,
    Activity,
    Lock,
    AlertTriangle,
    Zap
} from 'lucide-react';

export default function HowItWorksPage() {
    return (
        <div className="space-y-8 max-w-6xl mx-auto pb-12">
            {/* Header */}
            <div className="flex items-center gap-4 mb-8">
                <div className="p-3 rounded-xl bg-primary/20 border border-primary/30">
                    <Activity className="w-8 h-8 text-primary" />
                </div>
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">How GUARDIENT Works</h1>
                    <p className="text-gray-400">
                        Transparent, mathematical trust evaluation based on agentless detection, clear formulas, and automated response.
                    </p>
                </div>
            </div>

            {/* Pipeline Steps */}
            <section>
                <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2">
                    <Shield className="w-5 h-5 text-primary" />
                    The TrustScore Pipeline
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    {[
                        {
                            step: "01",
                            title: "Signal Collection",
                            desc: "Agentless gathering of network, identity, and cloud telemetry.",
                            icon: Network
                        },
                        {
                            step: "02",
                            title: "Event Detection",
                            desc: "Analysis & classification of raw events into severity levels (0.0-1.0).",
                            icon: SearchIcon
                        },
                        {
                            step: "03",
                            title: "Risk Calculation",
                            desc: "Grouping events into 5 categories and calculating risk scores.",
                            icon: Calculator
                        },
                        {
                            step: "04",
                            title: "Aggregation",
                            desc: "Weighted combination of category risks based on impact.",
                            icon: Layers
                        },
                        {
                            step: "05",
                            title: "TrustScore",
                            desc: "Final score generation with temporal smoothing (0-100 scale).",
                            icon: Shield
                        }
                    ].map((item, i) => (
                        <div key={i} className="bg-white/5 border border-white/10 rounded-xl p-4 relative overflow-hidden group hover:border-primary/50 transition-all">
                            <div className="absolute top-0 right-0 p-2 opacity-10 text-4xl font-black">{item.step}</div>
                            <div className="mb-3 p-2 bg-primary/10 rounded-lg w-fit text-primary">
                                <item.icon className="w-5 h-5" />
                            </div>
                            <h3 className="font-bold text-white mb-1.5 text-sm">{item.title}</h3>
                            <p className="text-xs text-gray-400 leading-relaxed">{item.desc}</p>
                        </div>
                    ))}
                </div>
            </section>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Risk Categories */}
                <section className="bg-white/5 border border-white/10 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4">Risk Signal Categories</h3>
                    <div className="overflow-hidden rounded-lg border border-white/10">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-white/5 text-gray-400 font-semibold uppercase text-xs">
                                <tr>
                                    <th className="px-4 py-3">Category</th>
                                    <th className="px-4 py-3">Weight</th>
                                    <th className="px-4 py-3">Signals</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5 text-gray-300">
                                <tr>
                                    <td className="px-4 py-3 flex items-center gap-2">
                                        <Network className="w-4 h-4 text-blue-400" /> Network
                                    </td>
                                    <td className="px-4 py-3 font-mono text-blue-400">30%</td>
                                    <td className="px-4 py-3 text-xs text-gray-500">C2, unusual ports, beaconing</td>
                                </tr>
                                <tr>
                                    <td className="px-4 py-3 flex items-center gap-2">
                                        <User className="w-4 h-4 text-purple-400" /> Identity
                                    </td>
                                    <td className="px-4 py-3 font-mono text-purple-400">25%</td>
                                    <td className="px-4 py-3 text-xs text-gray-500">Imposs. travel, brute force</td>
                                </tr>
                                <tr>
                                    <td className="px-4 py-3 flex items-center gap-2">
                                        <Cloud className="w-4 h-4 text-orange-400" /> Cloud
                                    </td>
                                    <td className="px-4 py-3 font-mono text-orange-400">20%</td>
                                    <td className="px-4 py-3 text-xs text-gray-500">API anomalies, VM state</td>
                                </tr>
                                <tr>
                                    <td className="px-4 py-3 flex items-center gap-2">
                                        <Cpu className="w-4 h-4 text-emerald-400" /> Hardware
                                    </td>
                                    <td className="px-4 py-3 font-mono text-emerald-400">15%</td>
                                    <td className="px-4 py-3 text-xs text-gray-500">Hypervisor alerts</td>
                                </tr>
                                <tr>
                                    <td className="px-4 py-3 flex items-center gap-2">
                                        <Clock className="w-4 h-4 text-pink-400" /> Temporal
                                    </td>
                                    <td className="px-4 py-3 font-mono text-pink-400">10%</td>
                                    <td className="px-4 py-3 text-xs text-gray-500">Burst activity</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>

                {/* Severity Scale */}
                <section className="bg-white/5 border border-white/10 rounded-xl p-6">
                    <h3 className="text-lg font-bold text-white mb-4">Event Severity Normalization</h3>
                    <div className="space-y-4">
                        {[
                            { score: "0.0", label: "Benign / Expected", color: "bg-success" },
                            { score: "0.2", label: "Slight Anomaly", color: "bg-blue-500" },
                            { score: "0.5", label: "Suspicious", color: "bg-warning" },
                            { score: "0.8", label: "High-risk", color: "bg-orange-500" },
                            { score: "1.0", label: "Confirmed Malicious", color: "bg-critical" }
                        ].map((item, i) => (
                            <div key={i} className="flex items-center gap-4">
                                <div className={`w-12 py-1 rounded text-center text-xs font-bold text-black ${item.color}`}>
                                    {item.score}
                                </div>
                                <div className="text-sm text-gray-300">{item.label}</div>
                            </div>
                        ))}
                    </div>
                </section>
            </div>

            {/* Formulas */}
            <section className="bg-white/5 border border-white/10 rounded-xl p-6">
                <h3 className="text-lg font-bold text-white mb-6">Mathematical Formulas</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                        <h4 className="text-sm font-semibold text-gray-400 uppercase mb-3">Risk Aggregation</h4>
                        <div className="bg-black/40 rounded-lg p-4 font-mono text-xs text-gray-300 leading-relaxed border border-white/5">
                            <span className="text-blue-400">R_total</span> = <br />
                            &nbsp;&nbsp;(0.30 × R_network) +<br />
                            &nbsp;&nbsp;(0.25 × R_identity) +<br />
                            &nbsp;&nbsp;(0.20 × R_cloud) +<br />
                            &nbsp;&nbsp;(0.15 × R_hardware) +<br />
                            &nbsp;&nbsp;(0.10 × R_temporal)
                        </div>
                    </div>
                    <div>
                        <h4 className="text-sm font-semibold text-gray-400 uppercase mb-3">TrustScore Generation</h4>
                        <div className="bg-black/40 rounded-lg p-4 font-mono text-xs text-gray-300 leading-relaxed border border-white/5">
                            <span className="text-primary">TrustScore</span> = 100 × (1 - R_total)<br /><br />
                            <span className="text-gray-500"># Result is clamped [0, 100]</span><br />
                            <span className="text-gray-500"># Higher score = More trusted</span>
                        </div>
                    </div>
                </div>
            </section>

            {/* Response Thresholds */}
            <section>
                <h3 className="text-lg font-bold text-white mb-6">Automated Response Thresholds</h3>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                    {[
                        { range: "80-100", label: "Trusted", action: "Normal Monitoring", color: "text-success border-success/30 bg-success/10" },
                        { range: "60-79", label: "Monitor", action: "Increased Telemetry", color: "text-warning border-warning/30 bg-warning/10" },
                        { range: "40-59", label: "Alert", action: "Notify SOC Team", color: "text-orange-500 border-orange-500/30 bg-orange-500/10" },
                        { range: "20-39", label: "Isolate", action: "Network Isolation", color: "text-red-500 border-red-500/30 bg-red-500/10" },
                        { range: "0-19", label: "Emergency", action: "Full Containment", color: "text-critical border-critical/30 bg-critical/10" }
                    ].map((item, i) => (
                        <div key={i} className={`p-4 rounded-xl border flex flex-col items-center text-center ${item.color}`}>
                            <div className="text-2xl font-black mb-1">{item.range}</div>
                            <div className="font-bold uppercase text-xs mb-2">{item.label}</div>
                            <div className="text-[10px] opacity-80">{item.action}</div>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
}

// Component Imports
function SearchIcon(props: any) {
    return (
        <svg
            {...props}
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
        >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.3-4.3" />
        </svg>
    );
}

function Calculator(props: any) {
    return (
        <svg
            {...props}
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
        >
            <rect width="16" height="20" x="4" y="2" rx="2" />
            <line x1="8" x2="16" y1="6" y2="6" />
            <line x1="16" x2="16" y1="14" y2="18" />
            <path d="M16 10h.01" />
            <path d="M12 10h.01" />
            <path d="M8 10h.01" />
            <path d="M12 14h.01" />
            <path d="M8 14h.01" />
            <path d="M12 18h.01" />
            <path d="M8 18h.01" />
        </svg>
    );
}

function Layers(props: any) {
    return (
        <svg
            {...props}
            xmlns="http://www.w3.org/2000/svg"
            width="24"
            height="24"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
        >
            <path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83Z" />
            <path d="m22 17.65-9.17 4.16a2 2 0 0 1-1.66 0L2 17.65" />
            <path d="m22 12.65-9.17 4.16a2 2 0 0 1-1.66 0L2 12.65" />
        </svg>
    );
}
