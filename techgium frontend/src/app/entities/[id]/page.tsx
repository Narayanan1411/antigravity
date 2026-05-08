'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity, AuditLog } from '@/types';
import { approveResponse } from '@/lib/api';
import { useParams, useRouter } from 'next/navigation';
import {
  ArrowLeft,
  Shield,
  Activity,
  History,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Network,
  User,
  Cloud,
  Cpu,
  Clock,
  Info,
  Brain,
  FlaskConical
} from 'lucide-react';
import { useState, useMemo } from 'react';
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  YAxis,
  XAxis,
  Tooltip,
  BarChart,
  Bar,
  Cell
} from 'recharts';

export default function EntityDetailPage() {
  const { id } = useParams();
  const router = useRouter();
  const { data: entities, status } = usePolling<Entity[]>('/entities/');
  const { data: auditLogs } = usePolling<AuditLog[]>('/audit/');
  const [isApproving, setIsApproving] = useState(false);
  const [viewMode, setViewMode] = useState<'latest' | 'history'>('latest');

  const entity = entities?.find(e => e.entity_id === id);
  const entityLogs = auditLogs?.filter(l => l.entity_id === id).sort((a, b) =>
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  // Build trust history chart data from trust_history evaluations
  const trustChartData = useMemo(() => {
    if (!entity?.trust_history) return [];
    return entity.trust_history.map((eval_, i) => ({
      time: i,
      score: eval_.final_trust_score,
    }));
  }, [entity?.trust_history]);

  // Build risk category bar chart data
  const riskBarData = useMemo(() => {
    if (!entity?.trust_evaluation?.trust_evaluation) return [];
    const te = entity.trust_evaluation.trust_evaluation;
    return [
      { name: 'Network', risk: Math.round((te.network?.Rc || 0) * 100), fill: '#3b82f6' },
      { name: 'Identity', risk: Math.round((te.identity?.Rc || 0) * 100), fill: '#8b5cf6' },
      { name: 'Cloud', risk: Math.round((te.cloud?.Rc || 0) * 100), fill: '#06b6d4' },
      { name: 'Hardware', risk: Math.round((te.hardware?.Rc || 0) * 100), fill: '#f59e0b' },
      { name: 'Temporal', risk: Math.round((te.temporal?.Rc || 0) * 100), fill: '#10b981' },
    ];
  }, [entity?.trust_evaluation]);

  if (!entity) {
    return <div className="text-gray-400">Loading entity details...</div>;
  }

  const handleApprove = async (action: string, approved: boolean = true) => {
    if (!confirm(`Are you sure you want to ${approved ? 'approve' : 'reject'} ${action}?`)) return;
    setIsApproving(true);
    try {
      await approveResponse({
        entity_id: entity.entity_id,
        action: action,
        approved: approved,
        approved_by: 'SOC_ANALYST'
      });
    } catch (err) {
      // Silent fail for simulation mode
    } finally {
      setIsApproving(false);
    }
  };

  const showResponsePanel = entity.approval_required;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <button
          onClick={() => router.back()}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Entities
        </button>
      </div>

      {/* Entity Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-xl bg-white/5 border border-white/10 ${getScoreTextColor(entity.trust_score)}`}>
            <Shield className="w-8 h-8" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-3">
              {entity.entity_id}
              <DecisionBadge decision={entity.decision} score={entity.trust_score} />
              {entity.metadata?.owner === 'presenter' && (
                <span className="px-2 py-0.5 rounded bg-primary/20 text-primary text-xs font-bold uppercase border border-primary/30">
                  Presenter Device
                </span>
              )}
            </h2>
            <div className="flex items-center gap-4 text-sm text-gray-500 mt-1">
              {entity.metadata?.ip && (
                <span className="flex items-center gap-1"><Network className="w-3 h-3" /> {entity.metadata.ip}</span>
              )}
              {entity.metadata?.mac && (
                <span className="flex items-center gap-1"><Cpu className="w-3 h-3" /> {entity.metadata.mac}</span>
              )}
              {entity.metadata?.hostname && (
                <span className="flex items-center gap-1"><Shield className="w-3 h-3" /> {entity.metadata.hostname}</span>
              )}
              <span suppressHydrationWarning>Last updated: {new Date(entity.last_updated).toLocaleString()}</span>
            </div>
          </div>
        </div>
        <div className="text-right">
          <div className="text-sm text-gray-400 mb-1 flex items-center justify-end gap-2">
            {entity.trust_evaluation && (
              <span className="flex items-center gap-1 text-[10px]">
                PREV: {entity.trust_evaluation.previous_trust_score}
                {entity.trust_score !== entity.trust_evaluation.previous_trust_score && (
                  <span className={entity.trust_score < entity.trust_evaluation.previous_trust_score ? 'text-critical' : 'text-success'}>
                    ({entity.trust_score < entity.trust_evaluation.previous_trust_score ? '↓' : '↑'}
                    {Math.abs(entity.trust_score - entity.trust_evaluation.previous_trust_score).toFixed(1)})
                  </span>
                )}
              </span>
            )}
            Current TrustScore
          </div>
          <div className={`text-4xl font-black ${getScoreTextColor(entity.trust_score)}`}>
            {entity.trust_score}
          </div>
        </div>
      </div>

      {/* Pending Approval Panel */}
      {showResponsePanel && (
        <div className="bg-critical/10 border border-critical/30 rounded-lg p-6 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-2 bg-critical/20 rounded-full">
              <AlertTriangle className="w-6 h-6 text-critical" />
            </div>
            <div>
              <h4 className="font-bold text-white">Pending SOC Approval Required</h4>
              <p className="text-sm text-gray-400">Entity behavior triggered {entity.decision} state. Confidence: {entity.confidence}%</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => handleApprove('network_isolate')}
              disabled={isApproving}
              className="px-4 py-2 bg-critical text-white rounded-md font-semibold hover:bg-critical/90 transition-colors disabled:opacity-50"
            >
              Isolate Network
            </button>
            <button className="px-4 py-2 bg-white/10 text-white rounded-md font-semibold hover:bg-white/20 transition-colors">
              Dismiss Alert
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">

          {/* Trust Score Chart (live) */}
          {trustChartData.length > 2 && (
            <div className="soc-card">
              <h3 className="font-semibold text-lg mb-4 flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" />
                Trust Score Timeline
              </h3>
              <div className="h-[160px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trustChartData}>
                    <defs>
                      <linearGradient id="entityTrustGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22c55e" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <YAxis domain={[0, 100]} hide />
                    <XAxis dataKey="time" hide />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#141414',
                        border: '1px solid #262626',
                        borderRadius: '8px',
                        fontSize: '12px'
                      }}
                      formatter={(value: number) => [`${value}`, 'TrustScore']}
                    />
                    <Area
                      type="monotone"
                      dataKey="score"
                      stroke="#22c55e"
                      fill="url(#entityTrustGrad)"
                      strokeWidth={2}
                      dot={false}
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* TrustScore Breakdown */}
          <div className="soc-card">
            <div className="flex items-center justify-between mb-6">
              <h3 className="font-semibold text-lg flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary" />
                Explainability: TrustScore Breakdown
              </h3>
              <div className="flex bg-white/5 rounded-lg p-1 border border-white/10">
                <button
                  onClick={() => setViewMode('latest')}
                  className={`px-3 py-1 text-xs rounded-md transition-all ${viewMode === 'latest' ? 'bg-primary text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
                >
                  Latest Evaluation
                </button>
                <button
                  onClick={() => setViewMode('history')}
                  className={`px-3 py-1 text-xs rounded-md transition-all ${viewMode === 'history' ? 'bg-primary text-white shadow-lg' : 'text-gray-400 hover:text-white'}`}
                >
                  History
                </button>
              </div>
            </div>

            {viewMode === 'latest' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="space-y-6">
                  <CategoryScore
                    label="Network Risk"
                    value={(entity.trust_evaluation?.trust_evaluation?.network?.Rc || 0) * 100}
                    delta={entity.trust_evaluation?.trust_evaluation?.network?.delta || 0}
                    signals={entity.trust_evaluation?.trust_evaluation?.network?.signals}
                    icon={Network}
                  />
                  <CategoryScore
                    label="Identity Integrity"
                    value={(entity.trust_evaluation?.trust_evaluation?.identity?.Rc || 0) * 100}
                    delta={entity.trust_evaluation?.trust_evaluation?.identity?.delta || 0}
                    signals={entity.trust_evaluation?.trust_evaluation?.identity?.signals}
                    icon={User}
                  />
                  <CategoryScore
                    label="Cloud Posture"
                    value={(entity.trust_evaluation?.trust_evaluation?.cloud?.Rc || 0) * 100}
                    delta={entity.trust_evaluation?.trust_evaluation?.cloud?.delta || 0}
                    signals={entity.trust_evaluation?.trust_evaluation?.cloud?.signals}
                    icon={Cloud}
                  />
                  <CategoryScore
                    label="Hardware Security"
                    value={(entity.trust_evaluation?.trust_evaluation?.hardware?.Rc || 0) * 100}
                    delta={entity.trust_evaluation?.trust_evaluation?.hardware?.delta || 0}
                    signals={entity.trust_evaluation?.trust_evaluation?.hardware?.signals}
                    icon={Cpu}
                  />
                  <CategoryScore
                    label="Temporal Stability"
                    value={(entity.trust_evaluation?.trust_evaluation?.temporal?.Rc || 0) * 100}
                    delta={entity.trust_evaluation?.trust_evaluation?.temporal?.delta || 0}
                    signals={entity.trust_evaluation?.trust_evaluation?.temporal?.signals}
                    icon={Clock}
                  />
                </div>

                <div className="space-y-6">
                  {/* Confidence Card */}
                  <div className="flex flex-col items-center justify-center p-6 bg-white/5 rounded-xl border border-white/10">
                    <div className="text-sm text-gray-400 mb-2 flex items-center gap-2">
                      Inference Confidence
                      <div className="group relative">
                        <Info className="w-3 h-3 cursor-help" />
                        <div className="hidden group-hover:block absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-2 bg-gray-900 text-xs text-gray-300 rounded border border-white/20 z-10">
                          Inference confidence reflects the reliability of agentless signals and is intentionally conservative, especially for simulated data.
                        </div>
                      </div>
                    </div>
                    <div className="text-5xl font-bold text-white mb-2">{entity.confidence}%</div>
                    <div className="w-full bg-white/10 h-2 rounded-full mt-4 overflow-hidden">
                      <div className="bg-primary h-full transition-all duration-500" style={{ width: `${entity.confidence}%` }} />
                    </div>
                  </div>

                  {/* Risk Bar Chart */}
                  {riskBarData.length > 0 && (
                    <div className="bg-white/5 rounded-xl border border-white/10 p-4">
                      <div className="text-xs text-gray-400 mb-3 font-medium">Risk by Category</div>
                      <div className="h-[140px]">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={riskBarData}>
                            <YAxis domain={[0, 100]} hide />
                            <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#888' }} axisLine={false} tickLine={false} />
                            <Tooltip
                              contentStyle={{
                                backgroundColor: '#141414',
                                border: '1px solid #262626',
                                borderRadius: '8px',
                                fontSize: '11px'
                              }}
                              formatter={(value: number) => [`${value}%`, 'Risk']}
                            />
                            <Bar dataKey="risk" radius={[4, 4, 0, 0]} animationDuration={300}>
                              {riskBarData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.fill} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    </div>
                  )}
                </div>
              </div>

            ) : (
              <div className="space-y-4">
                {entity.trust_history?.slice().reverse().map((evalItem, idx) => (
                  <div key={idx} className="p-4 bg-white/5 rounded-xl border border-white/10 hover:border-white/20 transition-all">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <span className="text-xs font-mono text-gray-500" suppressHydrationWarning>
                          {new Date(evalItem.timestamp).toLocaleTimeString()}
                        </span>
                        <span className={`text-xs font-bold uppercase ${getScoreTextColor(evalItem.final_trust_score)}`}>
                          {evalItem.decision}
                        </span>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <div className="text-[10px] text-gray-500 uppercase">TrustScore</div>
                          <div className={`text-sm font-bold ${getScoreTextColor(evalItem.final_trust_score)}`}>
                            {evalItem.final_trust_score}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="grid grid-cols-5 gap-2">
                      {Object.entries(evalItem.trust_evaluation).map(([cat, data]: [string, any]) => (
                        <div key={cat} className="text-center">
                          <div className="text-[9px] text-gray-500 uppercase truncate">{cat}</div>
                          <div className={`text-xs font-bold ${data.Rc === 0 ? 'text-gray-400' :
                            data.Rc < 0.3 ? 'text-success' :
                              data.Rc < 0.6 ? 'text-warning' :
                                'text-critical'
                            }`}>
                            {Math.round(data.Rc * 100)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
                {(!entity.trust_history || entity.trust_history.length === 0) && (
                  <div className="text-center py-12 text-gray-500 italic">No evaluation history available</div>
                )}
              </div>
            )}
          </div>

          {/* Event Timeline */}
          <div className="soc-card">
            <h3 className="font-semibold text-lg mb-6 flex items-center gap-2">
              <History className="w-5 h-5 text-primary" />
              Event Timeline
              {entityLogs && entityLogs.length > 0 && (
                <span className="text-xs text-gray-500 font-normal">({entityLogs.length} events)</span>
              )}
            </h3>
            <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2">
              {entityLogs?.map((log, i) => (
                <div key={i} className="relative pl-8 pb-4 border-l border-border last:border-0 last:pb-0">
                  <div className="absolute left-[-9px] top-0 w-4 h-4 rounded-full border-2 bg-card border-success" />
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-white">{log.action_type}</span>
                    <span className="text-xs text-gray-500" suppressHydrationWarning>{new Date(log.timestamp).toLocaleString()}</span>
                  </div>
                  <p className="text-sm text-gray-400">{log.reason}</p>
                  <div className="mt-2 flex items-center gap-3">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${log.status === 'success' ? 'bg-success/10 text-success border-success/20' : 'bg-critical/10 text-critical border-critical/20'
                      }`}>
                      {log.status.toUpperCase()}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded border flex items-center gap-1 bg-success/10 text-success border-success/20">
                      REAL
                    </span>
                    {log.approved_by && (
                      <span className="text-[10px] text-gray-500">by {log.approved_by}</span>
                    )}
                  </div>
                </div>
              ))}
              {(!entityLogs || entityLogs.length === 0) && (
                <div className="text-center py-8 text-gray-500 italic">No historical events recorded</div>
              )}
            </div>
          </div>
        </div>

        {/* Right Sidebar */}
        <div className="space-y-6">
          {/* Active Responses */}
          <div className="soc-card">
            <h3 className="font-semibold text-lg mb-4">Active Responses</h3>
            <div className="space-y-3">
              {entity.active_actions.map(action => (
                <div key={action} className="p-3 bg-primary/10 border border-primary/20 rounded-md flex items-center gap-3">
                  <CheckCircle2 className="w-4 h-4 text-primary" />
                  <span className="text-sm text-white font-medium">{action}</span>
                </div>
              ))}
              {entity.active_actions.length === 0 && (
                <div className="p-3 bg-white/5 border border-white/10 rounded-md text-sm text-gray-500 text-center italic">
                  No active measures
                </div>
              )}
            </div>
          </div>

          {/* Entity Metadata */}
          <div className="soc-card">
            <h3 className="font-semibold text-lg mb-4">Device Information</h3>
            <div className="space-y-3 text-sm">
              {entity.metadata?.hostname && (
                <div className="flex justify-between"><span className="text-gray-500">Hostname</span><span className="text-white font-mono">{entity.metadata.hostname}</span></div>
              )}
              {entity.metadata?.ip && (
                <div className="flex justify-between"><span className="text-gray-500">IP Address</span><span className="text-white font-mono">{entity.metadata.ip}</span></div>
              )}
              {entity.metadata?.mac && (
                <div className="flex justify-between"><span className="text-gray-500">MAC Address</span><span className="text-white font-mono">{entity.metadata.mac}</span></div>
              )}
              {entity.metadata?.os && (
                <div className="flex justify-between"><span className="text-gray-500">OS</span><span className="text-white">{entity.metadata.os}</span></div>
              )}
              {entity.metadata?.type && (
                <div className="flex justify-between"><span className="text-gray-500">Type</span><span className="text-white uppercase text-xs">{entity.metadata.type}</span></div>
              )}
            </div>
          </div>

          {/* Category Breakdown (compact) */}
          <div className="soc-card">
            <h3 className="font-semibold text-lg mb-4">Category Breakdown</h3>
            <div className="space-y-3">
              {['network', 'identity', 'cloud', 'hardware', 'temporal'].map(cat => {
                const val = entity.category_breakdown?.[cat as keyof typeof entity.category_breakdown] || 0;
                return (
                  <div key={cat} className="flex items-center gap-3">
                    <span className="text-xs text-gray-400 w-20 capitalize">{cat}</span>
                    <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-500 ${val > 60 ? 'bg-critical' : val > 30 ? 'bg-warning' : 'bg-success'}`}
                        style={{ width: `${Math.max(val, 2)}%` }}
                      />
                    </div>
                    <span className="text-xs font-mono text-white w-8 text-right">{val}%</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function CategoryScore({ label, value, delta, signals, icon: Icon }: any) {
  const isNegative = delta < 0;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs font-medium">
        <div className="flex items-center gap-2 text-gray-400">
          <Icon className="w-3.5 h-3.5" />
          {label}
        </div>
        <div className="flex items-center gap-2">
          {delta !== 0 && (
            <span className={`font-bold flex items-center gap-0.5 ${isNegative ? 'text-critical' : 'text-success'}`}>
              {isNegative ? '−' : '+'} {Math.abs(delta * 100).toFixed(1)}
            </span>
          )}
          <span className="text-white font-mono">{value.toFixed(1)}% Risk</span>
        </div>
      </div>
      <div className="h-3 bg-white/5 rounded-full overflow-hidden border border-white/5 relative shadow-inner">
        <div
          className={`h-full transition-all duration-700 ease-out rounded-full ${value > 60 ? 'bg-critical' : value > 30 ? 'bg-warning' : 'bg-success'}`}
          style={{ width: `${Math.max(value, 1)}%`, opacity: value > 0 ? 1 : 0.3 }}
        />
      </div>
      {signals && signals.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1">
          {signals.map((s: string, i: number) => (
            <span key={i} className="text-[9px] px-1.5 py-0.5 rounded-sm bg-primary/10 text-primary/80 border border-primary/20">
              {s}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function getScoreTextColor(score: number) {
  if (score >= 80) return 'text-success';
  if (score >= 50) return 'text-warning';
  if (score >= 30) return 'text-alert';
  return 'text-critical';
}

function DecisionBadge({ decision, score }: { decision: string, score: number }) {
  let colors = "bg-gray-500/10 text-gray-500 border-gray-500/20";

  if (score >= 80) colors = "bg-success/10 text-success border-success/20";
  else if (score >= 50) colors = "bg-warning/10 text-warning border-warning/20";
  else if (score >= 30) colors = "bg-alert/10 text-alert border-alert/20";
  else colors = "bg-critical/10 text-critical border-critical/20";

  return (
    <span className={`px-2 py-1 rounded text-xs font-bold uppercase border ${colors}`}>
      {decision}
    </span>
  );
}
