'use client';

import { usePolling } from '@/hooks/usePolling';
import { Entity, AuditLog } from '@/types';
import {
  Users,
  ShieldCheck,
  Eye,
  ShieldAlert,
  Clock,
  TrendingUp,
  AlertCircle,
  Activity,
  Wifi,
  WifiOff,
  Brain,
  Zap,
  Target
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
  Legend
} from 'recharts';
import { useMemo } from 'react';
import Link from 'next/link';

export default function Dashboard() {
  const { data: entities, isLoading: entitiesLoading, status } = usePolling<Entity[]>('/entities/');
  const { data: auditLogs } = usePolling<AuditLog[]>('/audit/');
  const { data: transparencyStatsData } = usePolling<any>('/transparency/stats', 3000);
  const transparencyStats = transparencyStatsData || { total_events: 0, high_severity_count: 0 };

  const isBackendOnline = status === 'online';

  const stats = useMemo(() => {
    if (!entities) return {
      total: 0, trusted: 0, monitor: 0, isolated: 0,
      highRisk: 0, pendingApprovals: 0, activeResponses: 0
    };

    return {
      total: entities.length,
      trusted: entities.filter(e => e.decision === 'trusted').length,
      monitor: entities.filter(e => e.decision === 'monitor').length,
      isolated: entities.filter(e => e.decision === 'isolate' || e.decision === 'emergency').length,
      highRisk: entities.filter(e => e.trust_score < 40).length,
      pendingApprovals: entities.filter(e => e.approval_required).length,
      activeResponses: entities.filter(e => e.active_actions.length > 0).length,
    };
  }, [entities]);

  const riskChartData = useMemo(() => {
    if (!entities) return [];
    return [
      { name: 'Critical', shortName: '<30', value: entities.filter(e => e.trust_score < 30).length, fill: '#ef4444', gradient: 'url(#criticalGradient)' },
      { name: 'Alert', shortName: '30-49', value: entities.filter(e => e.trust_score >= 30 && e.trust_score < 50).length, fill: '#f97316', gradient: 'url(#alertGradient)' },
      { name: 'Monitor', shortName: '50-79', value: entities.filter(e => e.trust_score >= 50 && e.trust_score < 80).length, fill: '#eab308', gradient: 'url(#monitorGradient)' },
      { name: 'Trusted', shortName: '≥80', value: entities.filter(e => e.trust_score >= 80).length, fill: '#22c55e', gradient: 'url(#trustedGradient)' },
    ];
  }, [entities]);

  const pieData = useMemo(() => {
    if (!entities || entities.length === 0) return [];
    return riskChartData.filter(d => d.value > 0);
  }, [entities, riskChartData]);

  if (entitiesLoading && !entities) {
    return <div className="flex items-center justify-center h-full text-gray-400">Loading system data...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-white">Security Overview</h2>
          <p className="text-gray-400">Real-time status of all monitored entities</p>
        </div>
        <div className="flex items-center gap-4">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium border ${isBackendOnline
            ? "bg-success/10 text-success border-success/20"
            : "bg-critical/10 text-critical border-critical/20"
            }`}>
            {isBackendOnline ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
            {isBackendOnline ? "API Online" : "API Offline"}
          </div>
          <div className="flex items-center gap-2 text-xs font-medium text-gray-500 bg-card px-3 py-1.5 rounded-md border border-border" suppressHydrationWarning>
            <Clock className="w-3.5 h-3.5" />
            Updated: {new Date().toLocaleTimeString()}
          </div>
        </div>
      </div>

      {/* Stats Grid - 8 columns */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        <StatCard
          title="Events Analyzed"
          value={transparencyStats.total_events}
          icon={Zap}
          color="text-primary"
        />
        <StatCard
          title="High Severity"
          value={transparencyStats.high_severity_count}
          icon={Target}
          color="text-alert"
          pulse={transparencyStats.high_severity_count > 0}
        />
        <StatCard
          title="Total Entities"
          value={stats.total}
          icon={Users}
          color="text-primary"
        />
        <StatCard
          title="Trusted"
          value={stats.trusted}
          icon={ShieldCheck}
          color="text-success"
        />
        <StatCard
          title="Monitoring"
          value={stats.monitor}
          icon={Eye}
          color="text-warning"
        />
        <StatCard
          title="Isolated"
          value={stats.isolated}
          icon={ShieldAlert}
          color="text-critical"
        />
        <StatCard
          title="Active Responses"
          value={stats.activeResponses}
          icon={Activity}
          color="text-primary"
          href="/responses"
        />
        <StatCard
          title="Pending Approvals"
          value={stats.pendingApprovals}
          icon={AlertCircle}
          color="text-alert"
          href="/incidents"
          pulse={stats.pendingApprovals > 0}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Enhanced Risk Distribution Chart */}
        <div className="lg:col-span-2 soc-card overflow-hidden">
          <div className="flex items-center justify-between mb-6">
            <h3 className="font-semibold text-lg flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-primary" />
              Risk Distribution
            </h3>
            <div className="flex gap-2">
              {riskChartData.map((item) => (
                <div key={item.name} className="flex items-center gap-1.5 text-xs">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.fill }} />
                  <span className="text-gray-400">{item.name}</span>
                  <span className="font-bold text-white">{item.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Bar Chart */}
            <div className="h-[260px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={riskChartData} layout="vertical" barCategoryGap="20%">
                  <defs>
                    <linearGradient id="criticalGradient" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#dc2626" stopOpacity={0.8} />
                      <stop offset="100%" stopColor="#ef4444" stopOpacity={1} />
                    </linearGradient>
                    <linearGradient id="alertGradient" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#ea580c" stopOpacity={0.8} />
                      <stop offset="100%" stopColor="#f97316" stopOpacity={1} />
                    </linearGradient>
                    <linearGradient id="monitorGradient" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#ca8a04" stopOpacity={0.8} />
                      <stop offset="100%" stopColor="#eab308" stopOpacity={1} />
                    </linearGradient>
                    <linearGradient id="trustedGradient" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#16a34a" stopOpacity={0.8} />
                      <stop offset="100%" stopColor="#22c55e" stopOpacity={1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#262626" horizontal={false} />
                  <XAxis type="number" stroke="#666" fontSize={11} tickLine={false} axisLine={false} />
                  <YAxis
                    dataKey="name"
                    type="category"
                    width={70}
                    stroke="#666"
                    fontSize={11}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    content={<CustomTooltip />}
                    cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                  />
                  <Bar
                    dataKey="value"
                    radius={[0, 8, 8, 0]}
                    animationDuration={800}
                    animationEasing="ease-out"
                  >
                    {riskChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.gradient} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            {/* Pie Chart */}
            <div className="h-[260px] flex items-center justify-center">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <defs>
                      <filter id="glow">
                        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                        <feMerge>
                          <feMergeNode in="coloredBlur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>
                    </defs>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={90}
                      paddingAngle={3}
                      dataKey="value"
                      animationDuration={800}
                      animationEasing="ease-out"
                      stroke="none"
                    >
                      {pieData.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={entry.fill}
                          style={{ filter: 'url(#glow)' }}
                        />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomPieTooltip />} />
                    {/* Center Text */}
                    <text x="50%" y="46%" textAnchor="middle" fill="#fff" fontSize={28} fontWeight="bold">
                      {stats.total}
                    </text>
                    <text x="50%" y="58%" textAnchor="middle" fill="#888" fontSize={11}>
                      Total Entities
                    </text>
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-center text-gray-500">
                  <div className="w-32 h-32 rounded-full border-4 border-dashed border-gray-700 flex items-center justify-center mx-auto mb-3">
                    <span className="text-3xl font-bold text-gray-600">0</span>
                  </div>
                  <p className="text-sm">No entities detected</p>
                </div>
              )}
            </div>
          </div>

          {/* Risk Level Legend Bar */}
          <div className="mt-6 pt-4 border-t border-border">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1 flex-1">
                <div className="h-2 flex-1 rounded-l-full bg-gradient-to-r from-red-600 to-red-500" />
                <div className="h-2 flex-1 bg-gradient-to-r from-orange-600 to-orange-500" />
                <div className="h-2 flex-1 bg-gradient-to-r from-yellow-600 to-yellow-500" />
                <div className="h-2 flex-1 rounded-r-full bg-gradient-to-r from-green-600 to-green-500" />
              </div>
            </div>
            <div className="flex justify-between mt-2 text-[10px] text-gray-500 uppercase font-medium">
              <span>Critical Risk</span>
              <span>Alert</span>
              <span>Monitor</span>
              <span>Trusted</span>
            </div>
          </div>
        </div>

        {/* High Risk Entities */}
        <div className="soc-card space-y-4">
          <h3 className="font-semibold text-lg flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-critical" />
            High Risk Entities
          </h3>
          <div className="space-y-3">
            {entities?.filter(e => e.trust_score < 40).slice(0, 5).map(entity => (
              <Link
                key={entity.entity_id}
                href={`/entities/${entity.entity_id}`}
                className="block p-3 bg-white/5 rounded-md border border-white/10 hover:border-primary/30 transition-all hover:bg-white/[0.07]"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-white truncate max-w-[140px]">{entity.entity_id}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="w-16 h-1.5 bg-white/10 rounded-full overflow-hidden">
                        <div
                          className={`h-full transition-all duration-500 ${entity.trust_score < 30 ? 'bg-critical' : 'bg-alert'}`}
                          style={{ width: `${entity.trust_score}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-500">{entity.trust_score}</span>
                    </div>
                  </div>
                  <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${entity.trust_score < 30
                    ? "bg-critical/20 text-critical"
                    : "bg-alert/20 text-alert"
                    }`}>
                    {entity.decision}
                  </div>
                </div>
              </Link>
            ))}
            {stats.highRisk === 0 && (
              <div className="text-center py-8">
                <div className="w-16 h-16 rounded-full bg-success/10 flex items-center justify-center mx-auto mb-3">
                  <ShieldCheck className="w-8 h-8 text-success" />
                </div>
                <p className="text-gray-400 text-sm">All entities in safe state</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Custom Tooltip for Bar Chart
function CustomTooltip({ active, payload }: any) {
  if (!active || !payload || !payload.length) return null;
  const data = payload[0].payload;

  return (
    <div className="bg-card/95 backdrop-blur-sm border border-border rounded-lg px-4 py-3 shadow-xl">
      <div className="flex items-center gap-2 mb-1">
        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: data.fill }} />
        <span className="font-semibold text-white">{data.name}</span>
      </div>
      <div className="text-2xl font-bold text-white">{data.value}</div>
      <div className="text-xs text-gray-500">TrustScore {data.shortName}</div>
    </div>
  );
}

// Custom Tooltip for Pie Chart
function CustomPieTooltip({ active, payload }: any) {
  if (!active || !payload || !payload.length) return null;
  const data = payload[0].payload;

  return (
    <div className="bg-card/95 backdrop-blur-sm border border-border rounded-lg px-4 py-3 shadow-xl">
      <div className="flex items-center gap-2 mb-1">
        <div className="w-3 h-3 rounded-full" style={{ backgroundColor: data.fill }} />
        <span className="font-semibold text-white">{data.name}</span>
      </div>
      <div className="text-xl font-bold text-white">{data.value} entities</div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, href, pulse }: {
  title: string;
  value: number;
  icon: any;
  color: string;
  href?: string;
  pulse?: boolean;
}) {
  const content = (
    <div className={`soc-card flex items-start justify-between ${href ? 'hover:border-primary/30 transition-colors cursor-pointer' : ''}`}>
      <div>
        <p className="text-sm text-gray-400 font-medium">{title}</p>
        <p className="text-3xl font-bold text-white mt-1">{value}</p>
      </div>
      <div className={`p-2 rounded-lg bg-white/5 ${color} ${pulse ? 'animate-pulse' : ''}`}>
        <Icon className="w-6 h-6" />
      </div>
    </div>
  );

  if (href) {
    return <Link href={href}>{content}</Link>;
  }
  return content;
}
