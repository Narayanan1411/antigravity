'use client';

import { usePolling } from '@/hooks/usePolling';
import {
  ResponseExecution, DeviceBlock, ManualExecuteRequest,
} from '@/types';
import {
  blockDevice, unblockDevice, manualExecute,
  approveExecution, rejectExecution,
} from '@/lib/api';
import {
  Activity, Shield, ShieldOff, ShieldAlert, Clock,
  CheckCircle2, XCircle, AlertTriangle, Zap, Filter,
  Lock, Unlock, RefreshCw, ChevronDown, ChevronUp,
} from 'lucide-react';
import { useState, useMemo, useCallback } from 'react';

// ── Constants ─────────────────────────────────────────────────────────────────

const ACTION_LABELS: Record<string, string> = {
  allow:            'Allow',
  monitor:          'Monitor',
  require_mfa:      'Require MFA',
  restrict_network: 'Restrict Network',
  isolate_vlan:     'Isolate VLAN',
  lock_account:     'Lock Account',
  firewall_block:   'Firewall Block',
  kill_process:     'Kill Process',
  block_device:     'Block Device',
  unblock_device:   'Unblock Device',
};

const ACTION_COLORS: Record<string, string> = {
  allow:            'text-success border-success/30 bg-success/10',
  monitor:          'text-blue-400 border-blue-400/30 bg-blue-400/10',
  require_mfa:      'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
  restrict_network: 'text-orange-400 border-orange-400/30 bg-orange-400/10',
  isolate_vlan:     'text-red-400 border-red-400/30 bg-red-400/10',
  lock_account:     'text-red-400 border-red-400/30 bg-red-400/10',
  firewall_block:   'text-red-400 border-red-400/30 bg-red-400/10',
  kill_process:     'text-red-400 border-red-400/30 bg-red-400/10',
  block_device:     'text-red-400 border-red-400/30 bg-red-400/10',
  unblock_device:   'text-success border-success/30 bg-success/10',
};

const STATUS_CONFIG: Record<string, { color: string; label: string }> = {
  pending:  { color: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30', label: 'PENDING'  },
  running:  { color: 'bg-blue-400/10 text-blue-400 border-blue-400/30',       label: 'RUNNING'  },
  success:  { color: 'bg-green-400/10 text-green-400 border-green-400/30',    label: 'SUCCESS'  },
  failed:   { color: 'bg-red-400/10 text-red-400 border-red-400/30',          label: 'FAILED'   },
  rejected: { color: 'bg-gray-500/10 text-gray-400 border-gray-500/30',       label: 'REJECTED' },
};

const HARD_ACTIONS = ['restrict_network', 'isolate_vlan', 'lock_account', 'firewall_block', 'kill_process'];
const ALL_ACTIONS  = Object.keys(ACTION_LABELS);

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt(ts: string | null) {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

function shortId(id: string) {
  return id.length > 22 ? id.slice(0, 22) + '…' : id;
}

// ── Small display components ──────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? {
    color: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
    label: status.toUpperCase(),
  };
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${cfg.color}`}>
      {cfg.label}
    </span>
  );
}

function ActionBadge({ action }: { action: string }) {
  const color = ACTION_COLORS[action] ?? 'text-gray-400 border-gray-500/30 bg-gray-500/10';
  return (
    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${color}`}>
      {ACTION_LABELS[action] ?? action}
    </span>
  );
}

function TrustBar({ score }: { score: number | null }) {
  const v = score ?? 80;
  const color = v >= 60 ? 'bg-green-400' : v >= 30 ? 'bg-yellow-400' : 'bg-red-400';
  return (
    <div className="flex items-center gap-2">
      <div className="w-14 h-1.5 bg-white/10 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${v}%` }} />
      </div>
      <span className="text-xs text-gray-400 font-mono">{v.toFixed(0)}</span>
    </div>
  );
}

function StatCard({
  title, value, icon: Icon, color, sub,
}: { title: string; value: number | string; icon: any; color: string; sub?: string }) {
  return (
    <div className="soc-card flex items-start justify-between">
      <div>
        <p className="text-sm text-gray-400 font-medium">{title}</p>
        <p className="text-3xl font-bold text-white mt-1">{value}</p>
        {sub && <p className="text-xs text-gray-500 mt-0.5">{sub}</p>}
      </div>
      <div className={`p-2 rounded-lg bg-white/5 ${color}`}>
        <Icon className="w-6 h-6" />
      </div>
    </div>
  );
}

// ── Block Device Modal ────────────────────────────────────────────────────────

interface Device { device_id: string; hostname: string; device_type: string }

function BlockModal({
  devices, onClose, onSuccess,
}: { devices: Device[]; onClose: () => void; onSuccess: () => void }) {
  const [deviceId, setDeviceId] = useState('');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    if (!deviceId) { setError('Please select a device.'); return; }
    setLoading(true); setError('');
    try {
      await blockDevice({ device_id: deviceId, reason: reason || 'Manual SOC block' });
      onSuccess();
    } catch (e: any) {
      setError(e.message ?? 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="soc-card w-full max-w-md space-y-4">
        <div className="flex items-center gap-2">
          <ShieldOff className="w-5 h-5 text-red-400" />
          <h3 className="text-lg font-bold text-white">Block Device</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Device *</label>
            <select
              className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary"
              value={deviceId}
              onChange={e => setDeviceId(e.target.value)}
            >
              <option value="">— select device —</option>
              {devices.map(d => (
                <option key={d.device_id} value={d.device_id}>
                  {d.hostname} ({d.device_type}) · {d.device_id.slice(0, 16)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Reason</label>
            <input
              className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-primary"
              placeholder="e.g. Suspected lateral movement"
              value={reason}
              onChange={e => setReason(e.target.value)}
            />
          </div>
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex gap-2 justify-end pt-1">
          <button onClick={onClose}
            className="px-4 py-2 rounded text-sm text-gray-400 hover:text-white border border-border hover:border-primary/50 transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={loading}
            className="px-4 py-2 rounded text-sm font-semibold bg-red-500/20 text-red-400 border border-red-400/40 hover:bg-red-500/30 transition-colors disabled:opacity-50">
            {loading ? 'Blocking…' : 'Block Device'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Manual Trigger Modal ──────────────────────────────────────────────────────

function ExecuteModal({
  devices, onClose, onSuccess,
}: { devices: Device[]; onClose: () => void; onSuccess: () => void }) {
  const [form, setForm] = useState<ManualExecuteRequest>({
    device_id: '', action: 'monitor', trust_score: 50, risk_score: 0,
    severity: 'MEDIUM', triggered_by: 'SOC_ADMIN', auto_approve: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const isHard = HARD_ACTIONS.includes(form.action);
  const set = (k: keyof ManualExecuteRequest, v: any) => setForm(f => ({ ...f, [k]: v }));

  const submit = async () => {
    if (!form.device_id) { setError('Please select a device.'); return; }
    setLoading(true); setError('');
    try {
      await manualExecute(form);
      onSuccess();
    } catch (e: any) {
      setError(e.message ?? 'Request failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
      <div className="soc-card w-full max-w-md space-y-4">
        <div className="flex items-center gap-2">
          <Zap className="w-5 h-5 text-primary" />
          <h3 className="text-lg font-bold text-white">Trigger Response Action</h3>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Device *</label>
            <select
              className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary"
              value={form.device_id} onChange={e => set('device_id', e.target.value)}
            >
              <option value="">— select device —</option>
              {devices.map(d => (
                <option key={d.device_id} value={d.device_id}>
                  {d.hostname} ({d.device_type})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Action *</label>
            <select
              className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary"
              value={form.action} onChange={e => set('action', e.target.value)}
            >
              {ALL_ACTIONS.map(a => (
                <option key={a} value={a}>{ACTION_LABELS[a]}</option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Trust Score</label>
              <input type="number" min={0} max={100}
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary"
                value={form.trust_score} onChange={e => set('trust_score', +e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Severity</label>
              <select
                className="w-full bg-background border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-primary"
                value={form.severity} onChange={e => set('severity', e.target.value)}
              >
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>
          {isHard && (
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input type="checkbox" className="w-4 h-4 accent-yellow-400"
                checked={!!form.auto_approve} onChange={e => set('auto_approve', e.target.checked)} />
              <span className="text-xs text-yellow-400">Skip approval gate (force-execute)</span>
            </label>
          )}
          {isHard && !form.auto_approve && (
            <p className="text-xs text-yellow-400/80 bg-yellow-400/5 border border-yellow-400/20 rounded p-2">
              This hard-containment action will enter <strong>pending</strong> state and require approval below.
            </p>
          )}
          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>
        <div className="flex gap-2 justify-end pt-1">
          <button onClick={onClose}
            className="px-4 py-2 rounded text-sm text-gray-400 hover:text-white border border-border hover:border-primary/50 transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={loading}
            className="px-4 py-2 rounded text-sm font-semibold bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 transition-colors disabled:opacity-50">
            {loading ? 'Triggering…' : 'Trigger'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Approval Queue Row ────────────────────────────────────────────────────────

function ApprovalRow({ exec, onAction }: { exec: ResponseExecution; onAction: () => void }) {
  const [loading, setLoading] = useState<'approve' | 'reject' | null>(null);
  const [expanded, setExpanded] = useState(false);

  const doApprove = async () => {
    setLoading('approve');
    try { await approveExecution(exec.execution_id, { approver: 'SOC_ADMIN' }); onAction(); }
    catch (e) { console.error(e); } finally { setLoading(null); }
  };

  const doReject = async () => {
    setLoading('reject');
    try { await rejectExecution(exec.execution_id, { rejector: 'SOC_ADMIN', reason: 'Rejected via dashboard' }); onAction(); }
    catch (e) { console.error(e); } finally { setLoading(null); }
  };

  return (
    <div className="border border-yellow-400/20 bg-yellow-400/5 rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1.5 flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <ActionBadge action={exec.action} />
            <span className="font-mono text-xs text-gray-300">{shortId(exec.device_id)}</span>
            {exec.severity && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${
                exec.severity === 'CRITICAL' ? 'text-red-400 border-red-400/30 bg-red-400/10' :
                exec.severity === 'HIGH'     ? 'text-orange-400 border-orange-400/30 bg-orange-400/10' :
                'text-yellow-400 border-yellow-400/30 bg-yellow-400/10'
              }`}>{exec.severity}</span>
            )}
          </div>
          {exec.description && <p className="text-xs text-gray-400">{exec.description}</p>}
          <p className="text-[11px] text-gray-500">
            Triggered by <span className="text-gray-300">{exec.triggered_by}</span>
            {' · '}{fmt(exec.created_at)}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button onClick={() => setExpanded(e => !e)}
            className="p-1.5 rounded hover:bg-white/5 text-gray-500 hover:text-white transition-colors">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          <button onClick={doReject} disabled={!!loading}
            className="px-3 py-1.5 rounded text-xs font-semibold bg-red-400/10 text-red-400 border border-red-400/30 hover:bg-red-400/20 transition-colors disabled:opacity-50">
            {loading === 'reject' ? '…' : 'Reject'}
          </button>
          <button onClick={doApprove} disabled={!!loading}
            className="px-3 py-1.5 rounded text-xs font-semibold bg-green-400/10 text-green-400 border border-green-400/30 hover:bg-green-400/20 transition-colors disabled:opacity-50">
            {loading === 'approve' ? '…' : 'Approve & Execute'}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="grid grid-cols-3 gap-4 pt-2 border-t border-white/5 text-xs">
          <div>
            <span className="text-gray-500 block mb-1">Trust Score</span>
            <TrustBar score={exec.trust_score} />
          </div>
          <div>
            <span className="text-gray-500 block mb-1">Risk Score</span>
            <span className="text-white font-mono">{exec.risk_score?.toFixed(1) ?? '—'}</span>
          </div>
          <div>
            <span className="text-gray-500 block mb-1">Execution ID</span>
            <span className="text-gray-300 font-mono text-[10px] break-all">{exec.execution_id}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Active Block Row ──────────────────────────────────────────────────────────

function BlockRow({ block, onUnblock }: { block: DeviceBlock; onUnblock: () => void }) {
  const [loading, setLoading] = useState(false);

  const doUnblock = async () => {
    setLoading(true);
    try { await unblockDevice({ device_id: block.device_id, unblocked_by: 'SOC_ADMIN' }); onUnblock(); }
    catch (e) { console.error(e); } finally { setLoading(false); }
  };

  return (
    <tr className="hover:bg-white/[0.02] transition-colors">
      <td><span className="font-mono text-sm text-white">{block.device_id}</span></td>
      <td><ActionBadge action={block.action} /></td>
      <td><span className="text-xs text-gray-300">{block.reason || '—'}</span></td>
      <td><span className="text-xs text-gray-400">{block.blocked_by}</span></td>
      <td>
        <span className="text-xs text-gray-400" suppressHydrationWarning>
          {fmt(block.blocked_at)}
        </span>
      </td>
      <td>
        <button onClick={doUnblock} disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1 rounded text-xs font-semibold bg-green-400/10 text-green-400 border border-green-400/30 hover:bg-green-400/20 transition-colors disabled:opacity-50">
          <Unlock className="w-3 h-3" />
          {loading ? 'Unblocking…' : 'Unblock'}
        </button>
      </td>
    </tr>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ResponsesPage() {
  const { data: executions, isLoading: exLoading, mutate: refreshExec } =
    usePolling<ResponseExecution[]>('/response/executions?limit=200', 3000);
  const { data: blocks, isLoading: blLoading, mutate: refreshBlocks } =
    usePolling<DeviceBlock[]>('/response/blocks?active_only=true', 3000);
  const { data: devices } =
    usePolling<Device[]>('/devices', 10000);

  const [statusFilter, setStatusFilter] = useState('all');
  const [actionFilter, setActionFilter] = useState('all');
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [showExecModal, setShowExecModal] = useState(false);

  const refresh = useCallback(() => { refreshExec(); refreshBlocks(); }, [refreshExec, refreshBlocks]);

  const pending = useMemo(() => (executions ?? []).filter(e => e.status === 'pending'), [executions]);

  const filtered = useMemo(() => {
    let list = executions ?? [];
    if (statusFilter !== 'all') list = list.filter(e => e.status === statusFilter);
    if (actionFilter !== 'all') list = list.filter(e => e.action === actionFilter);
    return list;
  }, [executions, statusFilter, actionFilter]);

  const stats = useMemo(() => {
    const all = executions ?? [];
    return {
      total:    all.length,
      pending:  all.filter(e => e.status === 'pending').length,
      success:  all.filter(e => e.status === 'success').length,
      failed:   all.filter(e => e.status === 'failed').length,
      rejected: all.filter(e => e.status === 'rejected').length,
      blocked:  (blocks ?? []).length,
    };
  }, [executions, blocks]);

  const deviceList = devices ?? [];

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-3">
            <Shield className="w-7 h-7 text-primary" />
            Response Center
          </h2>
          <p className="text-gray-400 text-sm mt-0.5">
            Live response orchestration — block, isolate, and approve actions in real time
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={refresh}
            className="p-2 rounded-lg border border-border text-gray-400 hover:text-white hover:border-primary/50 transition-colors"
            title="Refresh now">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => setShowExecModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-primary/20 text-primary border border-primary/40 hover:bg-primary/30 transition-colors">
            <Zap className="w-4 h-4" /> Trigger Action
          </button>
          <button onClick={() => setShowBlockModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-red-500/20 text-red-400 border border-red-400/40 hover:bg-red-500/30 transition-colors">
            <ShieldOff className="w-4 h-4" /> Block Device
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard title="Total" value={stats.total}    icon={Activity}     color="text-primary" />
        <StatCard title="Pending" value={stats.pending} icon={Clock}        color="text-yellow-400"
          sub={stats.pending > 0 ? 'Needs approval' : undefined} />
        <StatCard title="Success" value={stats.success} icon={CheckCircle2} color="text-green-400" />
        <StatCard title="Failed"  value={stats.failed}  icon={AlertTriangle} color="text-red-400" />
        <StatCard title="Rejected" value={stats.rejected} icon={XCircle}   color="text-gray-400" />
        <StatCard title="Blocked" value={stats.blocked} icon={ShieldOff}   color="text-red-400"
          sub="Active blocks" />
      </div>

      {/* Approval Queue */}
      {pending.length > 0 && (
        <section className="space-y-3">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-yellow-400" />
            <h3 className="text-sm font-semibold text-yellow-400 uppercase tracking-wider">
              Approval Queue ({pending.length})
            </h3>
          </div>
          <div className="space-y-2">
            {pending.map(exec => (
              <ApprovalRow key={exec.execution_id} exec={exec} onAction={refresh} />
            ))}
          </div>
        </section>
      )}

      {/* Active Blocks */}
      <section className="space-y-3">
        <div className="flex items-center gap-2">
          <ShieldOff className="w-4 h-4 text-red-400" />
          <h3 className="text-sm font-semibold text-red-400 uppercase tracking-wider">
            Active Device Blocks {(blocks ?? []).length > 0 ? `(${blocks!.length})` : ''}
          </h3>
        </div>
        <div className="soc-card p-0 overflow-hidden">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Device ID</th><th>Action</th><th>Reason</th>
                <th>Blocked By</th><th>Since</th><th>Controls</th>
              </tr>
            </thead>
            <tbody>
              {blLoading && !blocks ? (
                <tr><td colSpan={6} className="text-center py-8 text-gray-500 italic">Loading…</td></tr>
              ) : (blocks ?? []).length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8">
                    <div className="flex flex-col items-center gap-2 text-gray-600">
                      <ShieldAlert className="w-8 h-8 opacity-30" />
                      <span className="italic text-sm">No active device blocks</span>
                    </div>
                  </td>
                </tr>
              ) : (
                (blocks ?? []).map(b => (
                  <BlockRow key={b.block_id} block={b} onUnblock={refresh} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Execution History */}
      <section className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-semibold text-primary uppercase tracking-wider">
              Execution History
            </h3>
          </div>
          <div className="flex gap-2">
            <div className="relative">
              <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-500" />
              <select
                className="bg-card border border-border rounded pl-7 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-primary appearance-none"
                value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
              >
                <option value="all">All Statuses</option>
                {Object.keys(STATUS_CONFIG).map(s => (
                  <option key={s} value={s}>{STATUS_CONFIG[s].label}</option>
                ))}
              </select>
            </div>
            <div className="relative">
              <Filter className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-500" />
              <select
                className="bg-card border border-border rounded pl-7 pr-3 py-1.5 text-xs text-white focus:outline-none focus:border-primary appearance-none"
                value={actionFilter} onChange={e => setActionFilter(e.target.value)}
              >
                <option value="all">All Actions</option>
                {ALL_ACTIONS.map(a => <option key={a} value={a}>{ACTION_LABELS[a]}</option>)}
              </select>
            </div>
          </div>
        </div>

        <div className="soc-card p-0 overflow-hidden">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Action</th><th>Device</th><th>Status</th>
                <th>Trust</th><th>Severity</th><th>Triggered By</th>
                <th>Approval</th><th>Time</th>
              </tr>
            </thead>
            <tbody>
              {exLoading && !executions ? (
                <tr><td colSpan={8} className="text-center py-8 text-gray-500 italic">Loading…</td></tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12">
                    <div className="flex flex-col items-center gap-2 text-gray-600">
                      <Activity className="w-8 h-8 opacity-30" />
                      <span className="italic text-sm">No execution records</span>
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.slice(0, 100).map(exec => (
                  <tr key={exec.execution_id} className="hover:bg-white/[0.02] transition-colors">
                    <td><ActionBadge action={exec.action} /></td>
                    <td>
                      <span className="font-mono text-xs text-gray-300">{shortId(exec.device_id)}</span>
                    </td>
                    <td><StatusBadge status={exec.status} /></td>
                    <td><TrustBar score={exec.trust_score} /></td>
                    <td>
                      {exec.severity ? (
                        <span className={`text-[10px] font-bold uppercase ${
                          exec.severity === 'CRITICAL' ? 'text-red-400' :
                          exec.severity === 'HIGH'     ? 'text-orange-400' :
                          exec.severity === 'MEDIUM'   ? 'text-yellow-400' : 'text-gray-500'
                        }`}>{exec.severity}</span>
                      ) : <span className="text-gray-600">—</span>}
                    </td>
                    <td><span className="text-xs text-gray-400">{exec.triggered_by}</span></td>
                    <td>
                      {exec.requires_approval ? (
                        exec.approved_by ? (
                          <span className="text-xs text-green-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" />{exec.approved_by}
                          </span>
                        ) : exec.rejected_by ? (
                          <span className="text-xs text-red-400 flex items-center gap-1">
                            <XCircle className="w-3 h-3" />{exec.rejected_by}
                          </span>
                        ) : (
                          <span className="text-xs text-yellow-400">awaiting</span>
                        )
                      ) : (
                        <span className="text-xs text-gray-600">auto</span>
                      )}
                    </td>
                    <td>
                      <span className="text-xs text-gray-500" suppressHydrationWarning>
                        {fmt(exec.created_at)}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
        {filtered.length > 100 && (
          <p className="text-xs text-gray-600 text-center">
            Showing 100 of {filtered.length} — use filters to narrow
          </p>
        )}
      </section>

      {/* Modals */}
      {showBlockModal && (
        <BlockModal devices={deviceList}
          onClose={() => setShowBlockModal(false)}
          onSuccess={() => { setShowBlockModal(false); refresh(); }} />
      )}
      {showExecModal && (
        <ExecuteModal devices={deviceList}
          onClose={() => setShowExecModal(false)}
          onSuccess={() => { setShowExecModal(false); refresh(); }} />
      )}
    </div>
  );
}
