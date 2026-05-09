import {
  Entity, AuditLog, ApprovalRequest,
  BlockRequest, UnblockRequest, ManualExecuteRequest,
  ExecutionApprovalRequest, ExecutionRejectRequest,
} from '../types';

// Use relative path so Next.js dev-server proxy (next.config.mjs rewrites)
// forwards to http://localhost:8000/api/v1 — avoids browser CORS restrictions.
const BASE_URL = '/api/v1';

export const fetcher = async (url: string) => {
  const res = await fetch(`${BASE_URL}${url}`);
  if (!res.ok) throw new Error('Failed to fetch data');
  return res.json();
};

export const approveResponse = async (payload: ApprovalRequest) => {
  const res = await fetch(`${BASE_URL}/response/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      entity_id: payload.entity_id,
      action: payload.action,
      approved: payload.approved,
      approved_by: payload.approved_by || 'SOC_ANALYST',
    }),
  });
  if (!res.ok) throw new Error('Failed to approve action');
  return res.json();
};

export const ingestEvent = async (payload: any) => {
  const res = await fetch(`${BASE_URL}/events/ingest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error('Failed to ingest event');
  return res.json();
};

// ── Response Executor API ─────────────────────────────────────────────────────

const post = async (path: string, body: unknown) => {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Request failed');
  }
  return res.json();
};

export const blockDevice = (payload: BlockRequest) =>
  post('/response/block', { ...payload, blocked_by: payload.blocked_by ?? 'SOC_ADMIN' });

export const unblockDevice = (payload: UnblockRequest) =>
  post('/response/unblock', { ...payload, unblocked_by: payload.unblocked_by ?? 'SOC_ADMIN' });

export const manualExecute = (payload: ManualExecuteRequest) =>
  post('/response/execute', payload);

export const approveExecution = (executionId: string, payload: ExecutionApprovalRequest) =>
  post(`/response/executions/${executionId}/approve`, payload);

export const rejectExecution = (executionId: string, payload: ExecutionRejectRequest) =>
  post(`/response/executions/${executionId}/reject`, payload);

