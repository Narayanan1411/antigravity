export type DecisionState = 'trusted' | 'monitor' | 'isolate' | 'emergency' | 'discovering';

export interface CategoryBreakdown {
  network: number;
  identity: number;
  cloud: number;
  hardware: number;
  temporal: number;
}

export interface CategoryEvaluation {
  weight: number;
  Rc: number;
  delta: number;
  signals: string[];
}

export interface ConfidenceComponents {
  source_factor: number;        // 0.33 for simulated, 1.0 for real
  coverage_factor: number;      // categories_seen / total_categories
  consistency_factor: number;   // min(1.0, event_count / 10)
  event_count: number;          // For display
  category_count: number;       // For display
  is_simulated: boolean;        // For display
}

export interface TrustEvaluation {
  entity_id: string;
  timestamp: string;
  simulation: boolean;
  final_trust_score: number;
  previous_trust_score: number;
  confidence: number;
  decision: string;
  trust_evaluation: Record<string, CategoryEvaluation>;
  confidence_components?: ConfidenceComponents;
}

export interface Entity {
  entity_id: string;
  trust_score: number | null;
  confidence: number;
  decision: DecisionState;
  discovering?: boolean;
  category_breakdown: CategoryBreakdown;
  last_updated: string;
  last_seen?: string;
  total_event_count?: number;
  active_actions: string[];
  last_action: string | null;
  approval_required: boolean;
  metadata?: {
    ip?: string;
    mac?: string;
    hostname?: string;
    os?: string;
    owner?: string;
    env?: string;
    simulated?: string;
    type?: string;
  };
  trust_evaluation?: TrustEvaluation | null;
  trust_history?: TrustEvaluation[];
}

export interface AuditLog {
  timestamp: string;
  entity_id: string;
  action_type: string;
  status: string;
  reason: string;
  approved_by: string | null;
  simulated: boolean;
}

export interface ApprovalRequest {
  entity_id: string;
  action: string;
  approved: boolean;
  approved_by?: string;
}

// ── Response Executor types ───────────────────────────────────────────────────

export type ExecutionStatus = 'pending' | 'running' | 'success' | 'failed' | 'rejected';

export interface ResponseExecution {
  execution_id: string;
  device_id: string;
  action: string;
  status: ExecutionStatus;
  triggered_by: string;
  trust_score: number | null;
  risk_score: number | null;
  severity: string | null;
  requires_approval: boolean;
  approved_by: string | null;
  rejected_by: string | null;
  rejection_reason: string | null;
  description: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  executed_at: string | null;
}

export interface DeviceBlock {
  block_id: string;
  device_id: string;
  action: string;
  reason: string | null;
  blocked_by: string;
  unblocked_by: string | null;
  blocked_at: string;
  unblocked_at: string | null;
  is_active: boolean;
}

export interface BlockRequest {
  device_id: string;
  reason?: string;
  blocked_by?: string;
}

export interface UnblockRequest {
  device_id: string;
  unblocked_by?: string;
}

export interface ManualExecuteRequest {
  device_id: string;
  action: string;
  triggered_by?: string;
  trust_score?: number;
  risk_score?: number;
  severity?: string;
  auto_approve?: boolean;
  metadata?: Record<string, unknown>;
}

export interface ExecutionApprovalRequest {
  approver?: string;
}

export interface ExecutionRejectRequest {
  rejector?: string;
  reason?: string;
}

