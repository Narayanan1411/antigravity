export type DecisionState = 'trusted' | 'monitor' | 'isolate' | 'emergency';

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
  trust_score: number;
  confidence: number;
  decision: DecisionState;
  category_breakdown: CategoryBreakdown;
  last_updated: string;
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

