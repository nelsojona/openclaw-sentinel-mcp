/**
 * Gateway integration types for Sentinel MCP
 */

/**
 * Security event types that can be published to Gateway
 */
export type SecurityEventType =
  | 'violation'
  | 'approval_required'
  | 'audit_entry'
  | 'cost_threshold'
  | 'anomaly_detected';

/**
 * Security event payload
 */
export interface SecurityEvent {
  type: SecurityEventType;
  timestamp: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  source: string;
  data: Record<string, unknown>;
}

/**
 * Security alert
 */
export interface SecurityAlert {
  id: string;
  type: SecurityEventType;
  timestamp: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  details: Record<string, unknown>;
  acknowledged: boolean;
}

/**
 * Security status
 */
export interface SecurityStatus {
  mode: string;
  activeAlerts: number;
  totalViolations24h: number;
  riskScore: number;
  lastUpdate: number;
}

/**
 * Gateway RPC message types
 */
export interface GatewayRequest {
  id: string;
  method: string;
  params?: Record<string, unknown>;
}

export interface GatewayResponse {
  id: string;
  success: boolean;
  payload?: unknown;
  error?: {
    code: number;
    message: string;
  };
}

export interface GatewayEvent {
  event: string;
  data: unknown;
}
