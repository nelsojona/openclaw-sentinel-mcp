/**
 * Event publisher for sending Sentinel security events to Gateway
 */

import type { SecurityEvent, GatewayRequest } from './types.js';

export class EventPublisher {
  private requestId = 0;

  /**
   * Publish a security event to the Gateway
   */
  async publishEvent(
    event: SecurityEvent,
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const request: GatewayRequest = {
      id: `sentinel-event-${++this.requestId}`,
      method: 'sentinel.publishEvent',
      params: {
        type: event.type,
        timestamp: event.timestamp,
        severity: event.severity,
        source: event.source,
        data: event.data,
      },
    };

    await sendRequest(request);
  }

  /**
   * Publish a security violation event
   */
  async publishViolation(
    violation: {
      tool: string;
      host: string;
      agent: string;
      reason: string;
      riskScore: number;
    },
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const event: SecurityEvent = {
      type: 'violation',
      timestamp: Date.now(),
      severity: violation.riskScore >= 80 ? 'critical' : violation.riskScore >= 60 ? 'high' : 'medium',
      source: 'sentinel-mcp',
      data: violation,
    };

    await this.publishEvent(event, sendRequest);
  }

  /**
   * Publish an approval required event
   */
  async publishApprovalRequired(
    approval: {
      tool: string;
      host: string;
      agent: string;
      confirmationToken: string;
      riskScore: number;
    },
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const event: SecurityEvent = {
      type: 'approval_required',
      timestamp: Date.now(),
      severity: 'medium',
      source: 'sentinel-mcp',
      data: approval,
    };

    await this.publishEvent(event, sendRequest);
  }

  /**
   * Publish an audit log entry event
   */
  async publishAuditEntry(
    entry: {
      sequenceNumber: number;
      tool: string;
      host: string;
      verdict: string;
      riskScore: number;
    },
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const event: SecurityEvent = {
      type: 'audit_entry',
      timestamp: Date.now(),
      severity: 'low',
      source: 'sentinel-mcp',
      data: entry,
    };

    await this.publishEvent(event, sendRequest);
  }

  /**
   * Publish a cost threshold alert
   */
  async publishCostThreshold(
    alert: {
      currentCost: number;
      threshold: number;
      period: string;
    },
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const event: SecurityEvent = {
      type: 'cost_threshold',
      timestamp: Date.now(),
      severity: 'high',
      source: 'sentinel-mcp',
      data: alert,
    };

    await this.publishEvent(event, sendRequest);
  }

  /**
   * Publish an anomaly detected event
   */
  async publishAnomaly(
    anomaly: {
      tool: string;
      host: string;
      composite: number;
      factors: string[];
    },
    sendRequest: (request: GatewayRequest) => Promise<void>
  ): Promise<void> {
    const event: SecurityEvent = {
      type: 'anomaly_detected',
      timestamp: Date.now(),
      severity: anomaly.composite >= 75 ? 'high' : 'medium',
      source: 'sentinel-mcp',
      data: anomaly,
    };

    await this.publishEvent(event, sendRequest);
  }
}
