/**
 * Tests for Sentinel Gateway Bridge
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SentinelGatewayBridge } from '../../gateway/sentinel-bridge.js';
import type { SecurityEvent, SecurityStatus } from '../../gateway/types.js';
import WebSocket from 'ws';

// Mock WebSocket
vi.mock('ws');

describe('SentinelGatewayBridge', () => {
  let bridge: SentinelGatewayBridge;
  let mockWs: any;
  let messageHandler: any;

  const autoRespondToRequests = () => {
    mockWs.send.mockImplementation((data: string, callback: any) => {
      const request = JSON.parse(data);
      // Auto-respond to all requests with success
      setTimeout(() => {
        messageHandler?.(JSON.stringify({
          id: request.id,
          success: true,
          payload: request.method === 'sentinel.getStatus' ? {
            mode: 'alert',
            activeAlerts: 0,
            totalViolations24h: 0,
            riskScore: 0,
            lastUpdate: Date.now(),
          } : {},
        }));
      }, 0);
      callback?.(null);
    });
  };

  beforeEach(() => {
    mockWs = {
      on: vi.fn(),
      send: vi.fn((data, callback) => callback?.(null)),
      close: vi.fn(),
    };

    (WebSocket as any).mockImplementation(() => mockWs);

    bridge = new SentinelGatewayBridge({
      gatewayUrl: 'ws://localhost:18789',
      requestTimeout: 1000,
    });

    // Capture message handler for auto-responses
    mockWs.on.mockImplementation((event: string, handler: any) => {
      if (event === 'message') {
        messageHandler = handler;
      }
    });
  });

  afterEach(async () => {
    await bridge.disconnect();
    vi.clearAllMocks();
  });

  describe('Connection Management', () => {
    it('should connect to Gateway WebSocket', async () => {
      const connectPromise = bridge.connect();

      // Simulate WebSocket open event
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();

      await connectPromise;

      expect(bridge.isConnected()).toBe(true);
      expect(WebSocket).toHaveBeenCalledWith('ws://localhost:18789');
    });

    it('should handle connection errors', async () => {
      const connectPromise = bridge.connect();

      // Simulate WebSocket error event
      const errorHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'error')?.[1];
      errorHandler?.(new Error('Connection failed'));

      await expect(connectPromise).rejects.toThrow('Connection failed');
    });

    it('should disconnect gracefully', async () => {
      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;

      await bridge.disconnect();

      expect(mockWs.close).toHaveBeenCalled();
      expect(bridge.isConnected()).toBe(false);
    });

    it('should send connect message on open', async () => {
      autoRespondToRequests();
      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;

      // Wait for connect message
      await new Promise(resolve => setTimeout(resolve, 50));

      // Check that connect message was sent
      const sendCalls = mockWs.send.mock.calls;
      const connectMessage = sendCalls.find((call: any) => {
        try {
          const data = JSON.parse(call[0]);
          return data.method === 'connect';
        } catch {
          return false;
        }
      });

      expect(connectMessage).toBeDefined();
      const connectData = JSON.parse(connectMessage[0]);
      expect(connectData.params.role).toBe('sentinel');
      expect(connectData.params.scopes).toContain('security');
      expect(connectData.params.scopes).toContain('audit');
    });
  });

  describe('Event Publishing', () => {
    beforeEach(async () => {
      autoRespondToRequests();
      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;
    });

    it('should publish security violation event', async () => {
      const event: SecurityEvent = {
        type: 'violation',
        timestamp: Date.now(),
        severity: 'high',
        source: 'sentinel-mcp',
        data: {
          tool: 'fleet_ssh',
          host: 'hyperion',
          reason: 'Dangerous command detected',
        },
      };

      await bridge.publishEvent(event);

      const sendCalls = mockWs.send.mock.calls;
      const eventMessage = sendCalls.find((call: any) => {
        try {
          const data = JSON.parse(call[0]);
          return data.method === 'sentinel.publishEvent';
        } catch {
          return false;
        }
      });

      expect(eventMessage).toBeDefined();
      const eventData = JSON.parse(eventMessage[0]);
      expect(eventData.params.type).toBe('violation');
      expect(eventData.params.severity).toBe('high');
    });

    it('should publish approval required event', async () => {
      const event: SecurityEvent = {
        type: 'approval_required',
        timestamp: Date.now(),
        severity: 'medium',
        source: 'sentinel-mcp',
        data: {
          tool: 'fleet_ssh',
          confirmationToken: 'abc123',
        },
      };

      await bridge.publishEvent(event);

      const sendCalls = mockWs.send.mock.calls;
      const eventMessage = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.publishEvent';
      });

      expect(eventMessage).toBeDefined();
      const eventData = JSON.parse(eventMessage[0]);
      expect(eventData.params.type).toBe('approval_required');
    });

    it('should publish audit log entry', async () => {
      const event: SecurityEvent = {
        type: 'audit_entry',
        timestamp: Date.now(),
        severity: 'low',
        source: 'sentinel-mcp',
        data: {
          sequenceNumber: 42,
          tool: 'fleet_ssh',
          verdict: 'allowed',
        },
      };

      await bridge.publishEvent(event);

      const sendCalls = mockWs.send.mock.calls;
      const eventMessage = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.publishEvent';
      });

      expect(eventMessage).toBeDefined();
    });

    it('should publish cost threshold alert', async () => {
      const event: SecurityEvent = {
        type: 'cost_threshold',
        timestamp: Date.now(),
        severity: 'high',
        source: 'sentinel-mcp',
        data: {
          currentCost: 150,
          threshold: 100,
          period: 'daily',
        },
      };

      await bridge.publishEvent(event);

      const sendCalls = mockWs.send.mock.calls;
      const eventMessage = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.publishEvent';
      });

      expect(eventMessage).toBeDefined();
      const eventData = JSON.parse(eventMessage[0]);
      expect(eventData.params.severity).toBe('high');
    });

    it('should throw error when publishing while disconnected', async () => {
      await bridge.disconnect();

      const event: SecurityEvent = {
        type: 'violation',
        timestamp: Date.now(),
        severity: 'high',
        source: 'sentinel-mcp',
        data: {},
      };

      await expect(bridge.publishEvent(event)).rejects.toThrow('Not connected');
    });
  });

  describe('Security Status', () => {
    beforeEach(async () => {
      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;
    });

    it('should get security status', async () => {
      const statusPromise = bridge.getSecurityStatus();

      // Simulate response
      const messageHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'message')?.[1];
      const sendCalls = mockWs.send.mock.calls;
      const statusRequest = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.getStatus';
      });

      const requestId = JSON.parse(statusRequest[0]).id;
      const response = {
        id: requestId,
        success: true,
        payload: {
          mode: 'alert',
          activeAlerts: 3,
          totalViolations24h: 15,
          riskScore: 42,
          lastUpdate: Date.now(),
        } as SecurityStatus,
      };

      messageHandler?.(JSON.stringify(response));

      const status = await statusPromise;

      expect(status.mode).toBe('alert');
      expect(status.activeAlerts).toBe(3);
      expect(status.riskScore).toBe(42);
    });

    it('should handle status request errors', async () => {
      const statusPromise = bridge.getSecurityStatus();

      const messageHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'message')?.[1];
      const sendCalls = mockWs.send.mock.calls;
      const statusRequest = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.getStatus';
      });

      const requestId = JSON.parse(statusRequest[0]).id;
      const response = {
        id: requestId,
        success: false,
        error: {
          code: 500,
          message: 'Internal error',
        },
      };

      messageHandler?.(JSON.stringify(response));

      await expect(statusPromise).rejects.toThrow('Failed to get security status');
    });
  });

  describe('Alert Subscription', () => {
    beforeEach(async () => {
      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;
    });

    it('should subscribe to security alerts', async () => {
      const alertIterator = bridge.subscribeToAlerts();

      // Check subscription was sent
      const sendCalls = mockWs.send.mock.calls;
      const subMessage = sendCalls.find((call: any) => {
        const data = JSON.parse(call[0]);
        return data.method === 'sentinel.subscribe';
      });

      expect(subMessage).toBeDefined();
      const subData = JSON.parse(subMessage[0]);
      expect(subData.params.events).toContain('security_alert');

      // Simulate alert event
      const messageHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'message')?.[1];
      const alert = {
        event: 'security_alert',
        data: {
          id: 'alert-1',
          type: 'violation',
          timestamp: Date.now(),
          severity: 'high',
          message: 'Dangerous command blocked',
          details: {},
          acknowledged: false,
        },
      };

      setTimeout(() => {
        messageHandler?.(JSON.stringify(alert));
      }, 10);

      const result = await alertIterator.next();
      expect(result.value).toBeDefined();
      expect(result.value?.type).toBe('violation');
      expect(result.value?.severity).toBe('high');
    });
  });

  describe('Request Timeout', () => {
    beforeEach(async () => {
      bridge = new SentinelGatewayBridge({
        gatewayUrl: 'ws://localhost:18789',
        requestTimeout: 100, // Short timeout for testing
      });

      const connectPromise = bridge.connect();
      const openHandler = mockWs.on.mock.calls.find((call: any) => call[0] === 'open')?.[1];
      openHandler?.();
      await connectPromise;
    });

    it('should timeout requests that take too long', async () => {
      const statusPromise = bridge.getSecurityStatus();

      // Don't send response - let it timeout
      await expect(statusPromise).rejects.toThrow('Request timeout');
    });
  });
});
