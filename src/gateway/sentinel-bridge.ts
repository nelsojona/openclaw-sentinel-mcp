/**
 * Sentinel Gateway Bridge
 *
 * Bridges Sentinel security events to the OpenClaw Gateway WebSocket for centralized monitoring.
 */

import WebSocket from 'ws';
import type {
  SecurityEvent,
  SecurityAlert,
  SecurityStatus,
  GatewayRequest,
  GatewayResponse,
  GatewayEvent,
} from './types.js';
import { EventPublisher } from './event-publisher.js';

export interface SentinelGatewayBridgeConfig {
  gatewayUrl?: string;
  reconnectInterval?: number;
  requestTimeout?: number;
}

export class SentinelGatewayBridge {
  private ws: WebSocket | null = null;
  private connected = false;
  private readonly gatewayUrl: string;
  private readonly reconnectInterval: number;
  private readonly requestTimeout: number;
  private readonly eventPublisher: EventPublisher;
  private pendingRequests = new Map<string, {
    resolve: (value: GatewayResponse) => void;
    reject: (error: Error) => void;
    timeout: NodeJS.Timeout;
  }>();
  private alertSubscribers: Array<(alert: SecurityAlert) => void> = [];

  constructor(config: SentinelGatewayBridgeConfig = {}) {
    this.gatewayUrl = config.gatewayUrl ?? 'ws://127.0.0.1:18789';
    this.reconnectInterval = config.reconnectInterval ?? 5000;
    this.requestTimeout = config.requestTimeout ?? 30000;
    this.eventPublisher = new EventPublisher();
  }

  /**
   * Connect to the Gateway WebSocket
   */
  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    return new Promise((resolve, reject) => {
      try {
        this.ws = new WebSocket(this.gatewayUrl);

        this.ws.on('open', () => {
          this.connected = true;
          this.handleConnect();
          resolve();
        });

        this.ws.on('message', (data: WebSocket.RawData) => {
          this.handleMessage(data.toString());
        });

        this.ws.on('close', () => {
          this.connected = false;
          this.handleDisconnect();
        });

        this.ws.on('error', (error) => {
          reject(error);
        });
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Disconnect from the Gateway
   */
  async disconnect(): Promise<void> {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
      this.connected = false;
    }
  }

  /**
   * Publish a security event to the Gateway
   */
  async publishEvent(event: SecurityEvent): Promise<void> {
    await this.eventPublisher.publishEvent(event, (request) => this.sendRequest(request));
  }

  /**
   * Subscribe to security alerts from the Gateway
   */
  async *subscribeToAlerts(): AsyncIterableIterator<SecurityAlert> {
    // Send subscription request
    await this.sendRequest({
      id: `sub-alerts-${Date.now()}`,
      method: 'sentinel.subscribe',
      params: { events: ['security_alert'] },
    });

    // Yield alerts as they arrive
    while (this.connected) {
      const alert = await this.waitForAlert();
      if (alert) {
        yield alert;
      }
    }
  }

  /**
   * Get current security status from Sentinel
   */
  async getSecurityStatus(): Promise<SecurityStatus> {
    const response = await this.sendRequest({
      id: `status-${Date.now()}`,
      method: 'sentinel.getStatus',
    });

    if (!response.success || !response.payload) {
      throw new Error('Failed to get security status');
    }

    return response.payload as SecurityStatus;
  }

  /**
   * Check if connected to Gateway
   */
  isConnected(): boolean {
    return this.connected;
  }

  // Private methods

  private handleConnect(): void {
    // Send connect message with Sentinel role
    this.sendRequest({
      id: 'connect',
      method: 'connect',
      params: {
        version: 3,
        clientInfo: {
          id: 'sentinel-mcp',
          version: '1.0.0',
          platform: 'node',
        },
        role: 'sentinel',
        scopes: ['security', 'audit'],
      },
    }).catch((error) => {
      console.error('Failed to send connect message:', error);
    });
  }

  private handleDisconnect(): void {
    // Clean up pending requests
    for (const [, pending] of this.pendingRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('Disconnected from Gateway'));
    }
    this.pendingRequests.clear();

    // Attempt reconnection if not explicitly disconnected
    if (this.ws) {
      setTimeout(() => {
        this.connect().catch((error) => {
          console.error('Reconnection failed:', error);
        });
      }, this.reconnectInterval);
    }
  }

  private handleMessage(message: string): void {
    try {
      const data = JSON.parse(message) as GatewayResponse | GatewayEvent;

      if ('id' in data) {
        // Response to our request
        this.handleResponse(data as GatewayResponse);
      } else if ('event' in data) {
        // Event from Gateway
        this.handleEvent(data as GatewayEvent);
      }
    } catch (error) {
      console.error('Failed to parse Gateway message:', error);
    }
  }

  private handleResponse(response: GatewayResponse): void {
    const pending = this.pendingRequests.get(response.id);
    if (pending) {
      clearTimeout(pending.timeout);
      this.pendingRequests.delete(response.id);
      pending.resolve(response);
    }
  }

  private handleEvent(event: GatewayEvent): void {
    if (event.event === 'security_alert') {
      const alert = event.data as SecurityAlert;
      for (const subscriber of this.alertSubscribers) {
        subscriber(alert);
      }
    }
  }

  private async sendRequest(request: GatewayRequest): Promise<GatewayResponse> {
    if (!this.connected || !this.ws) {
      throw new Error('Not connected to Gateway');
    }

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(request.id);
        reject(new Error(`Request timeout: ${request.method}`));
      }, this.requestTimeout);

      this.pendingRequests.set(request.id, { resolve, reject, timeout });

      this.ws!.send(JSON.stringify(request), (error) => {
        if (error) {
          clearTimeout(timeout);
          this.pendingRequests.delete(request.id);
          reject(error);
        }
      });
    });
  }

  private async waitForAlert(): Promise<SecurityAlert | null> {
    return new Promise((resolve) => {
      const subscriber = (alert: SecurityAlert) => {
        const index = this.alertSubscribers.indexOf(subscriber);
        if (index > -1) {
          this.alertSubscribers.splice(index, 1);
        }
        resolve(alert);
      };

      this.alertSubscribers.push(subscriber);

      // Timeout after 60 seconds
      setTimeout(() => {
        const index = this.alertSubscribers.indexOf(subscriber);
        if (index > -1) {
          this.alertSubscribers.splice(index, 1);
        }
        resolve(null);
      }, 60000);
    });
  }
}
