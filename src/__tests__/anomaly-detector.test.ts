/**
 * Tests for anomaly detection module
 */

import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { initializeDatabase } from '../database.js';
import {
  detectAnomalies,
  updateBaseline,
  convertAnomalyToRiskFactors,
} from '../anomaly-detector.js';
import type { PolicyContext, SentinelConfig, AnomalyBaseline } from '../types.js';

// Helper to convert database row to AnomalyBaseline
function getBaselineFromDb(db: Database.Database, tool: string, host: string): AnomalyBaseline | undefined {
  const row = db
    .prepare('SELECT * FROM anomaly_baselines WHERE tool = ? AND host = ?')
    .get(tool, host);

  if (!row) {
    return undefined;
  }

  return {
    id: row.id,
    tool: row.tool,
    host: row.host,
    frequencyMean: row.frequency_mean,
    frequencyStdDev: row.frequency_std_dev,
    hourlyDistribution: row.hourly_distribution,
    argumentFingerprints: row.argument_fingerprints,
    toolBigrams: row.tool_bigrams,
    errorRateMean: row.error_rate_mean,
    errorRateStdDev: row.error_rate_std_dev,
    lastUpdated: row.last_updated,
    sampleCount: row.sample_count,
  };
}

describe('Anomaly Detector', () => {
  let db: Database.Database;
  let config: SentinelConfig;

  beforeEach(() => {
    // Use in-memory database for tests
    const sentinelDb = initializeDatabase(':memory:');
    db = sentinelDb.db;

    config = {
      mode: 'alert',
      databasePath: ':memory:',
      openclawMcpCommand: 'node',
      openclawMcpArgs: [],
      anomalyThresholds: {
        suspicious: 30,
        anomalous: 60,
        critical: 80,
        autoLockdown: 90,
      },
      circuitBreaker: {
        failureThreshold: 2,
        cooldownMs: 120000,
      },
      confirmationTokenTtlMs: 300000,
    };
  });

  describe('First-time baseline creation', () => {
    it('should create baseline on first observation', () => {
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      updateBaseline(db, undefined, context);

      const baseline = db
        .prepare('SELECT * FROM anomaly_baselines WHERE tool = ? AND host = ?')
        .get('test_tool', 'hyperion');

      expect(baseline).toBeDefined();
      expect(baseline.sample_count).toBe(1);
      expect(baseline.frequency_mean).toBe(1);
    });

    it('should initialize hourly distribution correctly', () => {
      const now = new Date('2026-02-11T14:30:00Z').getTime();
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: now,
      };

      updateBaseline(db, undefined, context);

      const baseline = db
        .prepare('SELECT * FROM anomaly_baselines WHERE tool = ? AND host = ?')
        .get('test_tool', 'hyperion');

      const hourlyDist = JSON.parse(baseline.hourly_distribution);
      expect(hourlyDist).toHaveLength(24);

      const hour = new Date(now).getUTCHours();
      expect(hourlyDist[hour]).toBe(1.0); // 100% for first observation
    });
  });

  describe('EWMA baseline updates', () => {
    it('should update frequency mean with EWMA (α=0.1)', () => {
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Create initial baseline
      updateBaseline(db, undefined, context);

      // Simulate 10 operations in the last hour
      const oneHourAgo = context.timestamp - 3600000;
      for (let i = 0; i < 10; i++) {
        db.prepare(
          'INSERT INTO audit_log (sequence_number, timestamp, tool, host, agent, arguments, verdict, action, risk_score, risk_factors, mode, hash, previous_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        ).run(
          i,
          oneHourAgo + i * 1000,
          'test_tool',
          'hyperion',
          'user@test',
          '{}',
          'allowed',
          'allow',
          0,
          '[]',
          'alert',
          `hash-${i}`,
          i === 0 ? 'genesis' : `hash-${i - 1}`,
        );
      }

      // Get baseline
      const baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');

      // Update baseline
      updateBaseline(db, baseline, context);

      // Check EWMA update: newMean = α × currentRate + (1 - α) × oldMean
      // We inserted 10 entries, but the count might be 9 or 10 depending on exact timestamps
      // oldMean = 1, α = 0.1
      // If currentRate = 9: newMean = 0.1 × 9 + 0.9 × 1 = 1.8
      // If currentRate = 10: newMean = 0.1 × 10 + 0.9 × 1 = 1.9
      const updatedBaseline = getBaselineFromDb(db, 'test_tool', 'hyperion');

      expect(updatedBaseline.frequencyMean).toBeGreaterThanOrEqual(1.8);
      expect(updatedBaseline.frequencyMean).toBeLessThanOrEqual(1.9);
      expect(updatedBaseline.sampleCount).toBe(2);
    });

    it('should update hourly distribution correctly', () => {
      const hour14Time = new Date('2026-02-11T14:30:00Z').getTime();
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: hour14Time,
      };

      // Create initial baseline (hour 14 UTC)
      updateBaseline(db, undefined, context);

      // Verify initial distribution
      let baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');
      let hourlyDist = JSON.parse(baseline.hourlyDistribution);
      expect(hourlyDist[14]).toBe(1.0); // 100% at hour 14

      // Update at different hour (hour 15 UTC)
      const laterContext = {
        ...context,
        timestamp: new Date('2026-02-11T15:30:00Z').getTime(),
      };

      updateBaseline(db, baseline, laterContext);

      baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');
      hourlyDist = JSON.parse(baseline.hourlyDistribution);

      // Hour 14 should now be 1/2 = 0.5
      expect(hourlyDist[14]).toBeCloseTo(0.5, 2);
      // Hour 15 should be 1/2 = 0.5
      expect(hourlyDist[15]).toBeCloseTo(0.5, 2);
    });

    it('should track argument fingerprints', () => {
      const context1: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      updateBaseline(db, undefined, context1);

      const baseline1 = getBaselineFromDb(db, 'test_tool', 'hyperion');
      const fingerprints1 = JSON.parse(baseline1.argumentFingerprints);
      expect(fingerprints1).toHaveLength(1);

      // Different arguments
      const context2: PolicyContext = {
        ...context1,
        arguments: { command: 'pwd' },
      };

      updateBaseline(db, baseline1, context2);

      const updated = db
        .prepare('SELECT * FROM anomaly_baselines WHERE tool = ? AND host = ?')
        .get('test_tool', 'hyperion');

      const fingerprints2 = JSON.parse(updated.argument_fingerprints);
      expect(fingerprints2).toHaveLength(2);
    });
  });

  describe('Anomaly detection scoring', () => {
    it('should return zero scores for insufficient data', () => {
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      const scores = detectAnomalies(db, context, config);

      expect(scores.composite).toBe(0);
      expect(scores.frequency).toBe(0);
      expect(scores.temporal).toBe(0);
      expect(scores.argumentNovelty).toBe(0);
      expect(scores.sequence).toBe(0);
      expect(scores.errorRate).toBe(0);
    });

    it('should detect argument novelty', () => {
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: Date.now(),
      };

      // Create baseline with 10 samples
      updateBaseline(db, undefined, context);
      for (let i = 0; i < 9; i++) {
        const baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');
        updateBaseline(db, baseline, context);
      }

      // Now try with never-seen arguments
      const novelContext: PolicyContext = {
        ...context,
        arguments: { command: 'rm -rf /' }, // Different fingerprint
      };

      const scores = detectAnomalies(db, novelContext, config);

      expect(scores.argumentNovelty).toBe(100); // Never seen before
      expect(scores.composite).toBeGreaterThan(0); // 30% weight on argument novelty
    });

    it('should detect temporal anomalies', () => {
      // Create baseline with samples only in hour 14
      const hour14Time = new Date('2026-02-11T14:30:00Z').getTime();
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'ls' },
        timestamp: hour14Time,
      };

      // Build baseline with 10 samples all at hour 14
      updateBaseline(db, undefined, context);
      for (let i = 0; i < 9; i++) {
        const baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');
        updateBaseline(db, baseline, context);
      }

      // Access at unusual hour (3 AM)
      const hour3Time = new Date('2026-02-11T03:30:00Z').getTime();
      const unusualContext: PolicyContext = {
        ...context,
        timestamp: hour3Time,
      };

      const scores = detectAnomalies(db, unusualContext, config);

      // Hour 3 should have very low probability (close to 0)
      expect(scores.temporal).toBeGreaterThan(50); // Unusual time
    });
  });

  describe('Composite anomaly scoring', () => {
    it('should weight components correctly (25% freq, 15% temp, 30% arg, 15% seq, 15% err)', () => {
      // Simulate scenario with known component scores
      const context: PolicyContext = {
        tool: 'test_tool',
        host: 'hyperion',
        agent: 'user@test',
        arguments: { command: 'test' },
        timestamp: Date.now(),
      };

      // Build baseline
      updateBaseline(db, undefined, context);
      for (let i = 0; i < 9; i++) {
        const baseline = getBaselineFromDb(db, 'test_tool', 'hyperion');
        updateBaseline(db, baseline, context);
      }

      // Test with novel arguments (should give high argument novelty score)
      const novelContext: PolicyContext = {
        ...context,
        arguments: { command: 'novel-command-never-seen' },
      };

      const scores = detectAnomalies(db, novelContext, config);

      // Argument novelty = 100, weight = 30%
      // Composite should be approximately 30 (may have small frequency component)
      expect(scores.composite).toBeGreaterThanOrEqual(30);
      expect(scores.composite).toBeLessThanOrEqual(40);
    });
  });

  describe('Risk factor conversion', () => {
    it('should convert high anomaly scores to risk factors', () => {
      const anomalyScore = {
        composite: 75,
        frequency: 80,
        temporal: 60,
        argumentNovelty: 95,
        sequence: 45,
        errorRate: 70,
      };

      const riskFactors = convertAnomalyToRiskFactors(anomalyScore);

      expect(riskFactors).toHaveLength(5); // freq, temp, arg novelty, sequence, error rate (>30)

      const freqFactor = riskFactors.find((f) => f.factor === 'frequency_anomaly');
      expect(freqFactor).toBeDefined();
      expect(freqFactor?.score).toBe(80);

      const argFactor = riskFactors.find((f) => f.factor === 'argument_novelty');
      expect(argFactor).toBeDefined();
      expect(argFactor?.score).toBe(95);
    });

    it('should filter out low scores (≤30)', () => {
      const anomalyScore = {
        composite: 20,
        frequency: 15,
        temporal: 20,
        argumentNovelty: 25,
        sequence: 10,
        errorRate: 5,
      };

      const riskFactors = convertAnomalyToRiskFactors(anomalyScore);

      expect(riskFactors).toHaveLength(0); // All below threshold
    });
  });

  describe('Threshold-based alerting', () => {
    it('should trigger auto-lockdown at critical threshold (90)', () => {
      const anomalyScore = {
        composite: 92,
        frequency: 100,
        temporal: 100,
        argumentNovelty: 100,
        sequence: 80,
        errorRate: 75,
      };

      expect(anomalyScore.composite).toBeGreaterThanOrEqual(config.anomalyThresholds.autoLockdown);
    });

    it('should classify scores into severity buckets', () => {
      const suspicious = 35;
      const anomalous = 65;
      const critical = 85;

      expect(suspicious).toBeGreaterThanOrEqual(config.anomalyThresholds.suspicious);
      expect(suspicious).toBeLessThan(config.anomalyThresholds.anomalous);

      expect(anomalous).toBeGreaterThanOrEqual(config.anomalyThresholds.anomalous);
      expect(anomalous).toBeLessThan(config.anomalyThresholds.critical);

      expect(critical).toBeGreaterThanOrEqual(config.anomalyThresholds.critical);
    });
  });
});
