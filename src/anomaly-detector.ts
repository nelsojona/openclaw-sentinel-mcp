/**
 * Anomaly detection using EWMA (Exponentially Weighted Moving Average)
 *
 * Five weighted components:
 * - Frequency (25%): Z-score of ops/hour vs baseline
 * - Temporal (15%): Probability of this hour vs distribution
 * - Argument novelty (30%): Never-seen argument fingerprint
 * - Sequence (15%): Unusual tool call bigram
 * - Error rate (15%): Error rate spike vs baseline
 *
 * EWMA formula: frequencyMean = α × currentRate + (1 - α) × frequencyMean
 * where α = 0.1 (smoothing factor)
 */

import type Database from 'better-sqlite3';
import { createHash } from 'node:crypto';
import type {
  PolicyContext,
  AnomalyBaseline,
  AnomalyBaselineRow,
  AnomalyScore,
  RiskFactor,
  SentinelConfig,
} from './types.js';

const ALPHA = 0.1; // EWMA smoothing factor

/**
 * Compute hash fingerprint of arguments
 *
 * @param args - Arguments object
 * @returns SHA256 hash
 */
function hashArguments(args: Record<string, unknown>): string {
  const normalized = JSON.stringify(args, Object.keys(args).sort());
  return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Calculate Z-score
 *
 * @param value - Current value
 * @param mean - Mean
 * @param stdDev - Standard deviation
 * @returns Z-score
 */
function zScore(value: number, mean: number, stdDev: number): number {
  if (stdDev === 0) {
    return 0;
  }
  return Math.abs((value - mean) / stdDev);
}

/**
 * Normalize score to 0-100 range
 *
 * @param score - Raw score
 * @param max - Maximum expected score (e.g., 3 for Z-score)
 * @returns Normalized score (0-100)
 */
function normalizeScore(score: number, max: number): number {
  return Math.min(100, (score / max) * 100);
}

/**
 * Get baseline for tool/host pair
 *
 * @param db - Database connection
 * @param tool - Tool name
 * @param host - Host identifier
 * @returns Baseline or undefined
 */
function getBaseline(
  db: Database.Database,
  tool: string,
  host: string,
): AnomalyBaseline | undefined {
  const row = db
    .prepare('SELECT * FROM anomaly_baselines WHERE tool = ? AND host = ?')
    .get(tool, host) as AnomalyBaselineRow | undefined;

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

/**
 * Calculate frequency component score
 *
 * Measures how unusual the current operation rate is compared to baseline.
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param baseline - Baseline (or undefined for first-time)
 * @returns Score (0-100)
 */
function calculateFrequencyScore(
  db: Database.Database,
  context: PolicyContext,
  baseline: AnomalyBaseline | undefined,
): number {
  if (!baseline || baseline.sampleCount < 10) {
    return 0; // Not enough data
  }

  // Count operations in last hour for this tool/host
  const oneHourAgo = context.timestamp - 3600000;
  const count = (
    db
      .prepare('SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ?')
      .get(context.tool, context.host, oneHourAgo) as { count: number }
  ).count;

  const currentRate = count; // ops/hour
  const z = zScore(currentRate, baseline.frequencyMean, baseline.frequencyStdDev);

  // Z-score > 3 is highly unusual (99.7% confidence)
  return normalizeScore(z, 3);
}

/**
 * Calculate temporal component score
 *
 * Measures how unusual this time-of-day is for this tool/host.
 *
 * @param context - Policy context
 * @param baseline - Baseline (or undefined for first-time)
 * @returns Score (0-100)
 */
function calculateTemporalScore(
  context: PolicyContext,
  baseline: AnomalyBaseline | undefined,
): number {
  if (!baseline || baseline.sampleCount < 10) {
    return 0; // Not enough data
  }

  const hour = new Date(context.timestamp).getUTCHours(); // 0-23
  const distribution = JSON.parse(baseline.hourlyDistribution) as number[];

  if (distribution.length !== 24) {
    return 0; // Invalid distribution
  }

  const probability = distribution[hour];

  // Low probability = high anomaly score
  // P < 0.01 (1%) is highly unusual
  if (probability < 0.01) {
    return 100;
  }

  if (probability < 0.05) {
    return 75;
  }

  if (probability < 0.1) {
    return 50;
  }

  return 0;
}

/**
 * Calculate argument novelty component score
 *
 * Measures if we've seen these exact arguments before.
 *
 * @param context - Policy context
 * @param baseline - Baseline (or undefined for first-time)
 * @returns Score (0-100)
 */
function calculateArgumentNoveltyScore(
  context: PolicyContext,
  baseline: AnomalyBaseline | undefined,
): number {
  if (!baseline || baseline.sampleCount < 10) {
    return 0; // Not enough data
  }

  const fingerprint = hashArguments(context.arguments);
  const fingerprints = JSON.parse(baseline.argumentFingerprints) as string[];

  // Never seen this exact argument set before
  if (!fingerprints.includes(fingerprint)) {
    return 100;
  }

  return 0;
}

/**
 * Calculate sequence component score
 *
 * Measures if this tool call bigram (previous tool → current tool) is unusual.
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param baseline - Baseline (or undefined for first-time)
 * @returns Score (0-100)
 */
function calculateSequenceScore(
  db: Database.Database,
  context: PolicyContext,
  baseline: AnomalyBaseline | undefined,
): number {
  if (!baseline || baseline.sampleCount < 10) {
    return 0; // Not enough data
  }

  // Get last tool call for this host
  const lastTool = db
    .prepare('SELECT tool FROM audit_log WHERE host = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT 1')
    .get(context.host, context.timestamp) as { tool: string } | undefined;

  if (!lastTool) {
    return 0; // No previous tool call
  }

  const bigram = `${lastTool.tool}→${context.tool}`;
  const bigrams = JSON.parse(baseline.toolBigrams) as Record<string, number>;

  const probability = bigrams[bigram] ?? 0;

  // Never seen this sequence before
  if (probability === 0) {
    return 100;
  }

  // Rare sequence
  if (probability < 0.01) {
    return 75;
  }

  if (probability < 0.05) {
    return 50;
  }

  return 0;
}

/**
 * Calculate error rate component score
 *
 * Measures if error rate is spiking compared to baseline.
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param baseline - Baseline (or undefined for first-time)
 * @returns Score (0-100)
 */
function calculateErrorRateScore(
  db: Database.Database,
  context: PolicyContext,
  baseline: AnomalyBaseline | undefined,
): number {
  if (!baseline || baseline.sampleCount < 10) {
    return 0; // Not enough data
  }

  // Count errors in last hour for this tool/host
  const oneHourAgo = context.timestamp - 3600000;
  const total = (
    db
      .prepare('SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ?')
      .get(context.tool, context.host, oneHourAgo) as { count: number }
  ).count;

  const errors = (
    db
      .prepare(
        'SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ? AND response_status = ?',
      )
      .get(context.tool, context.host, oneHourAgo, 'error') as { count: number }
  ).count;

  const currentErrorRate = total > 0 ? errors / total : 0;
  const z = zScore(currentErrorRate, baseline.errorRateMean, baseline.errorRateStdDev);

  // Z-score > 3 is highly unusual
  return normalizeScore(z, 3);
}

/**
 * Detect anomalies for a given context
 *
 * Computes composite anomaly score from five weighted components.
 *
 * @param db - Database connection
 * @param context - Policy context
 * @param config - Sentinel configuration
 * @returns Anomaly score breakdown
 */
export function detectAnomalies(
  db: Database.Database,
  context: PolicyContext,
  config: SentinelConfig,
): AnomalyScore {
  const baseline = getBaseline(db, context.tool, context.host);

  const frequency = calculateFrequencyScore(db, context, baseline);
  const temporal = calculateTemporalScore(context, baseline);
  const argumentNovelty = calculateArgumentNoveltyScore(context, baseline);
  const sequence = calculateSequenceScore(db, context, baseline);
  const errorRate = calculateErrorRateScore(db, context, baseline);

  // Weighted average
  const composite =
    frequency * 0.25 + temporal * 0.15 + argumentNovelty * 0.3 + sequence * 0.15 + errorRate * 0.15;

  return {
    composite,
    frequency,
    temporal,
    argumentNovelty,
    sequence,
    errorRate,
  };
}

/**
 * Update baseline with new observation using EWMA
 *
 * EWMA formula: newMean = α × currentValue + (1 - α) × oldMean
 *
 * @param db - Database connection
 * @param baseline - Current baseline (or undefined for first-time)
 * @param context - Policy context
 * @param alpha - EWMA smoothing factor (default: 0.1)
 */
export function updateBaseline(
  db: Database.Database,
  baseline: AnomalyBaseline | undefined,
  context: PolicyContext,
  alpha: number = ALPHA,
): void {
  const now = Date.now();
  const hour = new Date(context.timestamp).getUTCHours();
  const argFingerprint = hashArguments(context.arguments);

  if (!baseline) {
    // First-time observation - initialize baseline
    const hourlyDistribution = new Array(24).fill(0);
    hourlyDistribution[hour] = 1.0; // 100% probability for this hour

    const row: Omit<AnomalyBaselineRow, 'id'> = {
      tool: context.tool,
      host: context.host,
      frequency_mean: 1, // 1 op/hour
      frequency_std_dev: 0,
      hourly_distribution: JSON.stringify(hourlyDistribution),
      argument_fingerprints: JSON.stringify([argFingerprint]),
      tool_bigrams: JSON.stringify({}),
      error_rate_mean: 0,
      error_rate_std_dev: 0,
      last_updated: now,
      sample_count: 1,
    };

    db.prepare(
      `INSERT INTO anomaly_baselines (
        tool, host, frequency_mean, frequency_std_dev, hourly_distribution,
        argument_fingerprints, tool_bigrams, error_rate_mean, error_rate_std_dev,
        last_updated, sample_count
      ) VALUES (
        @tool, @host, @frequency_mean, @frequency_std_dev, @hourly_distribution,
        @argument_fingerprints, @tool_bigrams, @error_rate_mean, @error_rate_std_dev,
        @last_updated, @sample_count
      )
      ON CONFLICT(tool, host) DO UPDATE SET
        frequency_mean = @frequency_mean,
        frequency_std_dev = @frequency_std_dev,
        hourly_distribution = @hourly_distribution,
        argument_fingerprints = @argument_fingerprints,
        tool_bigrams = @tool_bigrams,
        error_rate_mean = @error_rate_mean,
        error_rate_std_dev = @error_rate_std_dev,
        last_updated = @last_updated,
        sample_count = @sample_count
      `,
    ).run(row);

    return;
  }

  // Update frequency mean and std dev
  const oneHourAgo = context.timestamp - 3600000;
  const currentRate = (
    db
      .prepare('SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ?')
      .get(context.tool, context.host, oneHourAgo) as { count: number }
  ).count;

  const newFrequencyMean = alpha * currentRate + (1 - alpha) * baseline.frequencyMean;

  // Update variance using Welford's online algorithm
  const delta = currentRate - baseline.frequencyMean;
  const delta2 = currentRate - newFrequencyMean;
  const variance =
    baseline.frequencyStdDev ** 2 + (delta * delta2 - baseline.frequencyStdDev ** 2) / (baseline.sampleCount + 1);
  const newFrequencyStdDev = Math.sqrt(Math.max(0, variance));

  // Update hourly distribution
  const hourlyDistribution = JSON.parse(baseline.hourlyDistribution) as number[];
  const totalCount = baseline.sampleCount + 1;
  for (let h = 0; h < 24; h++) {
    if (h === hour) {
      hourlyDistribution[h] = (hourlyDistribution[h] * baseline.sampleCount + 1) / totalCount;
    } else {
      hourlyDistribution[h] = (hourlyDistribution[h] * baseline.sampleCount) / totalCount;
    }
  }

  // Update argument fingerprints (keep last 1000)
  const fingerprints = JSON.parse(baseline.argumentFingerprints) as string[];
  if (!fingerprints.includes(argFingerprint)) {
    fingerprints.push(argFingerprint);
    if (fingerprints.length > 1000) {
      fingerprints.shift();
    }
  }

  // Update tool bigrams
  const lastTool = db
    .prepare('SELECT tool FROM audit_log WHERE host = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT 1')
    .get(context.host, context.timestamp) as { tool: string } | undefined;

  const bigrams = JSON.parse(baseline.toolBigrams) as Record<string, number>;
  if (lastTool) {
    const bigram = `${lastTool.tool}→${context.tool}`;
    const currentBigramCount = bigrams[bigram] ?? 0;
    // Update with EWMA
    bigrams[bigram] = alpha * 1 + (1 - alpha) * currentBigramCount;
  }

  // Update error rate
  const total = (
    db
      .prepare('SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ?')
      .get(context.tool, context.host, oneHourAgo) as { count: number }
  ).count;

  const errors = (
    db
      .prepare(
        'SELECT COUNT(*) as count FROM audit_log WHERE tool = ? AND host = ? AND timestamp > ? AND response_status = ?',
      )
      .get(context.tool, context.host, oneHourAgo, 'error') as { count: number }
  ).count;

  const currentErrorRate = total > 0 ? errors / total : 0;
  const newErrorRateMean = alpha * currentErrorRate + (1 - alpha) * baseline.errorRateMean;

  const errorDelta = currentErrorRate - baseline.errorRateMean;
  const errorDelta2 = currentErrorRate - newErrorRateMean;
  const errorVariance =
    baseline.errorRateStdDev ** 2 + (errorDelta * errorDelta2 - baseline.errorRateStdDev ** 2) / totalCount;
  const newErrorRateStdDev = Math.sqrt(Math.max(0, errorVariance));

  // Write updated baseline
  const row: Omit<AnomalyBaselineRow, 'id'> = {
    tool: context.tool,
    host: context.host,
    frequency_mean: newFrequencyMean,
    frequency_std_dev: newFrequencyStdDev,
    hourly_distribution: JSON.stringify(hourlyDistribution),
    argument_fingerprints: JSON.stringify(fingerprints),
    tool_bigrams: JSON.stringify(bigrams),
    error_rate_mean: newErrorRateMean,
    error_rate_std_dev: newErrorRateStdDev,
    last_updated: now,
    sample_count: totalCount,
  };

  db.prepare(
    `INSERT INTO anomaly_baselines (
      tool, host, frequency_mean, frequency_std_dev, hourly_distribution,
      argument_fingerprints, tool_bigrams, error_rate_mean, error_rate_std_dev,
      last_updated, sample_count
    ) VALUES (
      @tool, @host, @frequency_mean, @frequency_std_dev, @hourly_distribution,
      @argument_fingerprints, @tool_bigrams, @error_rate_mean, @error_rate_std_dev,
      @last_updated, @sample_count
    )
    ON CONFLICT(tool, host) DO UPDATE SET
      frequency_mean = @frequency_mean,
      frequency_std_dev = @frequency_std_dev,
      hourly_distribution = @hourly_distribution,
      argument_fingerprints = @argument_fingerprints,
      tool_bigrams = @tool_bigrams,
      error_rate_mean = @error_rate_mean,
      error_rate_std_dev = @error_rate_std_dev,
      last_updated = @last_updated,
      sample_count = @sample_count
    `,
  ).run(row);
}

/**
 * Convert anomaly score to risk factors
 *
 * @param anomalyScore - Anomaly score breakdown
 * @returns Array of risk factors
 */
export function convertAnomalyToRiskFactors(anomalyScore: AnomalyScore): RiskFactor[] {
  const factors: RiskFactor[] = [];

  if (anomalyScore.frequency > 30) {
    factors.push({
      factor: 'frequency_anomaly',
      score: anomalyScore.frequency,
      details: `Unusual operation frequency (score: ${anomalyScore.frequency.toFixed(1)})`,
    });
  }

  if (anomalyScore.temporal > 30) {
    factors.push({
      factor: 'temporal_anomaly',
      score: anomalyScore.temporal,
      details: `Unusual time-of-day access (score: ${anomalyScore.temporal.toFixed(1)})`,
    });
  }

  if (anomalyScore.argumentNovelty > 30) {
    factors.push({
      factor: 'argument_novelty',
      score: anomalyScore.argumentNovelty,
      details: `Never-seen argument pattern (score: ${anomalyScore.argumentNovelty.toFixed(1)})`,
    });
  }

  if (anomalyScore.sequence > 30) {
    factors.push({
      factor: 'sequence_anomaly',
      score: anomalyScore.sequence,
      details: `Unusual tool call sequence (score: ${anomalyScore.sequence.toFixed(1)})`,
    });
  }

  if (anomalyScore.errorRate > 30) {
    factors.push({
      factor: 'error_rate_spike',
      score: anomalyScore.errorRate,
      details: `Error rate spike detected (score: ${anomalyScore.errorRate.toFixed(1)})`,
    });
  }

  return factors;
}
