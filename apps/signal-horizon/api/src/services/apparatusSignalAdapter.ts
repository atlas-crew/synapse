/**
 * Apparatus Signal Adapter
 *
 * Maps Apparatus event types (from @atlascrew/apparatus-lib SSE stream)
 * to Horizon's internal ThreatSignal format. This replaces the v1.0.0
 * "Cutlass Protocol" adapter in synapse-pingora for events flowing
 * through the Horizon API directly.
 *
 * Apparatus SSE event types → Horizon SignalType:
 *   deception (honeypot_hit)    → IP_THREAT
 *   deception (shell_command)   → BOT_SIGNATURE
 *   deception (sqli_probe)      → CAMPAIGN_INDICATOR
 *   tarpit                      → RATE_ANOMALY
 *   threat-intel                → CAMPAIGN_INDICATOR
 *   request                     → (not mapped — informational only)
 *   health                      → (not mapped — internal)
 */

import type { SSEEvent, SSEEventType, DeceptionEvent } from '@atlascrew/apparatus-lib';
import type { ThreatSignal, Severity, SignalType } from '../types/protocol.js';

// ============================================================================
// Apparatus event shapes (from SSE stream)
// ============================================================================

interface ApparatusTarpitEvent {
  ip: string;
  trappedAt?: string;
  duration?: number;
}

interface ApparatusThreatIntelEvent {
  type?: string;
  source?: string;
  ip?: string;
  fingerprint?: string;
  severity?: string;
  details?: Record<string, unknown>;
}

// ============================================================================
// Mapping
// ============================================================================

const DECEPTION_TYPE_MAP: Record<string, { signalType: SignalType; severity: Severity }> = {
  honeypot_hit: { signalType: 'IP_THREAT', severity: 'HIGH' },
  shell_command: { signalType: 'BOT_SIGNATURE', severity: 'CRITICAL' },
  sqli_probe: { signalType: 'CAMPAIGN_INDICATOR', severity: 'HIGH' },
};

const SEVERITY_MAP: Record<string, Severity> = {
  low: 'LOW',
  medium: 'MEDIUM',
  high: 'HIGH',
  critical: 'CRITICAL',
};

function normalizeSeverity(raw?: string): Severity {
  if (!raw) return 'MEDIUM';
  return SEVERITY_MAP[raw.toLowerCase()] ?? 'MEDIUM';
}

// ============================================================================
// Public API
// ============================================================================

export interface AdaptedSignal {
  signal: ThreatSignal;
  source: 'apparatus';
  apparatusEventType: SSEEventType;
  timestamp: string;
}

/**
 * Attempt to convert an Apparatus SSE event into a Horizon ThreatSignal.
 * Returns null for event types that don't map to threat signals (request, health).
 */
export function adaptApparatusEvent(event: SSEEvent): AdaptedSignal | null {
  const { type, timestamp, data } = event;

  switch (type) {
    case 'deception':
      return adaptDeceptionEvent(data as DeceptionEvent, timestamp);
    case 'tarpit':
      return adaptTarpitEvent(data as ApparatusTarpitEvent, timestamp);
    case 'threat-intel':
      return adaptThreatIntelEvent(data as ApparatusThreatIntelEvent, timestamp);
    default:
      // 'request' and 'health' events are informational — don't map to signals
      return null;
  }
}

// ============================================================================
// Event-specific adapters
// ============================================================================

function adaptDeceptionEvent(
  event: DeceptionEvent,
  timestamp: string,
): AdaptedSignal | null {
  const mapping = DECEPTION_TYPE_MAP[event.type] ?? {
    signalType: 'IP_THREAT' as const,
    severity: 'MEDIUM' as const,
  };

  return {
    signal: {
      signalType: mapping.signalType,
      sourceIp: event.ip,
      severity: mapping.severity,
      confidence: 0.85,
      metadata: {
        apparatusRoute: event.route,
        apparatusSessionId: event.sessionId,
        deceptionType: event.type,
        ...((event.details && typeof event.details === 'object') ? event.details : {}),
      },
    } as ThreatSignal,
    source: 'apparatus',
    apparatusEventType: 'deception',
    timestamp,
  };
}

function adaptTarpitEvent(
  event: ApparatusTarpitEvent,
  timestamp: string,
): AdaptedSignal {
  return {
    signal: {
      signalType: 'RATE_ANOMALY',
      sourceIp: event.ip,
      severity: 'MEDIUM',
      confidence: 0.9,
      metadata: {
        trappedAt: event.trappedAt,
        duration: event.duration,
        source: 'apparatus-tarpit',
      },
    } as ThreatSignal,
    source: 'apparatus',
    apparatusEventType: 'tarpit',
    timestamp,
  };
}

function adaptThreatIntelEvent(
  event: ApparatusThreatIntelEvent,
  timestamp: string,
): AdaptedSignal {
  return {
    signal: {
      signalType: 'CAMPAIGN_INDICATOR',
      sourceIp: event.ip,
      fingerprint: event.fingerprint,
      severity: normalizeSeverity(event.severity),
      confidence: 0.75,
      metadata: {
        intelType: event.type,
        intelSource: event.source,
        ...(event.details ?? {}),
      },
    } as ThreatSignal,
    source: 'apparatus',
    apparatusEventType: 'threat-intel',
    timestamp,
  };
}
