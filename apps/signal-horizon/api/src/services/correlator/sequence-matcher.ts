/**
 * Sequence Matcher for Attack Sequences
 * Tracks the progression of attack stages for threat entities
 */

import type { EnrichedSignal, Severity } from '../../types/protocol.js';

export enum AttackStage {
  RECONNAISSANCE = 'reconnaissance',
  EXPLOITATION = 'exploitation',
  EXFILTRATION = 'exfiltration',
}

export interface CampaignSequenceState {
  currentStage?: AttackStage;
  highestStage?: AttackStage;
  history: Array<{
    stage: AttackStage;
    signalId: string;
    timestamp: string;
    confidence: number;
  }>;
}

export interface ProcessResult {
  newState: CampaignSequenceState;
  confidenceBoost: number;
  severityEscalation?: Severity;
}

export const STAGE_ORDER: Record<AttackStage, number> = {
  [AttackStage.RECONNAISSANCE]: 1,
  [AttackStage.EXPLOITATION]: 2,
  [AttackStage.EXFILTRATION]: 3,
};

const MAX_HISTORY_SIZE = 500;

/**
 * Data-driven transition matrix
 */
interface TransitionRule {
  from?: AttackStage;
  to: AttackStage;
  boost: number;
  escalation?: Severity;
}

const TRANSITIONS: TransitionRule[] = [
  { to: AttackStage.RECONNAISSANCE, boost: 0.1 },
  { to: AttackStage.EXPLOITATION, boost: 0.2 },
  { from: AttackStage.RECONNAISSANCE, to: AttackStage.EXPLOITATION, boost: 0.4 },
  { from: AttackStage.EXPLOITATION, to: AttackStage.EXFILTRATION, boost: 0.5, escalation: 'CRITICAL' },
];

export class SequenceMatcher {
  /**
   * Determine the attack stage from an enriched signal
   */
  mapSignalToStage(signal: EnrichedSignal): AttackStage | null {
    const metadata = signal.metadata as Record<string, unknown> | undefined;

    // Check for explicit stage in metadata (if added by sensor or aggregator)
    if (
      metadata?.attackStage &&
      Object.values(AttackStage).includes(metadata.attackStage as AttackStage)
    ) {
      return metadata.attackStage as AttackStage;
    }

    // Check for DLP matches (Exfiltration)
    if (signal.signalType === 'SCHEMA_VIOLATION' && metadata?.dlp_match_count) {
      return AttackStage.EXFILTRATION;
    }

    // Mapping based on SignalType
    switch (signal.signalType) {
      case 'TEMPLATE_DISCOVERY':
        return AttackStage.RECONNAISSANCE;
      case 'BOT_SIGNATURE':
        return AttackStage.RECONNAISSANCE;
      case 'SCHEMA_VIOLATION':
        return AttackStage.EXPLOITATION;
      case 'CREDENTIAL_STUFFING':
        return AttackStage.EXPLOITATION;
      case 'IP_THREAT':
        return this.mapIpThreatToStage(metadata);
      default:
        return null;
    }
  }

  private mapIpThreatToStage(metadata: Record<string, unknown> | undefined): AttackStage | null {
    if (!metadata) return AttackStage.EXPLOITATION;

    const rawRuleIds = metadata.rule_ids;
    const ruleIds = Array.isArray(rawRuleIds)
      ? rawRuleIds.filter((id): id is string => typeof id === 'string')
      : [];

    if (ruleIds.some((id) => id.includes('sqli') || id.includes('xss') || id.includes('rce') || id.includes('lfi'))) {
      return AttackStage.EXPLOITATION;
    }
    if (ruleIds.some((id) => id.includes('exfil'))) {
      return AttackStage.EXFILTRATION;
    }
    if (ruleIds.some((id) => id.includes('scanner') || id.includes('recon'))) {
      return AttackStage.RECONNAISSANCE;
    }

    return AttackStage.EXPLOITATION; // Default for IP_THREAT
  }

  /**
   * Process a signal and return the updated sequence state and confidence boost
   */
  processSignal(state: CampaignSequenceState, signal: EnrichedSignal): ProcessResult {
    const signalStage = this.mapSignalToStage(signal);
    if (!signalStage) {
      return { newState: state, confidenceBoost: 0 };
    }

    const signalOrder = STAGE_ORDER[signalStage];
    const currentOrder = state.currentStage ? STAGE_ORDER[state.currentStage] : 0;

    let confidenceBoost = 0.02; // Base boost for repeating or non-progression signals
    let severityEscalation: Severity | undefined;
    let nextStage = state.currentStage;

    if (signalOrder > currentOrder) {
      nextStage = signalStage;
      
      // Find best matching transition rule
      const rule = 
        TRANSITIONS.find(r => r.from === state.currentStage && r.to === signalStage) ||
        TRANSITIONS.find(r => !r.from && r.to === signalStage);

      if (rule) {
        confidenceBoost = rule.boost;
        severityEscalation = rule.escalation;
      }
    }

    // Create a NEW state object with a NEW history array (Fix P0 shallow copy)
    const newHistory = [
      ...state.history,
      {
        stage: signalStage,
        signalId: signal.id || `gen-${Math.random().toString(36).slice(2, 11)}`,
        timestamp: new Date().toISOString(),
        confidence: signal.confidence,
      },
    ];

    // Enforce MAX_HISTORY_SIZE (Fix P1.1)
    if (newHistory.length > MAX_HISTORY_SIZE) {
      newHistory.shift();
    }

    const newState: CampaignSequenceState = {
      ...state,
      currentStage: nextStage,
      highestStage: 
        !state.highestStage || signalOrder > STAGE_ORDER[state.highestStage] 
          ? signalStage 
          : state.highestStage,
      history: newHistory,
    };

    return { newState, confidenceBoost, severityEscalation };
  }

  /**
   * Process a batch of signals (Fix P2.7)
   */
  processSignalBatch(
    state: CampaignSequenceState,
    signals: EnrichedSignal[],
    initialConfidence: number,
    initialSeverity: Severity
  ): { newState: CampaignSequenceState; confidence: number; severity: Severity } {
    let currentState = state;
    let currentConfidence = initialConfidence;
    let currentSeverity = initialSeverity;

    const severityRanks: Record<Severity, number> = {
      LOW: 1,
      MEDIUM: 2,
      HIGH: 3,
      CRITICAL: 4,
    };

    for (const signal of signals) {
      const result = this.processSignal(currentState, signal);
      currentState = result.newState;
      currentConfidence = Math.min(currentConfidence + result.confidenceBoost, 1.0);
      
      if (result.severityEscalation) {
        if (severityRanks[result.severityEscalation] > severityRanks[currentSeverity]) {
          currentSeverity = result.severityEscalation;
        }
      }
    }

    return {
      newState: currentState,
      confidence: currentConfidence,
      severity: currentSeverity,
    };
  }
}