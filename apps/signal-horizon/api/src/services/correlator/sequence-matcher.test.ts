import { describe, it, expect } from 'vitest';
import { SequenceMatcher, AttackStage, STAGE_ORDER, type CampaignSequenceState } from './sequence-matcher.js';
import type { EnrichedSignal, SignalType } from '../../types/protocol.js';

describe('SequenceMatcher', () => {
  const matcher = new SequenceMatcher();

  const createSignal = (signalType: SignalType, metadata: any = {}, id = 's1'): EnrichedSignal => ({
    id,
    signalType,
    metadata,
    confidence: 0.9,
    severity: 'HIGH',
    tenantId: 't1',
    sensorId: 'sen1',
  } as EnrichedSignal);

  describe('mapSignalToStage', () => {
    it.each([
      ['TEMPLATE_DISCOVERY', {}, AttackStage.RECONNAISSANCE],
      ['BOT_SIGNATURE', {}, AttackStage.RECONNAISSANCE],
      ['SCHEMA_VIOLATION', {}, AttackStage.EXPLOITATION],
      ['SCHEMA_VIOLATION', { dlp_match_count: 1 }, AttackStage.EXFILTRATION],
      ['CREDENTIAL_STUFFING', {}, AttackStage.EXPLOITATION],
      ['IP_THREAT', { rule_ids: ['942100_sqli'] }, AttackStage.EXPLOITATION],
      ['IP_THREAT', { rule_ids: ['941100_xss'] }, AttackStage.EXPLOITATION],
      ['IP_THREAT', { rule_ids: ['932100_rce'] }, AttackStage.EXPLOITATION],
      ['IP_THREAT', { rule_ids: ['exfil_data'] }, AttackStage.EXFILTRATION],
      ['IP_THREAT', { rule_ids: ['recon_scanner'] }, AttackStage.RECONNAISSANCE],
      ['IP_THREAT', { rule_ids: ['lfi_traversal'] }, AttackStage.EXPLOITATION], // LFI rule
      ['IP_THREAT', {}, AttackStage.EXPLOITATION], // Default for IP_THREAT
      ['IP_THREAT', { attackStage: AttackStage.EXFILTRATION }, AttackStage.EXFILTRATION], // Metadata override
      ['SCHEMA_VIOLATION', { dlp_match_count: 0 }, AttackStage.EXPLOITATION], // dlp_match_count: 0 is falsy
    ])('should map %s with metadata %j to %s', (type, meta, expected) => {
      const signal = createSignal(type as SignalType, meta);
      expect(matcher.mapSignalToStage(signal)).toBe(expected);
    });

    it('should return null for unknown signal types', () => {
      const signal = createSignal('PONG' as any);
      expect(matcher.mapSignalToStage(signal)).toBeNull();
    });

    it('should handle malformed rule_ids gracefully', () => {
      const signal = createSignal('IP_THREAT', { rule_ids: "not-an-array" });
      expect(matcher.mapSignalToStage(signal)).toBe(AttackStage.EXPLOITATION);
    });
  });

  describe('processSignal', () => {
    it('should fix P0 shallow copy bug (history array)', () => {
      const state: CampaignSequenceState = { history: [] };
      const signal = createSignal('TEMPLATE_DISCOVERY', {}, 's1');
      
      const res1 = matcher.processSignal(state, signal);
      const res2 = matcher.processSignal(state, signal);
      
      expect(res1.newState.history).toHaveLength(1);
      expect(res2.newState.history).toHaveLength(1);
      expect(state.history).toHaveLength(0); // Original state should not be mutated
      expect(res1.newState.history).not.toBe(res2.newState.history); // New arrays every time
    });

    it('should enforce MAX_HISTORY_SIZE', () => {
      const state: CampaignSequenceState = { history: [] };
      let currentState = state;
      
      // Add 501 signals
      for (let i = 0; i < 501; i++) {
        const signal = createSignal('TEMPLATE_DISCOVERY', {}, `s${i}`);
        currentState = matcher.processSignal(currentState, signal).newState;
      }
      
      expect(currentState.history).toHaveLength(500);
      expect(currentState.history[0].signalId).toBe('s1'); // s0 should be evicted
    });

    it.each([
      [undefined, AttackStage.RECONNAISSANCE, 0.1, undefined],
      [undefined, AttackStage.EXPLOITATION, 0.2, undefined],
      [AttackStage.RECONNAISSANCE, AttackStage.EXPLOITATION, 0.4, undefined],
      [AttackStage.EXPLOITATION, AttackStage.EXFILTRATION, 0.5, 'CRITICAL'],
      [AttackStage.RECONNAISSANCE, AttackStage.RECONNAISSANCE, 0.02, undefined], // Repeat
      [AttackStage.EXPLOITATION, AttackStage.RECONNAISSANCE, 0.02, undefined], // Regression (no back-transition)
    ])('transition from %s to %s should boost %f and escalate to %s', (from, to, boost, escalation) => {
      const state: CampaignSequenceState = { 
        currentStage: from, 
        highestStage: from,
        history: [] 
      };
      
      // Create a signal that maps to the 'to' stage
      let signal: EnrichedSignal;
      if (to === AttackStage.RECONNAISSANCE) signal = createSignal('TEMPLATE_DISCOVERY');
      else if (to === AttackStage.EXPLOITATION) signal = createSignal('SCHEMA_VIOLATION');
      else signal = createSignal('SCHEMA_VIOLATION', { dlp_match_count: 1 });

      const result = matcher.processSignal(state, signal);
      expect(result.confidenceBoost).toBe(boost);
      expect(result.severityEscalation).toBe(escalation);
      
      if (STAGE_ORDER[to] > (from ? STAGE_ORDER[from] : 0)) {
        expect(result.newState.currentStage).toBe(to);
      } else {
        expect(result.newState.currentStage).toBe(from); // No regression
      }
    });

    it('should return unchanged state for unmapped signal types', () => {
      const state: CampaignSequenceState = {
        currentStage: AttackStage.RECONNAISSANCE,
        highestStage: AttackStage.RECONNAISSANCE,
        history: [{ stage: AttackStage.RECONNAISSANCE, signalId: 's0', timestamp: '2026-01-01', confidence: 0.9 }],
      };

      const signal = createSignal('PONG' as any, {}, 's1');
      const result = matcher.processSignal(state, signal);

      expect(result.confidenceBoost).toBe(0);
      expect(result.newState).toBe(state); // Same reference — no copy needed
      expect(result.severityEscalation).toBeUndefined();
    });

    it('should preserve highestStage on regression', () => {
      const state: CampaignSequenceState = {
        currentStage: AttackStage.EXPLOITATION,
        highestStage: AttackStage.EXPLOITATION,
        history: [],
      };

      // Send a RECON signal (regression)
      const signal = createSignal('TEMPLATE_DISCOVERY', {}, 's1');
      const result = matcher.processSignal(state, signal);

      expect(result.newState.currentStage).toBe(AttackStage.EXPLOITATION); // No regression
      expect(result.newState.highestStage).toBe(AttackStage.EXPLOITATION); // Preserved
    });

    it('should update highestStage on progression', () => {
      const state: CampaignSequenceState = {
        currentStage: AttackStage.RECONNAISSANCE,
        highestStage: AttackStage.RECONNAISSANCE,
        history: [],
      };

      const signal = createSignal('SCHEMA_VIOLATION', { dlp_match_count: 1 }, 's1');
      const result = matcher.processSignal(state, signal);

      expect(result.newState.currentStage).toBe(AttackStage.EXFILTRATION);
      expect(result.newState.highestStage).toBe(AttackStage.EXFILTRATION);
    });
  });

  describe('processSignalBatch', () => {
    it('should process multiple signals and accumulate results', () => {
      const state: CampaignSequenceState = { history: [] };
      const signals = [
        createSignal('TEMPLATE_DISCOVERY', {}, 's1'),
        createSignal('SCHEMA_VIOLATION', {}, 's2'),
        createSignal('SCHEMA_VIOLATION', { dlp_match_count: 1 }, 's3'),
      ];

      const result = matcher.processSignalBatch(state, signals, 0.5, 'LOW');
      
      expect(result.newState.currentStage).toBe(AttackStage.EXFILTRATION);
      expect(result.severity).toBe('CRITICAL');
      // 0.5 + 0.1 (recon) + 0.4 (exploit) + 0.5 (exfil) = 1.5 -> capped at 1.0
      expect(result.confidence).toBe(1.0);
      expect(result.newState.history).toHaveLength(3);
    });

    it('should return initial values unchanged for empty signals', () => {
      const state: CampaignSequenceState = { history: [] };
      const result = matcher.processSignalBatch(state, [], 0.42, 'MEDIUM');

      expect(result.newState.history).toHaveLength(0);
      expect(result.confidence).toBe(0.42);
      expect(result.severity).toBe('MEDIUM');
    });

    it('should clamp confidence to 1.0 with high initial confidence', () => {
      const state: CampaignSequenceState = { history: [] };
      const signals = [
        createSignal('TEMPLATE_DISCOVERY', {}, 's1'),   // +0.1
        createSignal('SCHEMA_VIOLATION', {}, 's2'),      // +0.4
      ];

      const result = matcher.processSignalBatch(state, signals, 0.99, 'LOW');

      expect(result.confidence).toBe(1.0);
    });
  });
});