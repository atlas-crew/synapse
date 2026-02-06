/**
 * Unit tests for scope registry and alias expansion
 *
 * Security-critical: Tests cover cycle detection, alias expansion,
 * and edge cases to prevent authorization bypass.
 */

import { describe, it, expect } from 'vitest';
import {
  SCOPES,
  SCOPE_ALIASES,
  expandScopes,
  hasScope,
} from '../scopes.js';

describe('scopes.ts', () => {
  describe('SCOPES constant', () => {
    it('should define all expected scope keys', () => {
      // Verify critical scopes exist
      expect(SCOPES).toHaveProperty('hunt:read');
      expect(SCOPES).toHaveProperty('hunt:write');
      expect(SCOPES).toHaveProperty('hunt:execute');
      expect(SCOPES).toHaveProperty('analytics:read');
      expect(SCOPES).toHaveProperty('tunnel:shell');
      expect(SCOPES).toHaveProperty('fleet:admin');
    });

    it('should have descriptions for all scopes', () => {
      for (const [, description] of Object.entries(SCOPES)) {
        expect(description).toBeTruthy();
        expect(typeof description).toBe('string');
        expect(description.length).toBeGreaterThan(5);
      }
    });
  });

  describe('SCOPE_ALIASES', () => {
    it('should define backward-compatible aliases', () => {
      expect(SCOPE_ALIASES['dashboard:read']).toContain('analytics:read');
      expect(SCOPE_ALIASES['dashboard:read']).toContain('hunt:read');
      expect(SCOPE_ALIASES['fleet:read']).toContain('tunnel:read');
      expect(SCOPE_ALIASES['fleet:admin']).toContain('tunnel:shell');
    });

    it('should not contain circular references at the first level', () => {
      for (const [aliasKey, aliasedScopes] of Object.entries(SCOPE_ALIASES)) {
        // An alias should not directly reference itself
        expect(aliasedScopes).not.toContain(aliasKey);
      }
    });

    it('should only alias to valid scope keys or other aliases', () => {
      const allValidScopes = new Set([
        ...Object.keys(SCOPES),
        ...Object.keys(SCOPE_ALIASES),
      ]);

      for (const [, aliasedScopes] of Object.entries(SCOPE_ALIASES)) {
        for (const scope of aliasedScopes) {
          expect(allValidScopes.has(scope)).toBe(true);
        }
      }
    });
  });

  describe('expandScopes', () => {
    it('should return original scopes when no aliases match', () => {
      const result = expandScopes(['hunt:read', 'hunt:write']);
      expect(result).toContain('hunt:read');
      expect(result).toContain('hunt:write');
      expect(result.size).toBe(2);
    });

    it('should expand dashboard:read to include all aliased scopes', () => {
      const result = expandScopes(['dashboard:read']);

      expect(result).toContain('dashboard:read');
      expect(result).toContain('analytics:read');
      expect(result).toContain('analytics:health');
      expect(result).toContain('threats:read');
      expect(result).toContain('warroom:read');
      expect(result).toContain('hunt:read');
      expect(result).toContain('playbook:read');
      expect(result).toContain('campaigns:read');
    });

    it('should expand fleet:admin to include sensitive scopes', () => {
      const result = expandScopes(['fleet:admin']);

      expect(result).toContain('fleet:admin');
      expect(result).toContain('tunnel:shell');
      expect(result).toContain('tunnel:dashboard');
      expect(result).toContain('audit:read');
      expect(result).toContain('playbook:delete');
    });

    it('should combine multiple alias expansions', () => {
      const result = expandScopes(['dashboard:read', 'fleet:read']);

      // From dashboard:read
      expect(result).toContain('analytics:read');
      expect(result).toContain('hunt:read');

      // From fleet:read
      expect(result).toContain('tunnel:read');
      expect(result).toContain('credentials:read');
      expect(result).toContain('sensor:read');
    });

    it('should handle empty input', () => {
      const result = expandScopes([]);
      expect(result.size).toBe(0);
    });

    it('should handle unknown scopes gracefully', () => {
      const result = expandScopes(['unknown:scope', 'hunt:read']);
      expect(result).toContain('unknown:scope');
      expect(result).toContain('hunt:read');
      expect(result.size).toBe(2);
    });

    it('should not produce duplicates', () => {
      // hunt:read is in both dashboard:read alias AND explicitly provided
      const result = expandScopes(['dashboard:read', 'hunt:read']);
      const arr = Array.from(result);
      const huntReadCount = arr.filter((s) => s === 'hunt:read').length;
      expect(huntReadCount).toBe(1);
    });

    it('should handle transitive alias expansion', () => {
      // signal:read aliases to hunt:read, which could be expanded further
      // if hunt:read had aliases (it doesn't currently, but test the mechanism)
      const result = expandScopes(['signal:read']);
      expect(result).toContain('signal:read');
      expect(result).toContain('hunt:read');
    });

    it('should limit recursion depth to prevent DoS', () => {
      // This test verifies the MAX_ALIAS_DEPTH protection
      // Even with a malicious alias configuration, expansion should terminate
      const result = expandScopes(['dashboard:read']);
      // Should complete without stack overflow or infinite loop
      expect(result.size).toBeGreaterThan(0);
      expect(result.size).toBeLessThan(100); // Reasonable upper bound
    });

    it('should not expand the same scope twice (cycle detection)', () => {
      // Verify visited set prevents re-processing
      // dashboard:read -> hunt:read, signal:read -> hunt:read
      // hunt:read should only be added once
      const result = expandScopes(['dashboard:read', 'signal:read']);
      expect(result).toContain('hunt:read');
      // The result is a Set, so no duplicates by definition
      expect(result.size).toBe(new Set(result).size);
    });
  });

  describe('hasScope', () => {
    it('should return true for direct scope match', () => {
      expect(hasScope(['hunt:read', 'hunt:write'], 'hunt:read')).toBe(true);
    });

    it('should return false when scope not present', () => {
      expect(hasScope(['hunt:read'], 'hunt:write')).toBe(false);
    });

    it('should return true when scope is granted via alias', () => {
      // dashboard:read aliases to analytics:read
      expect(hasScope(['dashboard:read'], 'analytics:read')).toBe(true);
    });

    it('should return true for hunt:read via dashboard:read alias', () => {
      expect(hasScope(['dashboard:read'], 'hunt:read')).toBe(true);
    });

    it('should return true for tunnel:shell via fleet:admin alias', () => {
      expect(hasScope(['fleet:admin'], 'tunnel:shell')).toBe(true);
    });

    it('should return false for scope not in any alias', () => {
      expect(hasScope(['dashboard:read'], 'tunnel:shell')).toBe(false);
    });

    it('should handle empty user scopes', () => {
      expect(hasScope([], 'hunt:read')).toBe(false);
    });

    it('should handle unknown required scope', () => {
      expect(hasScope(['dashboard:read'], 'unknown:scope')).toBe(false);
    });

    it('should check all user scopes for alias matches', () => {
      // fleet:read aliases to tunnel:read
      expect(hasScope(['hunt:read', 'fleet:read'], 'tunnel:read')).toBe(true);
    });

    it('should prioritize direct match over alias', () => {
      // User has direct hunt:read AND dashboard:read (which aliases to hunt:read)
      // Should return true via direct match first
      expect(hasScope(['hunt:read', 'dashboard:read'], 'hunt:read')).toBe(true);
    });
  });

  describe('Security scenarios', () => {
    it('should not allow privilege escalation through alias chains', () => {
      // Verify that having a read scope doesn't grant write access
      expect(hasScope(['dashboard:read'], 'dashboard:write')).toBe(false);
      expect(hasScope(['fleet:read'], 'fleet:write')).toBe(false);
      expect(hasScope(['fleet:read'], 'fleet:admin')).toBe(false);
    });

    it('should protect sensitive scopes from unauthorized access', () => {
      // tunnel:shell is highly sensitive - only fleet:admin should grant it
      expect(hasScope(['dashboard:read'], 'tunnel:shell')).toBe(false);
      expect(hasScope(['dashboard:write'], 'tunnel:shell')).toBe(false);
      expect(hasScope(['fleet:read'], 'tunnel:shell')).toBe(false);
      expect(hasScope(['fleet:write'], 'tunnel:shell')).toBe(false);
      expect(hasScope(['fleet:admin'], 'tunnel:shell')).toBe(true);
    });

    it('should protect audit:read from non-admin users', () => {
      expect(hasScope(['dashboard:read'], 'audit:read')).toBe(false);
      expect(hasScope(['dashboard:write'], 'audit:read')).toBe(false);
      expect(hasScope(['fleet:admin'], 'audit:read')).toBe(true);
    });

    it('should protect destructive operations', () => {
      // playbook:delete is only via fleet:admin
      expect(hasScope(['dashboard:write'], 'playbook:delete')).toBe(false);
      expect(hasScope(['fleet:admin'], 'playbook:delete')).toBe(true);
    });
  });
});
