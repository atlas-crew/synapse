/**
 * Fingerprint validation tests (labs-764)
 * Ensures fingerprints meet entropy and anti-spoofing requirements
 */

import { describe, it, expect } from 'vitest';
import { FingerprintSchema, BaseThreatSignalSchema } from '../signal.js';

describe('FingerprintSchema', () => {
  describe('valid fingerprints', () => {
    it('accepts JA4 fingerprint format', () => {
      const ja4 = 't13d1517h2_8daaf6152771_b0da82dd1658';
      expect(FingerprintSchema.safeParse(ja4).success).toBe(true);
    });

    it('accepts hex fingerprint format', () => {
      const hex = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4';
      expect(FingerprintSchema.safeParse(hex).success).toBe(true);
    });

    it('accepts canvas fingerprint format', () => {
      const canvas = '3a7bd2f9e1c4a8b5d6e7f8g9h0i1j2k3';
      expect(FingerprintSchema.safeParse(canvas).success).toBe(true);
    });

    it('accepts fingerprint with colons (browser format)', () => {
      const fp = 'browser:canvas:3a7bd2f9e1c4';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });

    it('accepts fingerprint with periods', () => {
      const fp = 'vendor.renderer.extension123';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });

    it('accepts fingerprint at minimum length (16 chars)', () => {
      const fp = 'a1b2c3d4e5f6g7h8';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });

    it('accepts fingerprint at maximum length (256 chars)', () => {
      const fp = 'a'.repeat(128) + 'b'.repeat(64) + 'c'.repeat(32) + '1'.repeat(32);
      expect(fp.length).toBe(256);
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });
  });

  describe('invalid fingerprints - length', () => {
    it('rejects fingerprint too short', () => {
      const result = FingerprintSchema.safeParse('a1b2c3d4');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('at least 16');
      }
    });

    it('rejects fingerprint too long', () => {
      const fp = 'a'.repeat(257);
      const result = FingerprintSchema.safeParse(fp);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('at most 256');
      }
    });

    it('rejects empty string', () => {
      const result = FingerprintSchema.safeParse('');
      expect(result.success).toBe(false);
    });
  });

  describe('invalid fingerprints - character set', () => {
    it('rejects fingerprint with spaces', () => {
      const result = FingerprintSchema.safeParse('a1b2c3d4 e5f6g7h8');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('invalid characters');
      }
    });

    it('rejects fingerprint with special characters', () => {
      const result = FingerprintSchema.safeParse('a1b2c3d4$e5f6g7h8');
      expect(result.success).toBe(false);
    });

    it('rejects fingerprint with brackets', () => {
      const result = FingerprintSchema.safeParse('a1b2c3d4[e5f6]g7h8');
      expect(result.success).toBe(false);
    });

    it('rejects fingerprint with SQL injection attempt', () => {
      const result = FingerprintSchema.safeParse("a1b2c3d4'; DROP TABLE--");
      expect(result.success).toBe(false);
    });

    it('rejects fingerprint with null byte', () => {
      const result = FingerprintSchema.safeParse('a1b2c3d4\x00e5f6g7h8');
      expect(result.success).toBe(false);
    });
  });

  describe('invalid fingerprints - spoofing patterns', () => {
    it('rejects repeated characters (obvious spoof)', () => {
      const result = FingerprintSchema.safeParse('aaaaaaaaaaaaaaaa');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('spoofed');
      }
    });

    it('rejects sequential numbers starting pattern', () => {
      const result = FingerprintSchema.safeParse('012345abcdef1234567890');
      expect(result.success).toBe(false);
    });

    it('rejects "test" prefix', () => {
      const result = FingerprintSchema.safeParse('testfingerprint123456');
      expect(result.success).toBe(false);
    });

    it('rejects "fake" prefix', () => {
      const result = FingerprintSchema.safeParse('fakefingerprint12345');
      expect(result.success).toBe(false);
    });

    it('rejects "null" prefix', () => {
      const result = FingerprintSchema.safeParse('nullfingerprint12345');
      expect(result.success).toBe(false);
    });

    it('rejects all zeros', () => {
      const result = FingerprintSchema.safeParse('0000000000000000');
      expect(result.success).toBe(false);
    });

    it('rejects low entropy (only 2 unique chars)', () => {
      const result = FingerprintSchema.safeParse('abababababababab');
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].message).toContain('insufficient entropy');
      }
    });

    it('rejects low entropy (only 3 unique chars)', () => {
      const result = FingerprintSchema.safeParse('abcabcabcabcabca');
      expect(result.success).toBe(false);
    });
  });

  describe('boundary cases', () => {
    it('accepts fingerprint with exactly 4 unique characters', () => {
      const fp = 'abcdabcdabcdabcd';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });

    it('accepts valid JA4 with underscore separators', () => {
      const fp = 't13d1516h2_deadbeef1234_5678abcd9012';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });

    it('accepts mixed case fingerprint', () => {
      // Note: 'AbCdEfGh...' starts with 'abcdef' which is flagged as sequential
      const fp = 'XyZaBc1234567890';
      expect(FingerprintSchema.safeParse(fp).success).toBe(true);
    });
  });
});

describe('BaseThreatSignalSchema fingerprint integration', () => {
  it('accepts signal with valid fingerprint', () => {
    const signal = {
      sourceIp: '192.168.1.1',
      fingerprint: 't13d1517h2_8daaf6152771_b0da82dd1658',
      severity: 'HIGH',
      confidence: 0.95,
    };
    expect(BaseThreatSignalSchema.safeParse(signal).success).toBe(true);
  });

  it('accepts signal without fingerprint', () => {
    const signal = {
      sourceIp: '192.168.1.1',
      severity: 'HIGH',
      confidence: 0.95,
    };
    expect(BaseThreatSignalSchema.safeParse(signal).success).toBe(true);
  });

  it('rejects signal with spoofed fingerprint', () => {
    const signal = {
      sourceIp: '192.168.1.1',
      fingerprint: 'fakefingerprint12345',
      severity: 'HIGH',
      confidence: 0.95,
    };
    const result = BaseThreatSignalSchema.safeParse(signal);
    expect(result.success).toBe(false);
  });

  it('rejects signal with low-entropy fingerprint', () => {
    const signal = {
      sourceIp: '192.168.1.1',
      fingerprint: 'aaaaaaaaaaaaaaaa',
      severity: 'HIGH',
      confidence: 0.95,
    };
    const result = BaseThreatSignalSchema.safeParse(signal);
    expect(result.success).toBe(false);
  });
});
