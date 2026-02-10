/**
 * Crypto Utilities Tests
 * Security: WS3-004 - Verify encryption/decryption for sensitive config data
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  encryptConfig,
  decryptConfig,
  encryptSensitiveFields,
  decryptSensitiveFields,
  hasEncryptedFields,
} from '../crypto.js';

describe('Crypto Utilities', () => {
  // Store original env to restore after tests
  const originalEnv = process.env.CONFIG_ENCRYPTION_KEY;

  beforeAll(() => {
    // Set a test key
    process.env.CONFIG_ENCRYPTION_KEY = 'test-encryption-key-for-unit-tests-only';
  });

  afterAll(() => {
    // Restore original env
    if (originalEnv) {
      process.env.CONFIG_ENCRYPTION_KEY = originalEnv;
    } else {
      delete process.env.CONFIG_ENCRYPTION_KEY;
    }
  });

  describe('encryptConfig / decryptConfig', () => {
    it('should encrypt and decrypt a string', () => {
      const plaintext = 'my-secret-api-key-12345';
      const encrypted = encryptConfig(plaintext);

      expect(encrypted).not.toBe(plaintext);
      expect(encrypted).toBeTruthy();

      const decrypted = decryptConfig(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle empty strings', () => {
      expect(encryptConfig('')).toBe('');
      expect(decryptConfig('')).toBe('');
    });

    it('should produce different ciphertext for same input (due to random IV)', () => {
      const plaintext = 'same-secret';
      const encrypted1 = encryptConfig(plaintext);
      const encrypted2 = encryptConfig(plaintext);

      expect(encrypted1).not.toBe(encrypted2);

      // Both should decrypt to same value
      expect(decryptConfig(encrypted1)).toBe(plaintext);
      expect(decryptConfig(encrypted2)).toBe(plaintext);
    });

    it('should handle special characters', () => {
      const plaintext = 'secret with special chars: !@#$%^&*()_+-=[]{}|;:",.<>?/\\`~\n\t';
      const encrypted = encryptConfig(plaintext);
      const decrypted = decryptConfig(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle unicode characters', () => {
      const plaintext = 'secret with unicode: 日本語 🔐 émojis';
      const encrypted = encryptConfig(plaintext);
      const decrypted = decryptConfig(encrypted);
      expect(decrypted).toBe(plaintext);
    });
  });

  describe('encryptSensitiveFields / decryptSensitiveFields', () => {
    it('should encrypt fields matching sensitive patterns', () => {
      const config = {
        name: 'my-sensor',
        hmacSecret: 'secret-key-123',
        tlsKey: 'private-key-pem',
        adminPassword: 'admin123',
        apiToken: 'token-abc',
        normalField: 'not-encrypted',
      };

      const encrypted = encryptSensitiveFields(config);

      // Non-sensitive fields unchanged
      expect(encrypted.name).toBe('my-sensor');
      expect(encrypted.normalField).toBe('not-encrypted');

      // Sensitive fields encrypted
      expect(encrypted.hmacSecret).toHaveProperty('_encrypted', true);
      expect(encrypted.tlsKey).toHaveProperty('_encrypted', true);
      expect(encrypted.adminPassword).toHaveProperty('_encrypted', true);
      expect(encrypted.apiToken).toHaveProperty('_encrypted', true);

      // Should be able to decrypt
      const decrypted = decryptSensitiveFields(encrypted);
      expect(decrypted.hmacSecret).toBe('secret-key-123');
      expect(decrypted.tlsKey).toBe('private-key-pem');
      expect(decrypted.adminPassword).toBe('admin123');
      expect(decrypted.apiToken).toBe('token-abc');
    });

    it('should handle nested objects', () => {
      const config = {
        server: {
          port: 8080,
          credentials: {
            username: 'admin',
            password: 'secret123',
          },
        },
        tls: {
          privateKey: 'key-content',
          cert: 'cert-content', // Not a sensitive pattern
        },
      };

      const encrypted = encryptSensitiveFields(config);

      // password should be encrypted
      const encryptedServer = encrypted.server as { credentials: { password: { _encrypted: boolean } } };
      expect(encryptedServer.credentials.password).toHaveProperty('_encrypted', true);

      // privateKey should be encrypted
      const encryptedTls = encrypted.tls as { privateKey: { _encrypted: boolean }; cert: string };
      expect(encryptedTls.privateKey).toHaveProperty('_encrypted', true);

      // cert should NOT be encrypted (doesn't match patterns)
      expect(encryptedTls.cert).toBe('cert-content');

      const decrypted = decryptSensitiveFields(encrypted);
      const decryptedServer = decrypted.server as { credentials: { password: string } };
      const decryptedTls = decrypted.tls as { privateKey: string };
      expect(decryptedServer.credentials.password).toBe('secret123');
      expect(decryptedTls.privateKey).toBe('key-content');
    });

    it('should handle null and undefined values', () => {
      const config = {
        secret: 'value',
        nullField: null,
        undefinedField: undefined,
      };

      const encrypted = encryptSensitiveFields(config);
      expect(encrypted.nullField).toBeNull();
      expect(encrypted.undefinedField).toBeUndefined();
    });
  });

  describe('hasEncryptedFields', () => {
    it('should detect encrypted fields', () => {
      const encrypted = {
        name: 'test',
        secret: { _encrypted: true, value: 'abc123' },
      };

      expect(hasEncryptedFields(encrypted)).toBe(true);
    });

    it('should return false for plaintext config', () => {
      const plaintext = {
        name: 'test',
        secret: 'plaintext-secret',
      };

      expect(hasEncryptedFields(plaintext)).toBe(false);
    });

    it('should detect nested encrypted fields', () => {
      const nested = {
        level1: {
          level2: {
            secret: { _encrypted: true, value: 'xyz' },
          },
        },
      };

      expect(hasEncryptedFields(nested)).toBe(true);
    });
  });

  describe('decryptConfig tamper resistance', () => {
    it('should throw when ciphertext byte is flipped', () => {
      const plaintext = 'sensitive-api-key-value';
      const encrypted = encryptConfig(plaintext);

      // Decode, flip a byte in the middle of the ciphertext portion, re-encode
      const buf = Buffer.from(encrypted, 'base64');
      // salt(16) + iv(12) + authTag(16) = 44 bytes header; flip a byte in the ciphertext
      const flipIndex = Math.min(48, buf.length - 1);
      buf[flipIndex] = buf[flipIndex] ^ 0xff;
      const tampered = buf.toString('base64');

      expect(() => decryptConfig(tampered)).toThrow();
    });

    it('should throw when ciphertext is truncated', () => {
      const plaintext = 'another-secret-value-12345';
      const encrypted = encryptConfig(plaintext);

      // Decode and chop off the last 8 bytes, then re-encode
      const buf = Buffer.from(encrypted, 'base64');
      const truncated = buf.subarray(0, buf.length - 8).toString('base64');

      expect(() => decryptConfig(truncated)).toThrow();
    });

    it('should throw on garbled / invalid base64 input', () => {
      const garbled = '!!!not-valid-base64-at-all@@@###$$$';
      expect(() => decryptConfig(garbled)).toThrow();
    });
  });
});
