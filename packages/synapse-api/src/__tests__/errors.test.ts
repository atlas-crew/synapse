import { describe, it, expect } from 'vitest';
import { SynapseError } from '../errors.js';

describe('SynapseError', () => {
  describe('constructor', () => {
    it('should create error with message only', () => {
      const error = new SynapseError('Something went wrong');
      expect(error.message).toBe('Something went wrong');
      expect(error.name).toBe('SynapseError');
      expect(error.statusCode).toBeUndefined();
      expect(error.response).toBeUndefined();
    });

    it('should create error with message and status code', () => {
      const error = new SynapseError('Not Found', 404);
      expect(error.message).toBe('Not Found');
      expect(error.statusCode).toBe(404);
    });

    it('should create error with all parameters', () => {
      const error = new SynapseError('Error', 500, '{"error":"Internal"}');
      expect(error.statusCode).toBe(500);
      expect(error.response).toBe('{"error":"Internal"}');
    });

    it('should be an instance of Error', () => {
      const error = new SynapseError('Test');
      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(SynapseError);
    });

    it('should preserve stack trace', () => {
      const error = new SynapseError('Test error');
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('SynapseError');
    });
  });

  describe('isStatus()', () => {
    it('should return true for matching status code', () => {
      const error = new SynapseError('Not Found', 404);
      expect(error.isStatus(404)).toBe(true);
    });

    it('should return false for non-matching status code', () => {
      const error = new SynapseError('Not Found', 404);
      expect(error.isStatus(500)).toBe(false);
    });

    it('should return false when no status code is set', () => {
      const error = new SynapseError('Network error');
      expect(error.isStatus(500)).toBe(false);
    });
  });

  describe('isClientError()', () => {
    it('should return true for 400', () => {
      expect(new SynapseError('Bad Request', 400).isClientError()).toBe(true);
    });

    it('should return true for 401', () => {
      expect(new SynapseError('Unauthorized', 401).isClientError()).toBe(true);
    });

    it('should return true for 403', () => {
      expect(new SynapseError('Forbidden', 403).isClientError()).toBe(true);
    });

    it('should return true for 404', () => {
      expect(new SynapseError('Not Found', 404).isClientError()).toBe(true);
    });

    it('should return true for 499', () => {
      expect(new SynapseError('Client Closed', 499).isClientError()).toBe(true);
    });

    it('should return false for 500', () => {
      expect(new SynapseError('Server Error', 500).isClientError()).toBe(false);
    });

    it('should return false for 399', () => {
      expect(new SynapseError('Redirect', 399).isClientError()).toBe(false);
    });

    it('should return false when no status code', () => {
      expect(new SynapseError('Network error').isClientError()).toBe(false);
    });
  });

  describe('isServerError()', () => {
    it('should return true for 500', () => {
      expect(new SynapseError('Internal Error', 500).isServerError()).toBe(true);
    });

    it('should return true for 502', () => {
      expect(new SynapseError('Bad Gateway', 502).isServerError()).toBe(true);
    });

    it('should return true for 503', () => {
      expect(new SynapseError('Service Unavailable', 503).isServerError()).toBe(true);
    });

    it('should return true for 504', () => {
      expect(new SynapseError('Gateway Timeout', 504).isServerError()).toBe(true);
    });

    it('should return false for 404', () => {
      expect(new SynapseError('Not Found', 404).isServerError()).toBe(false);
    });

    it('should return false for 499', () => {
      expect(new SynapseError('Client Closed', 499).isServerError()).toBe(false);
    });

    it('should return false when no status code', () => {
      expect(new SynapseError('Network error').isServerError()).toBe(false);
    });
  });

  describe('isNetworkError()', () => {
    it('should return true when no status code (network failure)', () => {
      const error = new SynapseError('Network failure');
      expect(error.isNetworkError()).toBe(true);
    });

    it('should return false when status code is present', () => {
      const error = new SynapseError('Server Error', 500);
      expect(error.isNetworkError()).toBe(false);
    });
  });

  describe('fromResponse()', () => {
    it('should create error from HTTP response', () => {
      const error = SynapseError.fromResponse(404, 'Not Found');
      expect(error).toBeInstanceOf(SynapseError);
      expect(error.message).toBe('HTTP 404: Not Found');
      expect(error.statusCode).toBe(404);
      expect(error.response).toBe('Not Found');
    });

    it('should create error from 500 response', () => {
      const error = SynapseError.fromResponse(500, 'Internal Server Error');
      expect(error.statusCode).toBe(500);
      expect(error.isServerError()).toBe(true);
    });
  });

  describe('fromNetworkError()', () => {
    it('should create error from native Error', () => {
      const nativeError = new Error('ECONNREFUSED');
      const error = SynapseError.fromNetworkError(nativeError);
      expect(error).toBeInstanceOf(SynapseError);
      expect(error.message).toBe('Network error: ECONNREFUSED');
      expect(error.statusCode).toBeUndefined();
      expect(error.isNetworkError()).toBe(true);
    });

    it('should create error from TypeError', () => {
      const typeError = new TypeError('Failed to fetch');
      const error = SynapseError.fromNetworkError(typeError);
      expect(error.message).toContain('Failed to fetch');
      expect(error.isNetworkError()).toBe(true);
    });

    it('should set cause property', () => {
      const originalError = new Error('DNS resolution failed');
      const error = SynapseError.fromNetworkError(originalError);
      expect(error.cause).toBe(originalError);
    });
  });
});
