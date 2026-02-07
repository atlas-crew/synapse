/**
 * Management API Routes
 *
 * Handles sensor API key management and connectivity monitoring.
 */

import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import dns from 'dns/promises';
import tls from 'tls';
import net from 'net';
import { spawn } from 'child_process';
import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import { requireScope } from '../middleware/auth.js';
import { rateLimiters } from '../../middleware/rate-limiter.js';
import {
  getFleetCommandFeaturesForConfig,
  updateFleetCommandFeatures,
} from '../../services/fleet/command-features.js';

// =============================================================================
// Configuration
// =============================================================================

const CONNECTIVITY_CONFIG = {
  timeouts: {
    ping: 15000,
    dns: 10000,
    tls: 10000,
    traceroute: 60000,
  },
  limits: {
    maxHostnameLength: 253,
    maxLabelLength: 63,
    maxConcurrentTests: 3,
    pingPackets: 3,
    tracerouteMaxHops: 15,
  },
} as const;

// Default test targets (well-known public endpoints)
const DEFAULT_TEST_TARGETS = {
  ping: '8.8.8.8',
  dns: 'google.com',
  tls: 'google.com',
  traceroute: '8.8.8.8',
} as const;

// Concurrency limiter for expensive operations
let activeTests = 0;

// =============================================================================
// Network Diagnostic Test Types
// =============================================================================

type ErrorType = 'timeout' | 'connection_refused' | 'dns_error' | 'tls_error' | 'unreachable' | 'blocked' | 'unknown';

interface TestResult {
  testType: string;
  status: 'passed' | 'failed' | 'error';
  target: string;
  latencyMs: number | null;
  details: Record<string, unknown>;
  errorType?: ErrorType;
  error?: string;
  timestamp: string;
}

// =============================================================================
// SSRF Protection - Comprehensive IP/Hostname Validation
// =============================================================================

/**
 * Blocked hostname patterns (cloud metadata, internal services)
 */
const BLOCKED_HOSTNAMES = [
  /^localhost$/i,
  /^.*\.localhost$/i,
  /^.*\.local$/i,
  /^.*\.internal$/i,
  /^metadata\.google\.internal$/i,
  /^metadata$/i,
  /^kubernetes\.default\.svc/i,
  /^.*\.svc\.cluster\.local$/i,
];

/**
 * Check if an IP address is private, reserved, or otherwise blocked
 */
function isBlockedIP(ip: string): boolean {
  // Handle IPv4-mapped IPv6 addresses
  let normalizedIP = ip;
  if (ip.startsWith('::ffff:')) {
    normalizedIP = ip.substring(7);
  }

  // IPv4 checks
  if (net.isIPv4(normalizedIP)) {
    const parts = normalizedIP.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return true;
    }

    const [a, b, c, d] = parts;
    const ipNum = (a << 24) | (b << 16) | (c << 8) | d;

    // Blocked IPv4 ranges
    const blockedRanges = [
      { start: 0x0A000000, end: 0x0AFFFFFF, name: '10.0.0.0/8' },         // Private
      { start: 0xAC100000, end: 0xAC1FFFFF, name: '172.16.0.0/12' },      // Private
      { start: 0xC0A80000, end: 0xC0A8FFFF, name: '192.168.0.0/16' },     // Private
      { start: 0x7F000000, end: 0x7FFFFFFF, name: '127.0.0.0/8' },        // Loopback
      { start: 0xA9FE0000, end: 0xA9FEFFFF, name: '169.254.0.0/16' },     // Link-local
      { start: 0x00000000, end: 0x00FFFFFF, name: '0.0.0.0/8' },          // This network
      { start: 0xE0000000, end: 0xEFFFFFFF, name: '224.0.0.0/4' },        // Multicast
      { start: 0xF0000000, end: 0xFFFFFFFF, name: '240.0.0.0/4' },        // Reserved
      { start: 0x64400000, end: 0x647FFFFF, name: '100.64.0.0/10' },      // CGN
      { start: 0xC0000000, end: 0xC00000FF, name: '192.0.0.0/24' },       // IETF Protocol
      { start: 0xC0000200, end: 0xC00002FF, name: '192.0.2.0/24' },       // TEST-NET-1
      { start: 0xC6336400, end: 0xC63364FF, name: '198.51.100.0/24' },    // TEST-NET-2
      { start: 0xCB007100, end: 0xCB0071FF, name: '203.0.113.0/24' },     // TEST-NET-3
      { start: 0xC6120000, end: 0xC613FFFF, name: '198.18.0.0/15' },      // Benchmarking
    ];

    for (const range of blockedRanges) {
      if (ipNum >= range.start && ipNum <= range.end) {
        return true;
      }
    }

    // Explicitly block cloud metadata endpoint
    if (normalizedIP === '169.254.169.254') {
      return true;
    }

    return false;
  }

  // IPv6 checks
  if (net.isIPv6(ip)) {
    const lowerIP = ip.toLowerCase();
    const blockedIPv6Prefixes = [
      '::1',           // Loopback
      'fe80:',         // Link-local
      'fc00:',         // Unique local
      'fd00:',         // Unique local
      'ff00:',         // Multicast
      '::ffff:',       // IPv4-mapped (check recursively)
      '2001:db8:',     // Documentation
    ];

    for (const prefix of blockedIPv6Prefixes) {
      if (lowerIP === prefix.replace(/:$/, '') || lowerIP.startsWith(prefix)) {
        return true;
      }
    }

    // Full loopback variations
    if (lowerIP === '0:0:0:0:0:0:0:1' || lowerIP === '0000:0000:0000:0000:0000:0000:0000:0001') {
      return true;
    }
  }

  return false;
}

/**
 * Check if hostname is blocked
 */
function isBlockedHostname(hostname: string): boolean {
  return BLOCKED_HOSTNAMES.some(pattern => pattern.test(hostname));
}

/**
 * Validate hostname format and length
 */
function validateHostnameFormat(hostname: string): { valid: boolean; error?: string } {
  // Length checks
  if (!hostname || hostname.length > CONNECTIVITY_CONFIG.limits.maxHostnameLength) {
    return { valid: false, error: 'Hostname must be 1-253 characters' };
  }

  // Check each label
  const labels = hostname.split('.');
  for (const label of labels) {
    if (label.length > CONNECTIVITY_CONFIG.limits.maxLabelLength) {
      return { valid: false, error: 'Hostname label exceeds 63 characters' };
    }
    if (label.length === 0) {
      return { valid: false, error: 'Empty label in hostname' };
    }
  }

  // Format validation (hostname or IPv4)
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::(?:[a-fA-F0-9]{1,4}:){0,6}[a-fA-F0-9]{1,4}$|^(?:[a-fA-F0-9]{1,4}:){1,6}::(?:[a-fA-F0-9]{1,4}:){0,5}[a-fA-F0-9]{1,4}$/;

  if (!hostnameRegex.test(hostname) && !ipv4Regex.test(hostname) && !ipv6Regex.test(hostname)) {
    return { valid: false, error: 'Invalid hostname or IP address format' };
  }

  return { valid: true };
}

/**
 * Resolve hostname and validate the resolved IP (DNS rebinding protection)
 */
async function resolveAndValidateTarget(target: string, logger: Logger): Promise<{ ip: string; hostname: string }> {
  // If already an IP, validate directly
  if (net.isIP(target)) {
    if (isBlockedIP(target)) {
      throw new Error('Target IP is blocked (private/reserved range)');
    }
    return { ip: target, hostname: target };
  }

  // Check if hostname is blocked
  if (isBlockedHostname(target)) {
    throw new Error('Target hostname is blocked');
  }

  // Resolve hostname to IP first
  try {
    const { address } = await dns.lookup(target, { family: 4 });

    // Validate the resolved IP (prevents DNS rebinding)
    if (isBlockedIP(address)) {
      logger.warn({ target, resolvedIP: address }, 'DNS resolved to blocked IP');
      throw new Error('Target resolves to blocked IP address');
    }

    return { ip: address, hostname: target };
  } catch (error) {
    if ((error as Error).message.includes('blocked')) {
      throw error;
    }
    throw new Error('Failed to resolve hostname');
  }
}

/**
 * Sanitize error messages to prevent information disclosure
 */
function sanitizeErrorMessage(error: unknown): string {
  const rawMessage = error instanceof Error ? error.message : 'Unknown error';

  // Map known error codes to generic messages
  const errorMappings: Record<string, string> = {
    ECONNREFUSED: 'Connection refused',
    ETIMEDOUT: 'Connection timed out',
    ENOTFOUND: 'Host not found',
    EHOSTUNREACH: 'Host unreachable',
    ENETUNREACH: 'Network unreachable',
    ECONNRESET: 'Connection reset',
    EPERM: 'Operation not permitted',
    EACCES: 'Access denied',
  };

  for (const [code, message] of Object.entries(errorMappings)) {
    if (rawMessage.includes(code)) {
      return message;
    }
  }

  // Remove potentially sensitive information
  return rawMessage
    .replace(/\/[^\s]+/g, '[PATH]')
    .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, '[IP]')
    .replace(/port \d+/gi, 'port [REDACTED]')
    .slice(0, 200);
}

/**
 * Classify error type for structured responses
 */
function classifyError(error: unknown): ErrorType {
  const message = error instanceof Error ? error.message : '';

  if (message.includes('ETIMEDOUT') || message.includes('timed out') || message.includes('timeout')) {
    return 'timeout';
  }
  if (message.includes('ECONNREFUSED') || message.includes('refused')) {
    return 'connection_refused';
  }
  if (message.includes('ENOTFOUND') || message.includes('not found')) {
    return 'dns_error';
  }
  if (message.includes('certificate') || message.includes('TLS') || message.includes('SSL')) {
    return 'tls_error';
  }
  if (message.includes('EHOSTUNREACH') || message.includes('unreachable')) {
    return 'unreachable';
  }
  if (message.includes('blocked')) {
    return 'blocked';
  }

  return 'unknown';
}

// =============================================================================
// Secure Command Execution (No Shell Injection)
// =============================================================================

/**
 * Run command with spawn (no shell) and proper cleanup
 */
function runCommandSafe(
  command: string,
  args: string[],
  timeout: number
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let killed = false;

    const proc = spawn(command, args, {
      shell: false,
      timeout,
      env: { PATH: process.env.PATH },
    });

    const timeoutId = setTimeout(() => {
      if (!killed) {
        killed = true;
        proc.kill('SIGKILL');
        reject(new Error('Command timed out'));
      }
    }, timeout);

    proc.stdout?.on('data', (data: Buffer) => {
      stdout += data.toString();
      // Limit output size to prevent memory exhaustion
      if (stdout.length > 10000) {
        stdout = stdout.slice(0, 10000);
      }
    });

    proc.stderr?.on('data', (data: Buffer) => {
      stderr += data.toString();
      if (stderr.length > 5000) {
        stderr = stderr.slice(0, 5000);
      }
    });

    proc.on('close', (_code) => {
      clearTimeout(timeoutId);
      if (!killed) {
        resolve({ stdout, stderr });
      }
    });

    proc.on('error', (err) => {
      clearTimeout(timeoutId);
      if (!killed) {
        killed = true;
        reject(err);
      }
    });
  });
}

// =============================================================================
// Network Diagnostic Test Implementations
// =============================================================================

/**
 * Run a ping test using spawn (no shell injection)
 */
async function runPingTest(target: string, resolvedIP: string, logger: Logger): Promise<TestResult> {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  try {
    // Build args array (no string interpolation)
    const args = process.platform === 'win32'
      ? ['-n', '3', '-w', '5000', resolvedIP]
      : ['-c', '3', '-W', '5', resolvedIP];

    const { stdout } = await runCommandSafe('ping', args, CONNECTIVITY_CONFIG.timeouts.ping);
    const latencyMs = Date.now() - startTime;

    // Parse ping output for statistics
    const avgMatch = stdout.match(/(?:avg|average)[^0-9]*([0-9.]+)/i);
    const lossMatch = stdout.match(/([0-9.]+)%\s*(?:packet\s*)?loss/i);
    const ttlMatch = stdout.match(/ttl[=:]?\s*([0-9]+)/i);

    const avgLatency = avgMatch ? parseFloat(avgMatch[1]) : null;
    const packetLoss = lossMatch ? parseFloat(lossMatch[1]) : 0;
    const ttl = ttlMatch ? parseInt(ttlMatch[1], 10) : null;

    return {
      testType: 'ping',
      status: packetLoss < 100 ? 'passed' : 'failed',
      target,
      latencyMs: avgLatency || latencyMs,
      details: {
        packetsTransmitted: 3,
        packetLoss: `${packetLoss}%`,
        avgRoundTrip: avgLatency ? `${avgLatency}ms` : 'N/A',
        ttl,
      },
      timestamp,
    };
  } catch (error: unknown) {
    const errorType = classifyError(error);
    logger.warn({ errorType, target }, 'Ping test failed');
    return {
      testType: 'ping',
      status: 'failed',
      target,
      latencyMs: Date.now() - startTime,
      details: {},
      errorType,
      error: sanitizeErrorMessage(error),
      timestamp,
    };
  }
}

/**
 * Run a DNS resolution test
 */
async function runDnsTest(target: string, logger: Logger): Promise<TestResult> {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  try {
    // Resolve A records (IPv4)
    const addresses = await dns.resolve4(target);
    const latencyMs = Date.now() - startTime;

    // Get record count only (no sensitive details)
    let mxCount = 0;
    let nsCount = 0;
    let hasTxt = false;

    try { mxCount = (await dns.resolveMx(target)).length; } catch { /* optional */ }
    try { nsCount = (await dns.resolveNs(target)).length; } catch { /* optional */ }
    try { hasTxt = (await dns.resolveTxt(target)).length > 0; } catch { /* optional */ }

    return {
      testType: 'dns',
      status: 'passed',
      target,
      latencyMs,
      details: {
        resolvedAddresses: addresses,
        recordCount: addresses.length,
        mxRecordCount: mxCount,
        nsRecordCount: nsCount,
        hasTxtRecords: hasTxt,
      },
      timestamp,
    };
  } catch (error: unknown) {
    const errorType = classifyError(error);
    logger.warn({ errorType, target }, 'DNS test failed');
    return {
      testType: 'dns',
      status: 'failed',
      target,
      latencyMs: Date.now() - startTime,
      details: {},
      errorType,
      error: sanitizeErrorMessage(error),
      timestamp,
    };
  }
}

/**
 * Run a TLS handshake test with proper cleanup
 */
async function runTlsTest(target: string, resolvedIP: string, logger: Logger): Promise<TestResult> {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();
  const port = 443;
  const timeout = CONNECTIVITY_CONFIG.timeouts.tls;

  return new Promise((resolve) => {
    let resolved = false;

    const cleanup = (socket: tls.TLSSocket) => {
      if (!resolved) {
        resolved = true;
        socket.removeAllListeners();
        socket.destroy();
      }
    };

    const socket = tls.connect(
      {
        host: resolvedIP,
        port,
        servername: target,
        rejectUnauthorized: true,
        timeout,
      },
      () => {
        const latencyMs = Date.now() - startTime;
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        // Limited certificate details (no fingerprints, serial numbers)
        const certDetails = {
          subject: cert.subject?.CN || 'Unknown',
          issuer: cert.issuer?.O || 'Unknown',
          valid: socket.authorized,
          expiresInDays: cert.valid_to
            ? Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86400000)
            : null,
        };

        cleanup(socket);

        resolve({
          testType: 'tls',
          status: 'passed',
          target: `${target}:${port}`,
          latencyMs,
          details: {
            protocol,
            cipher: cipher?.name || 'Unknown',
            certificate: certDetails,
          },
          timestamp,
        });
      }
    );

    const timeoutId = setTimeout(() => {
      cleanup(socket);
      resolve({
        testType: 'tls',
        status: 'failed',
        target: `${target}:${port}`,
        latencyMs: timeout,
        details: {},
        errorType: 'timeout',
        error: 'TLS handshake timed out',
        timestamp,
      });
    }, timeout);

    socket.on('error', (error: Error) => {
      clearTimeout(timeoutId);
      if (!resolved) {
        const errorType = classifyError(error);
        logger.warn({ errorType, target }, 'TLS test failed');
        cleanup(socket);
        resolve({
          testType: 'tls',
          status: 'failed',
          target: `${target}:${port}`,
          latencyMs: Date.now() - startTime,
          details: {},
          errorType,
          error: sanitizeErrorMessage(error),
          timestamp,
        });
      }
    });

    socket.on('timeout', () => {
      clearTimeout(timeoutId);
      cleanup(socket);
      resolve({
        testType: 'tls',
        status: 'failed',
        target: `${target}:${port}`,
        latencyMs: timeout,
        details: {},
        errorType: 'timeout',
        error: 'Connection timeout',
        timestamp,
      });
    });
  });
}

/**
 * Run a traceroute test using spawn (no shell injection)
 */
async function runTracerouteTest(target: string, resolvedIP: string, logger: Logger): Promise<TestResult> {
  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  try {
    // Build args array (no string interpolation)
    const args = process.platform === 'win32'
      ? ['-h', '15', '-w', '3000', resolvedIP]
      : ['-m', '15', '-w', '3', resolvedIP];

    const command = process.platform === 'win32' ? 'tracert' : 'traceroute';
    const { stdout } = await runCommandSafe(command, args, CONNECTIVITY_CONFIG.timeouts.traceroute);
    const latencyMs = Date.now() - startTime;

    // Parse traceroute output
    const lines = stdout.split('\n').filter(line => line.trim());
    const hops: Array<{ hop: number; latency: string }> = [];

    for (const line of lines) {
      const hopMatch = line.match(/^\s*(\d+)\s+(.+)/);
      if (hopMatch) {
        const hopNum = parseInt(hopMatch[1], 10);
        const rest = hopMatch[2];
        const latencyMatch = rest.match(/([0-9.]+)\s*ms/);

        if (hopNum > 0) {
          hops.push({
            hop: hopNum,
            latency: latencyMatch ? `${latencyMatch[1]}ms` : '*',
          });
        }
      }
    }

    return {
      testType: 'traceroute',
      status: hops.length > 0 ? 'passed' : 'failed',
      target,
      latencyMs,
      details: {
        hopCount: hops.length,
        hops: hops.slice(0, 15),
      },
      timestamp,
    };
  } catch (error: unknown) {
    const errorType = classifyError(error);
    logger.warn({ errorType, target }, 'Traceroute test failed');
    return {
      testType: 'traceroute',
      status: 'failed',
      target,
      latencyMs: Date.now() - startTime,
      details: {},
      errorType,
      error: sanitizeErrorMessage(error),
      timestamp,
    };
  }
}

/**
 * Run a connectivity test by type with concurrency control
 */
async function runConnectivityTest(
  testType: string,
  target: string | undefined,
  logger: Logger
): Promise<TestResult> {
  const testTarget = target || DEFAULT_TEST_TARGETS[testType as keyof typeof DEFAULT_TEST_TARGETS] || '8.8.8.8';

  // Concurrency control
  if (activeTests >= CONNECTIVITY_CONFIG.limits.maxConcurrentTests) {
    return {
      testType,
      status: 'error',
      target: testTarget,
      latencyMs: null,
      details: {},
      errorType: 'blocked',
      error: 'Too many concurrent tests. Try again later.',
      timestamp: new Date().toISOString(),
    };
  }

  activeTests++;
  try {
    // Resolve and validate target (DNS rebinding protection)
    const { ip: resolvedIP, hostname } = await resolveAndValidateTarget(testTarget, logger);

    switch (testType) {
      case 'ping':
        return await runPingTest(hostname, resolvedIP, logger);
      case 'dns':
        return await runDnsTest(hostname, logger);
      case 'tls':
        return await runTlsTest(hostname, resolvedIP, logger);
      case 'traceroute':
        return await runTracerouteTest(hostname, resolvedIP, logger);
      default:
        return {
          testType,
          status: 'error',
          target: testTarget,
          latencyMs: null,
          details: {},
          error: `Unknown test type: ${testType}`,
          timestamp: new Date().toISOString(),
        };
    }
  } catch (error) {
    const errorType = classifyError(error);
    return {
      testType,
      status: 'error',
      target: testTarget,
      latencyMs: null,
      details: {},
      errorType,
      error: sanitizeErrorMessage(error),
      timestamp: new Date().toISOString(),
    };
  } finally {
    activeTests--;
  }
}

// Validation schemas
const createKeySchema = z.object({
  name: z.string().min(1).max(100),
  sensorId: z.string().uuid(),
  expiresAt: z.string().datetime().optional(),
  permissions: z.array(z.string()).optional(),
  purpose: z.string().max(255).optional(), // labs-afxu: Track token purpose
});

/**
 * Allowed scopes for sensor API keys. (labs-afxu)
 * Sensors should only have access to telemetry and blocklist sync.
 */
const ALLOWED_SENSOR_SCOPES = [
  'signal:write',
  'blocklist:read',
  'heartbeat:write',
  'config:read',
  'diag:write',
];

/**
 * Validates that requested scopes are appropriate for a sensor. (labs-afxu)
 */
function validateSensorScopes(requested: string[]): { valid: boolean; forbidden?: string[] } {
  const forbidden = requested.filter(s => !ALLOWED_SENSOR_SCOPES.includes(s));
  return {
    valid: forbidden.length === 0,
    forbidden: forbidden.length > 0 ? forbidden : undefined,
  };
}


const rotateKeySchema = z.object({
  expiresAt: z.string().datetime().optional(),
});

// Utility functions for API key management
function generateApiKey(): { key: string; hash: string; prefix: string } {
  const keyBytes = crypto.randomBytes(32);
  const key = keyBytes.toString('base64url');
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  const prefix = key.substring(0, 8);
  return { key, hash, prefix };
}

/**
 * Create management routes for API keys and connectivity
 */
export function createManagementRoutes(
  prisma: PrismaClient,
  logger: Logger
): Router {
  const router = Router();

  // =============================================================================
  // API Keys Management
  // =============================================================================

  /**
   * GET /keys - List all sensor API keys for tenant
   */
  router.get('/keys', requireScope('fleet:read'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;

      const keys = await prisma.sensorApiKey.findMany({
        where: {
          sensor: {
            tenantId,
          },
        },
        include: {
          sensor: {
            select: {
              id: true,
              name: true,
              connectionState: true,
            },
          },
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      // Sanitize: don't include key hash in response
      const sanitizedKeys = keys.map((key) => {
        const { keyHash, ...rest } = key;
        void keyHash;
        return {
          ...rest,
          sensor: key.sensor,
        };
      });

      res.json({
        keys: sanitizedKeys,
        total: sanitizedKeys.length,
      });
    } catch (error) {
      logger.error({ error }, 'Error listing API keys');
      res.status(500).json({
        error: 'Failed to list API keys',
      });
    }
  });

  /**
   * POST /keys - Generate new API key for a sensor
   */
  router.post('/keys', requireScope('fleet:write'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;
      const userId = req.auth!.userId;

      const validation = createKeySchema.safeParse(req.body);
      if (!validation.success) {
        res.status(400).json({
          error: 'Invalid request',
          details: validation.error.errors,
        });
        return;
      }

      const { name, sensorId, expiresAt, permissions, purpose } = validation.data;

      // labs-afxu: Validate requested scopes
      const requestedScopes = permissions || ['signal:write'];
      const scopeCheck = validateSensorScopes(requestedScopes);
      if (!scopeCheck.valid) {
        this.logger.warn({ sensorId, tenantId, forbidden: scopeCheck.forbidden }, 'Rejected unauthorized scopes for sensor token');
        return sendProblem(res, 403, 'Unauthorized scopes for sensor', {
          code: 'FORBIDDEN_SCOPES',
          details: { forbidden: scopeCheck.forbidden, allowed: ALLOWED_SENSOR_SCOPES },
          instance: req.originalUrl,
        });
      }

      // Verify sensor belongs to tenant
      const sensor = await prisma.sensor.findFirst({
        where: {
          id: sensorId,
          tenantId,
        },
      });

      if (!sensor) {
        res.status(404).json({
          error: 'Sensor not found or access denied',
        });
        return;
      }

      // Generate new API key
      const { key, hash, prefix } = generateApiKey();

      const apiKey = await prisma.sensorApiKey.create({
        data: {
          name,
          keyHash: hash,
          keyPrefix: prefix,
          sensorId,
          expiresAt: expiresAt ? new Date(expiresAt) : null,
          permissions: requestedScopes,
          createdBy: userId,
          status: 'ACTIVE',
        },
        include: {
          sensor: {
            select: {
              id: true,
              name: true,
              connectionState: true,
            },
          },
        },
      });

      // Return key only once - cannot be retrieved again
      const { keyHash, ...sanitizedKey } = apiKey;
      void keyHash;

      logger.info({ 
        keyId: apiKey.id, 
        sensorId, 
        tenantId, 
        userId, 
        scopes: requestedScopes,
        purpose: purpose || 'unspecified'
      }, 'Sensor API key created');

      res.status(201).json({
        ...sanitizedKey,
        key,
        warning: 'This key will only be shown once. Store it securely.',
      });
    } catch (error) {
      logger.error({ error }, 'Error creating API key');
      res.status(500).json({
        error: 'Failed to create API key',
      });
    }
  });

  /**
   * DELETE /keys/:keyId - Revoke an API key
   */
  router.delete('/keys/:keyId', requireScope('fleet:write'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;
      const { keyId } = req.params;

      const apiKey = await prisma.sensorApiKey.findFirst({
        where: {
          id: keyId,
          sensor: {
            tenantId,
          },
        },
      });

      if (!apiKey) {
        res.status(404).json({
          error: 'API key not found or access denied',
        });
        return;
      }

      await prisma.sensorApiKey.update({
        where: { id: keyId },
        data: {
          status: 'REVOKED',
        },
      });

      logger.info({ keyId }, 'API key revoked');

      res.json({
        message: 'API key revoked successfully',
        keyId,
      });
    } catch (error) {
      logger.error({ error }, 'Error revoking API key');
      res.status(500).json({
        error: 'Failed to revoke API key',
      });
    }
  });

  /**
   * POST /keys/:keyId/rotate - Rotate an API key
   */
  router.post('/keys/:keyId/rotate', requireScope('fleet:write'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;
      const { keyId } = req.params;

      const validation = rotateKeySchema.safeParse(req.body);
      if (!validation.success) {
        res.status(400).json({
          error: 'Invalid request',
          details: validation.error.errors,
        });
        return;
      }

      const { expiresAt } = validation.data;

      const existingKey = await prisma.sensorApiKey.findFirst({
        where: {
          id: keyId,
          sensor: {
            tenantId,
          },
        },
        include: {
          sensor: {
            select: {
              id: true,
              name: true,
              connectionState: true,
            },
          },
        },
      });

      if (!existingKey) {
        res.status(404).json({
          error: 'API key not found or access denied',
        });
        return;
      }

      if (existingKey.status === 'REVOKED') {
        res.status(400).json({
          error: 'Cannot rotate a revoked key',
        });
        return;
      }

      const { key, hash, prefix } = generateApiKey();

      const updatedKey = await prisma.sensorApiKey.update({
        where: { id: keyId },
        data: {
          keyHash: hash,
          keyPrefix: prefix,
          expiresAt: expiresAt ? new Date(expiresAt) : existingKey.expiresAt,
        },
        include: {
          sensor: {
            select: {
              id: true,
              name: true,
              connectionState: true,
            },
          },
        },
      });

      const { keyHash, ...sanitizedKey } = updatedKey;
      void keyHash;

      logger.info({ keyId }, 'API key rotated');

      res.json({
        ...sanitizedKey,
        key,
        warning: 'This key will only be shown once. Store it securely.',
      });
    } catch (error) {
      logger.error({ error }, 'Error rotating API key');
      res.status(500).json({
        error: 'Failed to rotate API key',
      });
    }
  });

  // =============================================================================
  // Connectivity Management
  // =============================================================================

  /**
   * GET /connectivity - Fleet-wide connectivity status
   */
  router.get('/connectivity', requireScope('fleet:read'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;

      const sensors = await prisma.sensor.findMany({
        where: { tenantId },
        select: {
          id: true,
          name: true,
          connectionState: true,
          lastHeartbeat: true,
        },
        orderBy: { name: 'asc' },
      });

      const now = new Date();
      const fiveMinutesAgo = new Date(now.getTime() - 5 * 60 * 1000);

      const stats = {
        total: sensors.length,
        online: sensors.filter(s => s.connectionState === 'CONNECTED').length,
        offline: sensors.filter(s => s.connectionState === 'DISCONNECTED').length,
        reconnecting: sensors.filter(s => s.connectionState === 'RECONNECTING').length,
        recentlyActive: sensors.filter(s =>
          s.lastHeartbeat && s.lastHeartbeat > fiveMinutesAgo
        ).length,
      };

      const byState = {
        CONNECTED: sensors.filter(s => s.connectionState === 'CONNECTED'),
        DISCONNECTED: sensors.filter(s => s.connectionState === 'DISCONNECTED'),
        RECONNECTING: sensors.filter(s => s.connectionState === 'RECONNECTING'),
      };

      res.json({
        stats,
        sensors: byState,
        timestamp: now.toISOString(),
      });
    } catch (error) {
      logger.error({ error }, 'Error fetching connectivity status');
      res.status(500).json({
        error: 'Failed to fetch connectivity status',
      });
    }
  });

  /**
   * POST /connectivity/test - Run network diagnostic tests
   *
   * Command endpoint (RPC-style) that performs connectivity tests.
   * Uses POST because of complex request body and side effects.
   *
   * Security measures:
   * - SSRF protection (blocks private IPs, cloud metadata, DNS rebinding)
   * - Command injection prevention (spawn with args, no shell)
   * - Rate limiting (10 requests/minute)
   * - Concurrency limiting (max 3 concurrent tests)
   * - Input validation and sanitization
   * - Audit logging
   *
   * @param testType - 'ping' | 'dns' | 'tls' | 'traceroute'
   * @param target - Optional hostname/IP (defaults to well-known endpoints)
   */
  router.post(
    '/connectivity/test',
    rateLimiters.connectivityTest,
    requireScope('fleet:write'),
    async (req: Request, res: Response) => {
    const startTime = Date.now();
    const clientIP = req.ip || 'unknown';
    const userId = req.auth?.userId || 'unknown';

    try {
      const { testType, target } = req.body;

      // Validate test type
      const validTestTypes = ['ping', 'dns', 'tls', 'traceroute'];
      if (!testType || !validTestTypes.includes(testType)) {
        res.status(400).json({
          type: 'https://api.signal-horizon.io/errors/validation-error',
          title: 'Invalid test type',
          status: 400,
          detail: `Test type must be one of: ${validTestTypes.join(', ')}`,
          validTypes: validTestTypes,
        });
        return;
      }

      // Validate target if provided
      if (target) {
        // Hostname format and length validation
        const validation = validateHostnameFormat(target);
        if (!validation.valid) {
          res.status(400).json({
            type: 'https://api.signal-horizon.io/errors/validation-error',
            title: 'Invalid target',
            status: 400,
            detail: validation.error,
          });
          return;
        }

        // Check if hostname is blocked
        if (isBlockedHostname(target)) {
          logger.warn({ clientIP, userId, target, testType }, 'Blocked hostname test attempt');
          res.status(400).json({
            type: 'https://api.signal-horizon.io/errors/ssrf-blocked',
            title: 'Target blocked',
            status: 400,
            detail: 'This target hostname is not allowed',
          });
          return;
        }

        // Check if IP is blocked (if target is an IP)
        if (net.isIP(target) && isBlockedIP(target)) {
          logger.warn({ clientIP, userId, target, testType }, 'Blocked IP test attempt');
          res.status(400).json({
            type: 'https://api.signal-horizon.io/errors/ssrf-blocked',
            title: 'Target blocked',
            status: 400,
            detail: 'Private and reserved IP addresses are not allowed',
          });
          return;
        }
      }

      // Audit log: test initiated
      logger.info(
        { clientIP, userId, testType, target: target || 'default', action: 'CONNECTIVITY_TEST_START' },
        'Connectivity test initiated'
      );

      // Run the actual test
      const result = await runConnectivityTest(testType, target, logger);

      // Audit log: test completed
      logger.info(
        {
          clientIP,
          userId,
          testType,
          target: result.target,
          status: result.status,
          latencyMs: result.latencyMs,
          duration: Date.now() - startTime,
          action: 'CONNECTIVITY_TEST_COMPLETE',
        },
        'Connectivity test completed'
      );

      res.json({
        result,
        request: {
          testType,
          target: result.target,
        },
        metadata: {
          timestamp: new Date().toISOString(),
          requestId: req.headers['x-request-id'] as string,
        },
      });
    } catch (error) {
      // Audit log: test failed
      logger.error(
        {
          clientIP,
          userId,
          testType: req.body?.testType,
          error: error instanceof Error ? error.message : 'Unknown error',
          duration: Date.now() - startTime,
          action: 'CONNECTIVITY_TEST_ERROR',
        },
        'Connectivity test error'
      );

      res.status(500).json({
        type: 'https://api.signal-horizon.io/errors/internal-error',
        title: 'Test failed',
        status: 500,
        detail: 'An unexpected error occurred while running the connectivity test',
      });
    }
  });

  /**
   * GET /connectivity/history - Historical connectivity data
   */
  router.get('/connectivity/history', requireScope('fleet:read'), async (req: Request, res: Response) => {
    try {
      const tenantId = req.auth!.tenantId;
      const { sensorId, hours = '24' } = req.query;

      const hoursNum = parseInt(hours as string, 10);
      if (isNaN(hoursNum) || hoursNum < 1 || hoursNum > 168) {
        res.status(400).json({
          error: 'hours must be a number between 1 and 168',
        });
        return;
      }

      const now = new Date();
      const startTime = new Date(now.getTime() - hoursNum * 60 * 60 * 1000);

      const sensors = await prisma.sensor.findMany({
        where: sensorId
          ? { id: sensorId as string, tenantId }
          : { tenantId },
        select: {
          id: true,
          name: true,
          connectionState: true,
          lastHeartbeat: true,
        },
      });

      // Generate sample historical data
      const historyData = sensors.map(sensor => {
        const dataPoints = [];
        const intervalMinutes = hoursNum > 24 ? 60 : 15;
        const points = Math.floor((hoursNum * 60) / intervalMinutes);

        for (let i = points; i >= 0; i--) {
          const timestamp = new Date(now.getTime() - i * intervalMinutes * 60 * 1000);

          const state = sensor.connectionState === 'CONNECTED' && Math.random() > 0.1
            ? 'CONNECTED'
            : Math.random() > 0.7 ? 'DISCONNECTED' : 'RECONNECTING';

          dataPoints.push({
            timestamp: timestamp.toISOString(),
            state,
            latencyMs: state === 'CONNECTED' ? Math.floor(Math.random() * 100) : null,
          });
        }

        return {
          sensorId: sensor.id,
          sensorName: sensor.name,
          currentState: sensor.connectionState,
          dataPoints,
        };
      });

      res.json({
        sensors: historyData,
        timeRange: {
          start: startTime.toISOString(),
          end: now.toISOString(),
          hours: hoursNum,
        },
      });
    } catch (error) {
      logger.error({ error }, 'Error fetching connectivity history');
      res.status(500).json({
        error: 'Failed to fetch connectivity history',
      });
    }
  });

  // =============================================================================
  // Hub Configuration Management
  // =============================================================================

  /**
   * GET /config - Get hub runtime configuration
   */
  router.get('/config', requireScope('fleet:admin'), async (_req: Request, res: Response) => {
    try {
      const { config } = await import('../../config.js');
      
      // Sanitize sensitive values
      const sanitizedConfig = {
        ...config,
        // Overlay runtime feature flags so the UI reflects live state.
        fleetCommands: getFleetCommandFeaturesForConfig(),
        database: {
          url: config.database.url.replace(/\/\/.*:.*@/, '//****:****@'),
        },
        telemetry: {
          ...config.telemetry,
          jwtSecret: '••••••••••••••••',
        },
        sensorBridge: {
          ...config.sensorBridge,
          apiKey: config.sensorBridge.apiKey ? '••••••••••••••••' : undefined,
        },
        clickhouse: {
          ...config.clickhouse,
          password: '••••••••••••••••',
        },
      };

      res.json(sanitizedConfig);
    } catch (error) {
      logger.error({ error }, 'Error fetching hub config');
      res.status(500).json({ error: 'Failed to fetch hub configuration' });
    }
  });

  /**
   * PATCH /config - Update hub runtime configuration
   * Note: Some changes (like PORT) may require a restart to take effect.
   */
  router.patch('/config', requireScope('fleet:admin'), async (req: Request, res: Response) => {
    try {
      const updateSchema = z.object({
        server: z.object({
          port: z.number().int().min(1).max(65535).optional(),
          host: z.string().optional(),
        }).optional(),
        aggregator: z.object({
          batchSize: z.number().int().positive().optional(),
          batchTimeoutMs: z.number().int().positive().optional(),
        }).optional(),
        broadcaster: z.object({
          pushDelayMs: z.number().int().nonnegative().optional(),
          cacheSize: z.number().int().positive().optional(),
        }).optional(),
        fleetCommands: z.object({
          enableToggleChaos: z.boolean().optional(),
          enableToggleMtd: z.boolean().optional(),
        }).optional(),
      });

      const validation = updateSchema.safeParse(req.body);
      if (!validation.success) {
        res.status(400).json({ error: 'Invalid configuration update', details: validation.error.errors });
        return;
      }

      // Runtime-only updates: apply feature flags immediately in memory.
      if (validation.data.fleetCommands) {
        updateFleetCommandFeatures({
          toggleChaos: validation.data.fleetCommands.enableToggleChaos,
          toggleMtd: validation.data.fleetCommands.enableToggleMtd,
        });
      }

      // In a real implementation, we would persist updates and possibly trigger restart hooks.
      // For now: acknowledge all changes, and apply runtime feature flags.
      logger.info({ updates: validation.data }, 'Hub configuration update requested');

      const { config } = await import('../../config.js');

      res.json({
        message: 'Configuration update acknowledged (feature flags applied in-memory).',
        updates: validation.data,
        config: {
          ...config,
          fleetCommands: getFleetCommandFeaturesForConfig(),
          database: {
            url: config.database.url.replace(/\/\/.*:.*@/, '//****:****@'),
          },
          telemetry: {
            ...config.telemetry,
            jwtSecret: '••••••••••••••••',
          },
          sensorBridge: {
            ...config.sensorBridge,
            apiKey: config.sensorBridge.apiKey ? '••••••••••••••••' : undefined,
          },
          clickhouse: {
            ...config.clickhouse,
            password: '••••••••••••••••',
          },
        },
      });
    } catch (error) {
      logger.error({ error }, 'Error updating hub config');
      res.status(500).json({ error: 'Failed to update hub configuration' });
    }
  });

  return router;
}
