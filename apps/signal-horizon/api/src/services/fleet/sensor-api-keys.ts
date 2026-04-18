import crypto from 'crypto';

export const ALLOWED_SENSOR_SCOPES = [
  'signal:write',
  'blocklist:read',
  'heartbeat:write',
  'config:read',
  'diag:write',
];

export function generateApiKey(): { key: string; hash: string; prefix: string } {
  const key = crypto.randomBytes(32).toString('base64url');
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  const prefix = key.substring(0, 8);
  return { key, hash, prefix };
}
