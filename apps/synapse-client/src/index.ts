/**
 * Synapse Client
 * TypeScript client and CLI for the Synapse (risk-server) API
 *
 * @example
 * ```typescript
 * import { SynapseClient } from 'synapse-client';
 *
 * const client = new SynapseClient({ baseUrl: 'http://localhost:3000' });
 * const status = await client.getStatus();
 * console.log(status.totalRequests);
 * ```
 */

export * from './types.js';
export * from './client.js';
