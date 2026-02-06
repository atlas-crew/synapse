/**
 * Synapse Client
 * TypeScript client and CLI for the Synapse (risk-server) API
 *
 * This package re-exports from synapse-api for backward compatibility.
 * For new projects, consider importing directly from synapse-api.
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

// Re-export everything from the standalone package
export * from 'synapse-api';
