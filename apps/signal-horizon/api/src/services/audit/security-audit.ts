/**
 * Security Audit Service
 * Compliance-focused security audit logging for playbook operations
 *
 * Logs:
 * - Playbook CRUD operations (create, update, delete)
 * - Failed authorization attempts
 * - Command executions to sensors
 * - Playbook execution lifecycle (start, step execution, completion)
 *
 * All logs include:
 * - ISO 8601 timestamp
 * - User and tenant context
 * - Client IP and user agent
 * - Action type and result
 * - Resource identifiers
 */

import type { PrismaClient } from '@prisma/client';
import type { Logger } from 'pino';
import type { Request } from 'express';

// =============================================================================
// Types
// =============================================================================

/**
 * Security-relevant action types for playbook and configuration operations
 */
export type SecurityAuditAction =
  // Playbook lifecycle
  | 'PLAYBOOK_CREATED'
  | 'PLAYBOOK_UPDATED'
  | 'PLAYBOOK_DELETED'
  // Authorization
  | 'PLAYBOOK_ACCESS_DENIED'
  | 'PLAYBOOK_RUN_ACCESS_DENIED'
  // Execution
  | 'PLAYBOOK_EXECUTION_STARTED'
  | 'PLAYBOOK_EXECUTION_COMPLETED'
  | 'PLAYBOOK_EXECUTION_FAILED'
  | 'PLAYBOOK_EXECUTION_CANCELLED'
  | 'PLAYBOOK_STEP_EXECUTED'
  | 'PLAYBOOK_STEP_FAILED'
  // Command operations
  | 'PLAYBOOK_COMMAND_SENT'
  | 'PLAYBOOK_COMMAND_FAILED'
  // Configuration operations
  | 'CONFIG_CREATED'
  | 'CONFIG_UPDATED'
  | 'CONFIG_DELETED';

/**
 * Result of an audited operation
 */
export type AuditResult = 'SUCCESS' | 'FAILURE' | 'DENIED';

/**
 * Context extracted from an HTTP request for audit logging
 */
export interface RequestContext {
  ipAddress: string | null;
  userAgent: string | null;
  userId: string | null;
  tenantId: string;
  /** Unique request ID from X-Request-ID header or generated UUID */
  requestId: string | null;
}

/**
 * Base audit event structure
 */
export interface SecurityAuditEvent {
  /** ISO 8601 formatted timestamp */
  timestamp: string;
  /** User who performed the action */
  userId: string | null;
  /** Tenant context */
  tenantId: string;
  /** Client IP address */
  ipAddress: string | null;
  /** Client user agent */
  userAgent: string | null;
  /** Unique request ID for tracing */
  requestId: string | null;
  /** Type of action performed */
  action: SecurityAuditAction;
  /** Result of the action */
  result: AuditResult;
  /** Primary resource identifier (playbook ID, run ID, etc.) */
  resourceId: string | null;
  /** Secondary resource identifier (war room ID, step ID, etc.) */
  secondaryResourceId?: string | null;
  /** Additional context-specific details */
  details?: Record<string, unknown>;
}

/**
 * Input for logging a security audit event
 */
export interface LogAuditEventInput {
  action: SecurityAuditAction;
  result: AuditResult;
  resourceId: string | null;
  secondaryResourceId?: string | null;
  details?: Record<string, unknown>;
}

// =============================================================================
// Security Audit Service
// =============================================================================

export class SecurityAuditService {
  private prisma: PrismaClient;
  private logger: Logger;

  constructor(prisma: PrismaClient, logger: Logger) {
    this.prisma = prisma;
    this.logger = logger.child({ service: 'security-audit' });
  }

  /**
   * Extract request context from an Express request
   */
  extractRequestContext(req: Request): RequestContext {
    const auth = req.auth;
    return {
      ipAddress: this.extractIpAddress(req),
      userAgent: this.extractUserAgent(req),
      userId: auth?.userId ?? null,
      tenantId: auth?.tenantId ?? 'unknown',
      requestId: req.id ?? null,
    };
  }

  /**
   * Extract client IP address from request
   * Handles X-Forwarded-For and other proxy headers
   */
  private extractIpAddress(req: Request): string | null {
    // Check for forwarded headers (load balancer/proxy)
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
      const firstIp = Array.isArray(forwarded)
        ? forwarded[0]
        : forwarded.split(',')[0];
      return firstIp?.trim() ?? null;
    }

    // Check X-Real-IP header
    const realIp = req.headers['x-real-ip'];
    if (realIp) {
      return Array.isArray(realIp) ? realIp[0] : realIp;
    }

    // Fall back to req.ip
    return req.ip ?? null;
  }

  /**
   * Extract user agent from request headers
   */
  private extractUserAgent(req: Request): string | null {
    const userAgent = req.headers['user-agent'];
    if (!userAgent) return null;
    // Truncate long user agents to prevent storage bloat
    return userAgent.substring(0, 500);
  }

  /**
   * Log a security audit event to the database
   * Writes to both the legacy AuditLog and the new SecurityAuditLog tables
   */
  async logEvent(
    context: RequestContext,
    input: LogAuditEventInput
  ): Promise<void> {
    const event: SecurityAuditEvent = {
      timestamp: new Date().toISOString(),
      userId: context.userId,
      tenantId: context.tenantId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      requestId: context.requestId,
      action: input.action,
      result: input.result,
      resourceId: input.resourceId,
      secondaryResourceId: input.secondaryResourceId,
      details: input.details,
    };

    // Determine resource type from action
    const resourceType = this.getResourceType(input.action);

    try {
      // Write to legacy AuditLog table
      // Note: SecurityAuditLog table will be available after migration
      await this.prisma.auditLog.create({
        data: {
          tenantId: context.tenantId,
          userId: context.userId,
          action: input.action,
          resource: resourceType,
          resourceId: input.resourceId,
          details: JSON.parse(JSON.stringify(event)),
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
        },
      });

      // Try to write to SecurityAuditLog if the table exists (post-migration)
      try {
        const securityAuditLog = (this.prisma as unknown as {
          securityAuditLog?: { create: (args: unknown) => Promise<unknown> };
        }).securityAuditLog;

        if (securityAuditLog) {
          await securityAuditLog.create({
            data: {
              action: input.action,
              resourceType,
              resourceId: input.resourceId ?? '',
              userId: context.userId ?? 'anonymous',
              tenantId: context.tenantId,
              ipAddress: context.ipAddress,
              userAgent: context.userAgent,
              result: input.result,
              details: input.details ? JSON.stringify(input.details) : null,
            },
          });
        }
      } catch {
        // SecurityAuditLog table may not exist yet - this is expected pre-migration
      }

      // Also log to structured logger for real-time monitoring
      this.logger.info(
        {
          audit: true,
          action: input.action,
          result: input.result,
          resourceId: input.resourceId,
          resourceType,
          tenantId: context.tenantId,
          userId: context.userId,
          ipAddress: context.ipAddress,
          requestId: context.requestId,
        },
        `Security audit: ${input.action} - ${input.result}`
      );
    } catch (error) {
      // Log error but don't fail the operation
      this.logger.error(
        { error, event },
        'Failed to write security audit log'
      );
    }
  }

  /**
   * Determine the resource type from the audit action
   */
  private getResourceType(action: SecurityAuditAction): string {
    if (action.startsWith('PLAYBOOK_EXECUTION') || action.startsWith('PLAYBOOK_STEP') || action.startsWith('PLAYBOOK_RUN')) {
      return 'playbook_run';
    }
    if (action.startsWith('PLAYBOOK_COMMAND')) {
      return 'sensor_command';
    }
    if (action.startsWith('CONFIG_')) {
      return 'configuration';
    }
    return 'playbook';
  }

  // ===========================================================================
  // Convenience Methods for Playbook Operations
  // ===========================================================================

  /**
   * Log playbook creation
   */
  async logPlaybookCreated(
    req: Request,
    playbookId: string,
    playbookName: string
  ): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_CREATED',
      result: 'SUCCESS',
      resourceId: playbookId,
      details: { playbookName },
    });
  }

  /**
   * Log playbook update
   */
  async logPlaybookUpdated(
    req: Request,
    playbookId: string,
    changes: Record<string, unknown>
  ): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_UPDATED',
      result: 'SUCCESS',
      resourceId: playbookId,
      details: { changes },
    });
  }

  /**
   * Log playbook deletion (soft delete)
   */
  async logPlaybookDeleted(req: Request, playbookId: string): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_DELETED',
      result: 'SUCCESS',
      resourceId: playbookId,
    });
  }

  /**
   * Log unauthorized access attempt to a playbook
   */
  async logPlaybookAccessDenied(
    req: Request,
    playbookId: string,
    attemptedAction: string
  ): Promise<void> {
    const context = this.extractRequestContext(req);
    await this.logEvent(context, {
      action: 'PLAYBOOK_ACCESS_DENIED',
      result: 'DENIED',
      resourceId: playbookId,
      details: { attemptedAction, attemptedTenantId: context.tenantId },
    });
  }

  /**
   * Log unauthorized access attempt to a playbook run
   */
  async logPlaybookRunAccessDenied(
    req: Request,
    runId: string,
    attemptedAction: string
  ): Promise<void> {
    const context = this.extractRequestContext(req);
    await this.logEvent(context, {
      action: 'PLAYBOOK_RUN_ACCESS_DENIED',
      result: 'DENIED',
      resourceId: runId,
      details: { attemptedAction, attemptedTenantId: context.tenantId },
    });
  }

  /**
   * Log playbook execution started
   */
  async logPlaybookExecutionStarted(
    req: Request,
    runId: string,
    playbookId: string,
    warRoomId: string
  ): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_EXECUTION_STARTED',
      result: 'SUCCESS',
      resourceId: runId,
      secondaryResourceId: warRoomId,
      details: { playbookId, warRoomId },
    });
  }

  /**
   * Log playbook execution completed
   */
  async logPlaybookExecutionCompleted(
    context: RequestContext,
    runId: string,
    playbookId: string
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_EXECUTION_COMPLETED',
      result: 'SUCCESS',
      resourceId: runId,
      details: { playbookId },
    });
  }

  /**
   * Log playbook execution failed
   */
  async logPlaybookExecutionFailed(
    context: RequestContext,
    runId: string,
    playbookId: string,
    error: string
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_EXECUTION_FAILED',
      result: 'FAILURE',
      resourceId: runId,
      details: { playbookId, error },
    });
  }

  /**
   * Log playbook execution cancelled
   */
  async logPlaybookExecutionCancelled(
    req: Request,
    runId: string,
    playbookId: string
  ): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_EXECUTION_CANCELLED',
      result: 'SUCCESS',
      resourceId: runId,
      details: { playbookId },
    });
  }

  /**
   * Log playbook run cancelled (simplified version without playbookId)
   */
  async logPlaybookRunCancelled(req: Request, runId: string): Promise<void> {
    await this.logEvent(this.extractRequestContext(req), {
      action: 'PLAYBOOK_EXECUTION_CANCELLED',
      result: 'SUCCESS',
      resourceId: runId,
    });
  }

  /**
   * Log playbook step executed
   */
  async logPlaybookStepExecuted(
    context: RequestContext,
    runId: string,
    stepId: string,
    stepIndex: number,
    stepType: string
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_STEP_EXECUTED',
      result: 'SUCCESS',
      resourceId: runId,
      secondaryResourceId: stepId,
      details: { stepIndex, stepType },
    });
  }

  /**
   * Log playbook step failed
   */
  async logPlaybookStepFailed(
    context: RequestContext,
    runId: string,
    stepId: string,
    stepIndex: number,
    error: string
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_STEP_FAILED',
      result: 'FAILURE',
      resourceId: runId,
      secondaryResourceId: stepId,
      details: { stepIndex, error },
    });
  }

  /**
   * Log command sent to sensors
   */
  async logCommandSent(
    context: RequestContext,
    runId: string,
    commandType: string,
    targetType: string,
    targetCount: number
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_COMMAND_SENT',
      result: 'SUCCESS',
      resourceId: runId,
      details: { commandType, targetType, targetCount },
    });
  }

  /**
   * Log command failed
   */
  async logCommandFailed(
    context: RequestContext,
    runId: string,
    commandType: string,
    error: string
  ): Promise<void> {
    await this.logEvent(context, {
      action: 'PLAYBOOK_COMMAND_FAILED',
      result: 'FAILURE',
      resourceId: runId,
      details: { commandType, error },
    });
  }

  // ===========================================================================
  // Configuration Audit Methods
  // ===========================================================================

  /**
   * Sensitive field patterns that should be redacted in audit logs
   */
  private static readonly SENSITIVE_PATTERNS = [
    /password/i,
    /secret/i,
    /token/i,
    /api[_-]?key/i,
    /auth/i,
    /credential/i,
    /private[_-]?key/i,
    /access[_-]?key/i,
    /bearer/i,
    /jwt/i,
    /encryption/i,
  ];

  /**
   * Redact sensitive values from a configuration object
   * Returns a deep copy with sensitive fields replaced by '[REDACTED]'
   */
  redactSensitiveValues<T extends Record<string, unknown>>(
    obj: T
  ): Record<string, unknown> {
    const redacted: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      const isSensitive = SecurityAuditService.SENSITIVE_PATTERNS.some(
        (pattern) => pattern.test(key)
      );

      if (isSensitive) {
        redacted[key] = '[REDACTED]';
      } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        redacted[key] = this.redactSensitiveValues(value as Record<string, unknown>);
      } else if (Array.isArray(value)) {
        redacted[key] = value.map((item) =>
          item !== null && typeof item === 'object'
            ? this.redactSensitiveValues(item as Record<string, unknown>)
            : item
        );
      } else {
        redacted[key] = value;
      }
    }

    return redacted;
  }

  /**
   * Compute a diff between two configuration objects, showing only changed fields
   * Both values are redacted for sensitive fields
   */
  computeConfigDiff(
    previousConfig: Record<string, unknown>,
    newConfig: Record<string, unknown>
  ): { field: string; previousValue: unknown; newValue: unknown }[] {
    const changes: { field: string; previousValue: unknown; newValue: unknown }[] = [];
    const allKeys = new Set([...Object.keys(previousConfig), ...Object.keys(newConfig)]);

    for (const key of allKeys) {
      const prev = previousConfig[key];
      const curr = newConfig[key];

      // Simple deep equality check
      if (JSON.stringify(prev) !== JSON.stringify(curr)) {
        const isSensitive = SecurityAuditService.SENSITIVE_PATTERNS.some(
          (pattern) => pattern.test(key)
        );

        changes.push({
          field: key,
          previousValue: isSensitive ? '[REDACTED]' : prev,
          newValue: isSensitive ? '[REDACTED]' : curr,
        });
      }
    }

    return changes;
  }

  /**
   * Log configuration creation
   */
  async logConfigCreated(
    req: Request,
    resourceType: string,
    resourceId: string,
    configValues: Record<string, unknown>
  ): Promise<void> {
    const redactedValues = this.redactSensitiveValues(configValues);
    await this.logEvent(this.extractRequestContext(req), {
      action: 'CONFIG_CREATED',
      result: 'SUCCESS',
      resourceId,
      details: {
        resourceType,
        newValues: redactedValues,
      },
    });
  }

  /**
   * Log configuration update with previous and new values
   */
  async logConfigUpdated(
    req: Request,
    resourceType: string,
    resourceId: string,
    previousValues: Record<string, unknown>,
    newValues: Record<string, unknown>
  ): Promise<void> {
    const changes = this.computeConfigDiff(previousValues, newValues);
    await this.logEvent(this.extractRequestContext(req), {
      action: 'CONFIG_UPDATED',
      result: 'SUCCESS',
      resourceId,
      details: {
        resourceType,
        changes,
        changeCount: changes.length,
      },
    });
  }

  /**
   * Log configuration deletion
   */
  async logConfigDeleted(
    req: Request,
    resourceType: string,
    resourceId: string,
    previousValues?: Record<string, unknown>
  ): Promise<void> {
    const redactedValues = previousValues
      ? this.redactSensitiveValues(previousValues)
      : undefined;
    await this.logEvent(this.extractRequestContext(req), {
      action: 'CONFIG_DELETED',
      result: 'SUCCESS',
      resourceId,
      details: {
        resourceType,
        ...(redactedValues && { previousValues: redactedValues }),
      },
    });
  }
}
