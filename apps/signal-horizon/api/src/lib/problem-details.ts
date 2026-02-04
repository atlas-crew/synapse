import type { Response } from 'express';
import { STATUS_CODES } from 'node:http';

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  code?: string;
  hint?: string;
  context?: unknown;
  details?: unknown;
  cause?: unknown;
  retryAfterSeconds?: number;
}

export interface ProblemDetailsOptions {
  type?: string;
  title?: string;
  instance?: string;
  code?: string;
  hint?: string;
  context?: unknown;
  details?: unknown;
  cause?: unknown;
  retryAfterSeconds?: number;
}

export function buildProblemDetails(
  status: number,
  detail: string,
  options: ProblemDetailsOptions = {}
): ProblemDetails {
  const title = options.title ?? STATUS_CODES[status] ?? 'Error';

  return {
    type: options.type ?? 'about:blank',
    title,
    status,
    detail,
    instance: options.instance,
    code: options.code,
    hint: options.hint,
    context: options.context,
    details: options.details,
    cause: options.cause,
    retryAfterSeconds: options.retryAfterSeconds,
  };
}

export function sendProblem(
  res: Response,
  status: number,
  detail: string,
  options: ProblemDetailsOptions = {}
): Response {
  const problem = buildProblemDetails(status, detail, options);
  return res.status(status).type('application/problem+json').json(problem);
}
