export type FleetPartialStatus = 'ok' | 'error';

export interface FleetPartialResultEntry<T> {
  sensorId: string;
  status: FleetPartialStatus;
  data?: T;
  error?: string;
}

export interface FleetPartialSummary {
  succeeded: number;
  failed: number;
}

export interface FleetPartialError {
  code: string;
  message: string;
}

export interface FleetPartialResult<T> {
  results: FleetPartialResultEntry<T>[];
  summary: FleetPartialSummary;
  error?: FleetPartialError;
}

export interface FleetPartialAggregateResult<TItem, TAggregate>
  extends FleetPartialResult<TItem> {
  aggregate: TAggregate;
}

export function createFleetPartialResult<T>(
  results: FleetPartialResultEntry<T>[]
): FleetPartialResult<T> {
  return {
    results,
    summary: {
      succeeded: results.filter((result) => result.status === 'ok').length,
      failed: results.filter((result) => result.status === 'error').length,
    },
  };
}

export function createFleetPartialAggregateResult<TItem, TAggregate>(
  results: FleetPartialResultEntry<TItem>[],
  aggregate: TAggregate
): FleetPartialAggregateResult<TItem, TAggregate> {
  return {
    ...createFleetPartialResult(results),
    aggregate,
  };
}

export function withFleetPartialError<T extends FleetPartialResult<unknown>>(
  result: T,
  error: FleetPartialError
): T {
  return {
    ...result,
    error,
  };
}
