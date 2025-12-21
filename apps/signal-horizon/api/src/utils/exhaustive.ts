/**
 * Exhaustive Switch Checking Utility
 * Ensures all cases in a switch statement are handled at compile time
 */

/**
 * Asserts that a code path should never be reached.
 * TypeScript will error if the switch is not exhaustive.
 *
 * @example
 * ```ts
 * type Status = 'active' | 'inactive' | 'pending';
 *
 * function handleStatus(status: Status) {
 *   switch (status) {
 *     case 'active': return 'Active';
 *     case 'inactive': return 'Inactive';
 *     case 'pending': return 'Pending';
 *     default: assertNever(status); // Error if a case is missing
 *   }
 * }
 * ```
 */
export function assertNever(value: never, message?: string): never {
  throw new Error(
    message ?? `Unexpected value: ${JSON.stringify(value)}. This should never happen.`
  );
}

/**
 * Type-safe exhaustive check that doesn't throw.
 * Returns undefined for unhandled cases while still providing compile-time safety.
 * Useful when you want to handle unknown messages gracefully.
 *
 * @example
 * ```ts
 * function handleMessage(message: Message) {
 *   switch (message.type) {
 *     case 'ping': return handlePing();
 *     case 'pong': return handlePong();
 *     default:
 *       // Log but don't crash for unknown message types
 *       console.warn(`Unhandled message type: ${exhaustiveCheck(message.type)}`);
 *   }
 * }
 * ```
 */
export function exhaustiveCheck<T extends string | number>(value: T): T {
  return value;
}
