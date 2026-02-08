import { memo } from 'react';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

interface MethodBadgeProps {
  method: HttpMethod;
  className?: string;
}

const methodStyles: Record<HttpMethod, string> = {
  GET: 'bg-method-get/10 text-method-get border-method-get/30',
  POST: 'bg-method-post/10 text-method-post border-method-post/30',
  PUT: 'bg-method-put/10 text-method-put border-method-put/30',
  PATCH: 'bg-method-patch/10 text-method-patch border-method-patch/30',
  DELETE: 'bg-method-delete/10 text-method-delete border-method-delete/30',
  HEAD: 'bg-surface-subtle text-ink-muted border-border-subtle',
  OPTIONS: 'bg-surface-subtle text-ink-muted border-border-subtle',
};

/**
 * MethodBadge - Colored badge for HTTP methods.
 * GET=green, POST=blue, PUT=yellow, PATCH=purple, DELETE=red.
 */
export const MethodBadge = memo(function MethodBadge({
  method,
  className = '',
}: MethodBadgeProps) {
  return (
    <span
      className={`
        inline-flex items-center px-2 py-0.5 text-xs font-semibold uppercase border
        ${methodStyles[method]}
        ${className}
      `}
    >
      {method}
    </span>
  );
});

export default MethodBadge;
