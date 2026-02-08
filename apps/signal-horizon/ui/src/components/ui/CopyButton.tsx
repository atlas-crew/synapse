import { useState, useCallback } from 'react';
import { Copy, Check } from 'lucide-react';
import { clsx } from 'clsx';

interface CopyButtonProps {
  value: string;
  className?: string;
  size?: 'sm' | 'md';
}

export function CopyButton({ value, className, size = 'md' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      // Clipboard access denied (non-HTTPS, permission denied, etc.)
    });
  }, [value]);

  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        handleCopy();
      }}
      className={clsx(
        'transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50',
        copied ? 'text-ac-green' : 'text-ink-muted hover:text-ink-primary',
        className
      )}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
      aria-label={copied ? 'Copied!' : 'Copy to clipboard'}
    >
      {copied ? (
        <Check className={clsx(size === 'sm' ? 'w-3 h-3' : 'w-4 h-4')} />
      ) : (
        <Copy className={clsx(size === 'sm' ? 'w-3 h-3' : 'w-4 h-4')} />
      )}
    </button>
  );
}
