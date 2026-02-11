import React, { useCallback, useEffect, useId, useRef } from 'react';
import { colors, fontFamily, fontWeight, spacing, shadows, transitions } from '../tokens/tokens';

/**
 * Modal — Centered overlay dialog.
 * Drawer — Slide-in panel from left or right edge.
 */

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  titleId?: string;
  size?: 'sm' | 'md' | 'lg' | 'xl' | string;
  persistent?: boolean;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

const sizeWidths: Record<string, string> = {
  sm: '400px',
  md: '560px',
  lg: '720px',
  xl: '960px',
};

export const Modal: React.FC<ModalProps> & { Footer: React.FC<{ children: React.ReactNode }> } = ({
  open,
  onClose,
  title,
  titleId,
  size = 'md',
  persistent,
  children,
  style,
}) => {
  const dialogRef = useRef<HTMLDivElement>(null);
  const generatedTitleId = useId();
  const resolvedTitleId = titleId ?? generatedTitleId;

  const getFocusableElements = useCallback((): HTMLElement[] => {
    if (!dialogRef.current) return [];
    const selector =
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';
    return Array.from(dialogRef.current.querySelectorAll<HTMLElement>(selector)).filter(
      (element) => !element.hasAttribute('disabled') && !element.getAttribute('aria-hidden'),
    );
  }, []);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !persistent) onClose();
      if (e.key !== 'Tab') return;

      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) {
        e.preventDefault();
        dialogRef.current?.focus();
        return;
      }

      const first = focusableElements[0];
      const last = focusableElements[focusableElements.length - 1];
      const active = document.activeElement as HTMLElement | null;

      if (e.shiftKey) {
        if (!active || active === first || !dialogRef.current?.contains(active)) {
          e.preventDefault();
          last.focus();
        }
        return;
      }

      if (!active || active === last || !dialogRef.current?.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    },
    [getFocusableElements, onClose, persistent],
  );

  useEffect(() => {
    if (!open) return;

    const previousActiveElement = document.activeElement as HTMLElement | null;

    document.addEventListener('keydown', handleKeyDown);
    document.body.style.overflow = 'hidden';

    const raf = requestAnimationFrame(() => {
      const focusableElements = getFocusableElements();
      if (focusableElements.length > 0) {
        focusableElements[0].focus();
        return;
      }
      dialogRef.current?.focus();
    });

    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
      previousActiveElement?.focus();
    };
  }, [getFocusableElements, handleKeyDown, open]);

  if (!open) return null;

  const width = sizeWidths[size] || size;

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.6)',
        backdropFilter: 'blur(4px)',
        animation: 'sh-fade-in 0.2s ease',
      }}
      onClick={persistent ? undefined : onClose}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? resolvedTitleId : undefined}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          background: colors.card.dark,
          border: '1px solid rgba(255,255,255,0.08)',
          borderRadius: 0,
          boxShadow: shadows.elevated.dark,
          width,
          maxWidth: '90vw',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          animation: 'sh-fade-in 0.2s ease',
          ...style,
        }}
      >
        {title && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: `${spacing.md} ${spacing.lg}`,
              borderBottom: '1px solid rgba(255,255,255,0.08)',
              flexShrink: 0,
            }}
          >
            <h2
              id={resolvedTitleId}
              style={{
                fontFamily,
                fontWeight: fontWeight.light,
                fontSize: '1.25rem',
                color: '#F0F4F8',
                margin: 0,
              }}
            >
              {title}
            </h2>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: 'none',
                border: 'none',
                color: colors.gray.mid,
                cursor: 'pointer',
                fontSize: '20px',
                padding: spacing.xs,
                lineHeight: 1,
                transition: `color ${transitions.fast}`,
              }}
              onMouseEnter={(e) => ((e.target as HTMLElement).style.color = '#F0F4F8')}
              onMouseLeave={(e) => ((e.target as HTMLElement).style.color = colors.gray.mid)}
              aria-label="Close"
            >
              ×
            </button>
          </div>
        )}
        <div
          style={{
            padding: spacing.lg,
            overflow: 'auto',
            flex: 1,
            fontFamily,
            fontSize: '14px',
            color: '#F0F4F8',
            lineHeight: '20px',
          }}
        >
          {children}
        </div>
      </div>
    </div>
  );
};

Modal.Footer = ({ children }) => (
  <div
    style={{
      display: 'flex',
      justifyContent: 'flex-end',
      gap: spacing.sm,
      padding: `${spacing.md} 0 0 0`,
      marginTop: spacing.md,
      borderTop: '1px solid rgba(255,255,255,0.08)',
    }}
  >
    {children}
  </div>
);

Modal.displayName = 'Modal';
Modal.Footer.displayName = 'Modal.Footer';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  position?: 'left' | 'right';
  width?: string;
  overlay?: boolean;
  children: React.ReactNode;
  style?: React.CSSProperties;
}

export const Drawer: React.FC<DrawerProps> = ({
  open,
  onClose,
  title,
  position = 'right',
  width = '400px',
  overlay = true,
  children,
  style,
}) => {
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (open) document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [open, onClose]);

  return (
    <>
      {overlay && open && (
        <div
          onClick={onClose}
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 999,
            background: 'rgba(0, 0, 0, 0.4)',
            animation: 'sh-fade-in 0.2s ease',
          }}
        />
      )}
      <div
        style={{
          position: 'fixed',
          top: 0,
          bottom: 0,
          [position]: 0,
          width,
          maxWidth: '90vw',
          zIndex: 1000,
          background: colors.card.dark,
          borderLeft: position === 'right' ? '1px solid rgba(255,255,255,0.08)' : undefined,
          borderRight: position === 'left' ? '1px solid rgba(255,255,255,0.08)' : undefined,
          boxShadow: shadows.elevated.dark,
          borderRadius: 0,
          display: 'flex',
          flexDirection: 'column',
          transform: open ? 'translateX(0)' : `translateX(${position === 'right' ? '100%' : '-100%'})`,
          transition: `transform 0.25s ease`,
          ...style,
        }}
      >
        {title && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: `${spacing.md} ${spacing.lg}`,
              borderBottom: '1px solid rgba(255,255,255,0.08)',
              flexShrink: 0,
            }}
          >
            <span style={{ fontFamily, fontWeight: fontWeight.light, fontSize: '1.25rem', color: '#F0F4F8' }}>
              {title}
            </span>
            <button
              onClick={onClose}
              style={{
                background: 'none',
                border: 'none',
                color: colors.gray.mid,
                cursor: 'pointer',
                fontSize: '20px',
                padding: spacing.xs,
                lineHeight: 1,
              }}
              aria-label="Close"
            >
              ×
            </button>
          </div>
        )}
        <div
          style={{
            padding: spacing.lg,
            overflow: 'auto',
            flex: 1,
            fontFamily,
            fontSize: '14px',
            color: '#F0F4F8',
          }}
        >
          {children}
        </div>
      </div>
    </>
  );
};

Drawer.displayName = 'Drawer';
