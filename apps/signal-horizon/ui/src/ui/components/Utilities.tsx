import React, { useState, useRef, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { colors, fontFamily, fontWeight, spacing, shadows, transitions } from '../tokens/tokens';

/**
 * Tooltip, ProgressBar, EmptyState, Spinner, LoadingOverlay, Breadcrumb
 */

interface TooltipProps {
  content: React.ReactNode;
  position?: 'top' | 'bottom' | 'left' | 'right';
  delay?: number;
  children: React.ReactNode;
}

export const Tooltip: React.FC<TooltipProps> = ({ content, position = 'top', delay = 200, children }) => {
  const [visible, setVisible] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const show = () => { timeoutRef.current = setTimeout(() => setVisible(true), delay); };
  const hide = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
    setVisible(false);
  };
  useEffect(() => () => { if (timeoutRef.current) clearTimeout(timeoutRef.current); }, []);

  const positionStyles: Record<string, React.CSSProperties> = {
    top: { bottom: '100%', left: '50%', transform: 'translateX(-50%)', marginBottom: '6px' },
    bottom: { top: '100%', left: '50%', transform: 'translateX(-50%)', marginTop: '6px' },
    left: { right: '100%', top: '50%', transform: 'translateY(-50%)', marginRight: '6px' },
    right: { left: '100%', top: '50%', transform: 'translateY(-50%)', marginLeft: '6px' },
  };

  return (
    <span style={{ position: 'relative', display: 'inline-flex' }} onMouseEnter={show} onMouseLeave={hide}>
      {children}
      {visible && (
        <div style={{
          position: 'absolute', ...positionStyles[position],
          background: '#001E62', border: '1px solid rgba(255,255,255,0.12)',
          borderRadius: 0, boxShadow: shadows.elevated.dark,
          padding: `${spacing.xs} ${spacing.sm}`, fontFamily,
          fontWeight: fontWeight.regular, fontSize: '12px', color: '#F0F4F8',
          whiteSpace: 'nowrap', zIndex: 100, pointerEvents: 'none',
          animation: 'sh-fade-in 0.15s ease',
        }}>
          {content}
        </div>
      )}
    </span>
  );
};
Tooltip.displayName = 'Tooltip';

interface ProgressBarProps {
  value: number;
  max?: number;
  color?: string;
  trackColor?: string;
  size?: 'sm' | 'md' | 'lg';
  label?: string;
  showValue?: boolean;
  formatValue?: (value: number, max: number) => string;
  style?: React.CSSProperties;
}

const barSizes = { sm: '4px', md: '8px', lg: '12px' };

export const ProgressBar: React.FC<ProgressBarProps> = ({
  value, max = 100, color = colors.blue, trackColor = 'rgba(255,255,255,0.08)',
  size = 'md', label, showValue, formatValue: fmt, style,
}) => {
  const percent = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div style={{ width: '100%', ...style }}>
      {(label || showValue) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: spacing.xs, fontFamily, fontSize: '12px' }}>
          {label && <span style={{ color: '#F0F4F8', fontWeight: fontWeight.medium }}>{label}</span>}
          {showValue && <span style={{ color: colors.gray.mid }}>{fmt ? fmt(value, max) : `${value}/${max}`}</span>}
        </div>
      )}
      <div style={{ width: '100%', height: barSizes[size], background: trackColor, borderRadius: 0, overflow: 'hidden' }}>
        <div style={{ width: `${percent}%`, height: '100%', background: color, borderRadius: 0, transition: `width ${transitions.normal}` }} />
      </div>
    </div>
  );
};
ProgressBar.displayName = 'ProgressBar';

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  style?: React.CSSProperties;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ icon, title, description, action, style }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: spacing['2xl'], textAlign: 'center', ...style }}>
    {icon && <div style={{ fontSize: '48px', color: colors.gray.mid, marginBottom: spacing.md, opacity: 0.5 }}>{icon}</div>}
    <div style={{ fontFamily, fontWeight: fontWeight.light, fontSize: '1.25rem', color: '#F0F4F8', marginBottom: spacing.xs }}>{title}</div>
    {description && <div style={{ fontFamily, fontWeight: fontWeight.regular, fontSize: '14px', color: colors.gray.mid, maxWidth: '400px', lineHeight: '20px', marginBottom: action ? spacing.lg : 0 }}>{description}</div>}
    {action}
  </div>
);
EmptyState.displayName = 'EmptyState';

interface SpinnerProps { size?: number; color?: string; style?: React.CSSProperties; }
export const Spinner: React.FC<SpinnerProps> = ({ size = 20, color = colors.blue, style }) => (
  <div style={{ width: size, height: size, border: `2px solid rgba(255,255,255,0.1)`, borderTopColor: color, borderRadius: '50%', animation: 'sh-spin 0.8s linear infinite', ...style }} />
);
Spinner.displayName = 'Spinner';

interface LoadingOverlayProps { message?: string; style?: React.CSSProperties; }
export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({ message = 'Loading...', style }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: spacing['2xl'], gap: spacing.md, ...style }}>
    <Spinner size={28} />
    <span style={{ fontFamily, fontSize: '14px', color: colors.gray.mid }}>{message}</span>
  </div>
);
LoadingOverlay.displayName = 'LoadingOverlay';

interface BreadcrumbItem { label: string; to?: string; onClick?: () => void; }
interface BreadcrumbProps { items: BreadcrumbItem[]; separator?: string; style?: React.CSSProperties; }

export const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, separator = '/', style }) => (
  <nav aria-label="Breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: spacing.sm, fontFamily, fontSize: '13px', ...style }}>
    {items.map((item, i) => (
      <React.Fragment key={i}>
        {i > 0 && <span style={{ color: 'rgba(255,255,255,0.2)' }}>{separator}</span>}
        {item.to ? (
          <Link
            to={item.to}
            style={{ color: colors.skyBlue, cursor: 'pointer', fontWeight: fontWeight.regular, transition: `color ${transitions.fast}`, textDecoration: 'none' }}
            onMouseEnter={(e) => ((e.target as HTMLElement).style.color = colors.hover.linkDark)}
            onMouseLeave={(e) => ((e.target as HTMLElement).style.color = colors.skyBlue)}
          >
            {item.label}
          </Link>
        ) : item.onClick ? (
          <span
            onClick={item.onClick}
            style={{ color: colors.skyBlue, cursor: 'pointer', fontWeight: fontWeight.regular, transition: `color ${transitions.fast}` }}
            onMouseEnter={(e) => ((e.target as HTMLElement).style.color = colors.hover.linkDark)}
            onMouseLeave={(e) => ((e.target as HTMLElement).style.color = colors.skyBlue)}
          >
            {item.label}
          </span>
        ) : (
          <span aria-current={i === items.length - 1 ? 'page' : undefined} style={{ color: '#F0F4F8', fontWeight: fontWeight.medium }}>
            {item.label}
          </span>
        )}
      </React.Fragment>
    ))}
  </nav>
);
Breadcrumb.displayName = 'Breadcrumb';
