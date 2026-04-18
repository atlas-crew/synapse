import React from 'react';
import { colors, fontFamily, fontWeight, spacing, transitions } from '../tokens/tokens';

/**
 * Button — Brand-compliant button with all variants.
 *
 * Usage:
 *   <Button>Primary Action</Button>
 *   <Button variant="magenta">Deploy</Button>
 *   <Button variant="outlined" size="sm">Filter</Button>
 *   <Button variant="secondary" size="sm">Cancel</Button>
 *   <Button variant="ghost">More</Button>
 */

type ButtonVariant = 'primary' | 'magenta' | 'outlined' | 'secondary' | 'ghost';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Full width */
  fill?: boolean;
  /** Alias for fill */
  fullWidth?: boolean;
  /** Loading state */
  loading?: boolean;
  /** Icon before text */
  icon?: React.ReactNode;
  /** Icon after text */
  iconAfter?: React.ReactNode;
}

const sizeMap: Record<ButtonSize, React.CSSProperties> = {
  sm: { fontSize: '12px', padding: `${spacing.sm}px ${spacing.md}px` },
  md: { fontSize: '14px', padding: `${spacing.sm + 2}px ${spacing.lg}px` },
  lg: { fontSize: '16px', padding: `${spacing.md - 2}px ${spacing.xl}px` },
};

const variantStyles: Record<ButtonVariant, {
  base: React.CSSProperties;
  hover: React.CSSProperties;
}> = {
  primary: {
    base: {
      background: colors.blue,
      color: '#FFFFFF',
      border: 'none',
      boxShadow: '0 1px 3px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.15)',
    },
    hover: {
      background: colors.hover.blueLight,
      boxShadow: '0 2px 6px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.2)',
    },
  },
  magenta: {
    base: {
      background: colors.magenta,
      color: '#FFFFFF',
      border: 'none',
      boxShadow: '0 1px 3px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.15)',
    },
    hover: {
      background: colors.hover.magenta,
      boxShadow: '0 2px 6px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.2)',
    },
  },
  outlined: {
    base: {
      background: 'transparent',
      color: '#F0F4F8',
      border: '1px solid rgba(255,255,255,0.2)',
      boxShadow: '0 1px 2px rgba(0,0,0,0.2)',
    },
    hover: {
      background: 'rgba(255,255,255,0.06)',
      borderColor: 'rgba(255,255,255,0.35)',
      color: '#FFFFFF',
      boxShadow: '0 2px 4px rgba(0,0,0,0.3)',
    },
  },
  secondary: {
    base: {
      background: colors.navy,
      color: '#FFFFFF',
      border: 'none',
      boxShadow: '0 1px 3px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.1)',
    },
    hover: {
      background: colors.hover.navy,
      boxShadow: '0 2px 6px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.15)',
    },
  },
  ghost: {
    base: { background: 'transparent', color: colors.blue, border: 'none' },
    hover: { background: 'rgba(255,255,255,0.06)' },
  },
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  fill,
  fullWidth,
  loading,
  icon,
  iconAfter,
  disabled,
  children,
  style,
  ...rest
}) => {
  const [hovered, setHovered] = React.useState(false);
  const vs = variantStyles[variant];
  const isFullWidth = fill || fullWidth;

  return (
    <button
      disabled={disabled || loading}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        fontFamily,
        fontWeight: fontWeight.medium,
        borderRadius: 0,
        cursor: disabled || loading ? 'not-allowed' : 'pointer',
        transition: `all ${transitions.fast}`,
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: spacing.sm,
        width: isFullWidth ? '100%' : undefined,
        opacity: disabled ? 0.5 : 1,
        ...sizeMap[size],
        ...vs.base,
        ...(hovered && !disabled ? vs.hover : {}),
        ...style,
      }}
      {...rest}
    >
      {loading ? (
        <span style={{ opacity: 0.7 }}>Loading…</span>
      ) : (
        <>
          {icon}
          {children}
          {iconAfter}
        </>
      )}
    </button>
  );
};

Button.displayName = 'Button';

