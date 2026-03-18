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
  sm: { fontSize: '12px', height: '36px', padding: `0 ${spacing.md}` },
  md: { fontSize: '14px', height: '44px', padding: `0 ${spacing.lg}` },
  lg: { fontSize: '16px', height: '52px', padding: `0 ${spacing.xl}` },
};

const variantStyles: Record<ButtonVariant, {
  base: React.CSSProperties;
  hover: React.CSSProperties;
}> = {
  primary: {
    base: { background: colors.blue, color: '#FFFFFF', border: 'none' },
    hover: { background: colors.hover.blueLight },
  },
  magenta: {
    base: { background: colors.magenta, color: '#FFFFFF', border: 'none' },
    hover: { background: colors.hover.magenta },
  },
  outlined: {
    base: {
      background: 'transparent',
      color: '#F0F4F8',
      border: `2px solid rgba(255,255,255,0.3)`,
    },
    hover: {
      background: colors.tint.navyMedium,
      borderColor: colors.tint.navyMedium,
      color: '#FFFFFF',
    },
  },
  secondary: {
    base: { background: colors.navy, color: '#FFFFFF', border: 'none' },
    hover: { background: colors.hover.navy },
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
