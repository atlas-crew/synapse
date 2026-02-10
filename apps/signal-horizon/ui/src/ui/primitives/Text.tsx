import React from 'react';
import { fontFamily, typography, colors } from '../tokens/tokens';
import { sx } from '../utils/helpers';

/**
 * Text — Typography primitive. Applies brand fonts and sizing automatically.
 *
 * Usage:
 *   <Text variant="h2">Dashboard</Text>
 *   <Text variant="body" muted>Secondary info</Text>
 *   <Text variant="eyebrow" color={colors.magenta}>STATUS</Text>
 *   <Text variant="kpiValue" color={colors.green}>17μs</Text>
 */

type TextVariant = keyof typeof typography;

interface TextProps extends React.HTMLAttributes<HTMLElement> {
  variant?: TextVariant;
  color?: string;
  muted?: boolean;
  as?: keyof JSX.IntrinsicElements;
  truncate?: boolean;
  align?: React.CSSProperties['textAlign'];
  maxWidth?: string;
  noMargin?: boolean;
  inline?: boolean;
  mono?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

const variantToTag: Partial<Record<TextVariant, keyof JSX.IntrinsicElements>> = {
  h1: 'h1', h2: 'h2', h3: 'h3', h4: 'h4', h5: 'h5', h6: 'h6',
  eyebrow: 'span', body: 'p', subhead: 'p', small: 'span', caption: 'span',
};

export const Text: React.FC<TextProps> = ({
  variant = 'body', color, muted, as, truncate, align, maxWidth,
  noMargin, inline, mono, style, children, ...rest
}) => {
  const variantStyles = typography[variant] || typography.body;
  const Tag = (as || variantToTag[variant] || 'span') as any;

  const resolvedColor = muted
    ? colors.gray.mid
    : color || (variant === 'chartSubtitle' || variant === 'chartLabel' || variant === 'chartLegend'
        ? colors.gray.mid
        : '#F0F4F8');

  const baseStyle = sx(
    {
      fontFamily: mono ? "'JetBrains Mono', 'Fira Code', monospace" : fontFamily,
      margin: noMargin ? 0 : undefined,
      color: resolvedColor,
      borderRadius: 0,
    },
    variantStyles as React.CSSProperties,
    truncate ? { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const } : undefined,
    align ? { textAlign: align } : undefined,
    maxWidth ? { maxWidth } : undefined,
    inline ? { display: 'inline' } : undefined,
    style,
  );

  return <Tag style={baseStyle} {...rest}>{children}</Tag>;
};

Text.displayName = 'Text';
