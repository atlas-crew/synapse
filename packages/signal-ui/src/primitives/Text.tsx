import React from 'react';
import { fontFamily, typography, colors, fontWeight } from '../tokens/tokens';
import { sx } from '../utils/helpers';

/**
 * Text — Typography primitive. Applies brand fonts and sizing automatically.
 *
 * Usage:
 *   <Text variant="display">Dashboard</Text>
 *   <Text variant="body" muted>Secondary info</Text>
 *   <Text variant="tag" color={colors.red}>CRITICAL</Text>
 *   <Text variant="metric">2,847</Text>
 */

export type TextVariant = keyof typeof typography;

interface TextProps extends React.HTMLAttributes<HTMLElement> {
  variant?: TextVariant;
  color?: string;
  muted?: boolean;
  as?: React.ElementType;
  truncate?: boolean;
  align?: React.CSSProperties['textAlign'];
  maxWidth?: string;
  noMargin?: boolean;
  inline?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
  weight?: keyof typeof fontWeight;
}

const variantToTag: Partial<Record<TextVariant, React.ElementType>> = {
  display: 'h1',
  heading: 'h2',
  subhead: 'h3',
  body: 'p',
  nav: 'span',
  navActive: 'span',
  code: 'code',
  h1: 'h1',
  h2: 'h2',
  h3: 'h3',
  h4: 'h4',
  h5: 'h5',
  h6: 'h6',
};

export const Text: React.FC<TextProps> = ({
  variant = 'body',
  color,
  muted,
  as,
  truncate,
  align,
  maxWidth,
  noMargin,
  inline,
  style,
  children,
  weight,
  ...rest
}) => {
  const variantStyles = typography[variant] || typography.body;
  const Tag = as || variantToTag[variant] || 'span';

  const resolvedColor = muted ? colors.textMuted : color || colors.text;

  const baseStyle = sx(
    {
      fontFamily,
      margin: noMargin ? 0 : undefined,
      color: resolvedColor,
      borderRadius: 0,
      fontWeight: weight ? fontWeight[weight] : undefined,
    },
    variantStyles as React.CSSProperties,
    truncate
      ? { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' as const }
      : undefined,
    align ? { textAlign: align } : undefined,
    maxWidth ? { maxWidth } : undefined,
    inline ? { display: 'inline' } : undefined,
    style,
  );

  return (
    <Tag style={baseStyle} {...rest}>
      {children}
    </Tag>
  );
};

Text.displayName = 'Text';

