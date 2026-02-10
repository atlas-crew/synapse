import React from 'react';
import { spacing } from '../tokens/tokens';

/**
 * Stack — Flex layout with consistent spacing.
 *
 * Usage:
 *   <Stack gap="md">items vertically</Stack>
 *   <Stack direction="row" gap="lg" align="center">items horizontally</Stack>
 */

type SpacingKey = keyof typeof spacing;

interface StackProps extends React.HTMLAttributes<HTMLDivElement> {
  direction?: 'row' | 'column';
  gap?: SpacingKey;
  align?: React.CSSProperties['alignItems'];
  justify?: React.CSSProperties['justifyContent'];
  wrap?: boolean;
  fill?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

export const Stack: React.FC<StackProps> = ({
  direction = 'column',
  gap = 'md',
  align,
  justify,
  wrap,
  fill,
  style,
  children,
  ...rest
}) => (
  <div
    style={{
      display: 'flex',
      flexDirection: direction,
      gap: spacing[gap],
      alignItems: align,
      justifyContent: justify,
      flexWrap: wrap ? 'wrap' : undefined,
      width: fill ? '100%' : undefined,
      ...style,
    }}
    {...rest}
  >
    {children}
  </div>
);

Stack.displayName = 'Stack';
