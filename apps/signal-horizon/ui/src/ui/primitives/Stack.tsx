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
type StackElement = 'div' | 'span' | 'section' | 'label';

interface StackProps extends React.HTMLAttributes<HTMLElement> {
  /**
   * Polymorphic element tag for semantic layout wrappers.
   * Limited to supported HTML containers.
   */
  as?: StackElement;
  direction?: 'row' | 'column';
  gap?: SpacingKey;
  align?: React.CSSProperties['alignItems'];
  justify?: React.CSSProperties['justifyContent'];
  wrap?: boolean;
  /**
   * Render as inline-flex instead of flex. Use with inline elements like <span>.
   */
  inline?: boolean;
  fill?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

export const Stack: React.FC<StackProps> = ({
  as: Component = 'div',
  direction = 'column',
  gap = 'md',
  align,
  justify,
  wrap,
  inline,
  fill,
  style,
  children,
  ...rest
}) => (
  <Component
    style={{
      display: inline ? 'inline-flex' : 'flex',
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
  </Component>
);

Stack.displayName = 'Stack';
