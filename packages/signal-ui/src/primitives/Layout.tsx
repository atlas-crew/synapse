import React from 'react';
import { spacing } from '../tokens/tokens';

/**
 * Divider — Horizontal or vertical separator.
 *
 * Usage:
 *   <Divider />
 *   <Divider spacing="lg" />
 */

type SpacingKey = keyof typeof spacing;

interface DividerProps {
  spacing?: SpacingKey;
  color?: string;
  vertical?: boolean;
}

export const Divider: React.FC<DividerProps> = ({
  spacing: spacingKey = 'md',
  color = 'rgba(255,255,255,0.08)',
  vertical,
}) => (
  <div
    style={
      vertical
        ? {
            width: '1px',
            alignSelf: 'stretch',
            background: color,
            marginLeft: spacing[spacingKey],
            marginRight: spacing[spacingKey],
          }
        : {
            height: '1px',
            width: '100%',
            background: color,
            marginTop: spacing[spacingKey],
            marginBottom: spacing[spacingKey],
          }
    }
  />
);

Divider.displayName = 'Divider';

/**
 * Grid — CSS Grid layout helper.
 *
 * Usage:
 *   <Grid cols={3} gap="lg">cards...</Grid>
 *   <Grid cols="200px 1fr 1fr" gap="md">mixed columns</Grid>
 */

interface GridProps extends React.HTMLAttributes<HTMLDivElement> {
  cols?: number | string;
  rows?: string;
  gap?: SpacingKey;
  rowGap?: SpacingKey;
  colGap?: SpacingKey;
  align?: React.CSSProperties['alignItems'];
  fill?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

export const Grid: React.FC<GridProps> = ({
  cols = 2,
  rows,
  gap = 'lg',
  rowGap,
  colGap,
  align,
  fill,
  style,
  children,
  ...rest
}) => (
  <div
    style={{
      display: 'grid',
      gridTemplateColumns:
        typeof cols === 'number' ? `repeat(${cols}, 1fr)` : cols,
      gridTemplateRows: rows,
      gap: !rowGap && !colGap ? spacing[gap] : undefined,
      rowGap: rowGap ? spacing[rowGap] : undefined,
      columnGap: colGap ? spacing[colGap] : undefined,
      alignItems: align,
      width: fill ? '100%' : undefined,
      ...style,
    }}
    {...rest}
  >
    {children}
  </div>
);

Grid.displayName = 'Grid';

