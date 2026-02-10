import React from 'react';
import { colors, spacing, shadows, borders } from '../tokens/tokens';
import { sx } from '../utils/helpers';

/**
 * Box — Base layout primitive.
 *
 * Usage:
 *   <Box bg="card" p="lg" shadow="card">content</Box>
 *   <Box bg="navy" p="xl" border="left" borderColor={colors.magenta}>content</Box>
 */

type BgPreset = 'card' | 'navy' | 'dark' | 'surface' | 'light' | 'transparent';
type PaddingPreset = keyof typeof spacing;

interface BoxProps extends React.HTMLAttributes<HTMLDivElement> {
  bg?: BgPreset | string;
  p?: PaddingPreset;
  px?: PaddingPreset;
  py?: PaddingPreset;
  shadow?: 'card' | 'elevated' | 'subtle' | 'none';
  border?: 'left' | 'top' | 'all' | 'subtle' | 'none';
  borderColor?: string;
  borderWidth?: string;
  flex?: boolean;
  direction?: 'row' | 'column';
  align?: React.CSSProperties['alignItems'];
  justify?: React.CSSProperties['justifyContent'];
  gap?: PaddingPreset;
  wrap?: boolean;
  grid?: boolean;
  cols?: number | string;
  fill?: boolean;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

const bgMap: Record<BgPreset, string> = {
  card: colors.card.dark,
  navy: colors.navy,
  dark: colors.bg.dark,
  surface: '#0D2247',
  light: colors.gray.light,
  transparent: 'transparent',
};

export const Box = React.forwardRef<HTMLDivElement, BoxProps>(
  (
    {
      bg, p, px, py, shadow, border, borderColor = colors.blue, borderWidth = '4px',
      flex, direction = 'column', align, justify, gap, wrap,
      grid, cols, fill, style, children, ...rest
    },
    ref,
  ) => {
    const resolvedBg = bg ? (bgMap[bg as BgPreset] || bg) : undefined;

    const borderStyles: React.CSSProperties = {};
    if (border === 'left') {
      borderStyles.borderLeft = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'top') {
      borderStyles.borderTop = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'all') {
      borderStyles.border = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'subtle') {
      borderStyles.border = borders.subtle.dark;
    }

    const baseStyle: React.CSSProperties = sx(
      { borderRadius: 0, boxSizing: 'border-box' as const },
      resolvedBg ? { background: resolvedBg } : undefined,
      p ? { padding: spacing[p] } : undefined,
      px ? { paddingLeft: spacing[px], paddingRight: spacing[px] } : undefined,
      py ? { paddingTop: spacing[py], paddingBottom: spacing[py] } : undefined,
      shadow && shadow !== 'none' ? { boxShadow: shadows[shadow].dark } : undefined,
      borderStyles,
      flex ? { display: 'flex', flexDirection: direction, alignItems: align, justifyContent: justify } : undefined,
      gap ? { gap: spacing[gap] } : undefined,
      wrap ? { flexWrap: 'wrap' as const } : undefined,
      grid
        ? {
            display: 'grid',
            gridTemplateColumns:
              typeof cols === 'number' ? `repeat(${cols}, 1fr)` : cols || 'repeat(auto-fit, minmax(200px, 1fr))',
          }
        : undefined,
      fill ? { width: '100%' } : undefined,
      style,
    );

    return (
      <div ref={ref} style={baseStyle} {...rest}>
        {children}
      </div>
    );
  },
);

Box.displayName = 'Box';
