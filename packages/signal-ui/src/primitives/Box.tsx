import React from 'react';
import { colors, spacing, shadows, borders } from '../tokens/tokens';
import { sx } from '../utils/helpers';

/**
 * Box — Base layout primitive.
 *
 * Usage:
 *   <Box bg="card" p="lg" shadow="card">content</Box>
 *   <Box bg="navy" p="xl" border="left" borderColor={colors.magenta}>content</Box>
 *   <Box as="section" p="md">content</Box>
 */

type BgPreset = 'card' | 'navy' | 'dark' | 'surface' | 'light' | 'transparent';
type PaddingPreset = keyof typeof spacing | 'none';

interface BoxProps extends React.HTMLAttributes<HTMLElement> {
  bg?: BgPreset | string;
  p?: PaddingPreset;
  px?: PaddingPreset;
  py?: PaddingPreset;
  shadow?: 'card' | 'elevated' | 'subtle' | 'none';
  border?: 'left' | 'top' | 'all' | 'subtle' | 'none' | 'bottom';
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
  as?: React.ElementType;
}

const bgMap: Record<BgPreset, string> = {
  card: colors.card.dark,
  navy: colors.navy,
  dark: colors.bg.dark,
  surface: colors.surface.base,
  light: colors.bg.light,
  transparent: 'transparent',
};

export const Box = React.forwardRef<HTMLElement, BoxProps>(
  (
    {
      bg,
      p,
      px,
      py,
      shadow,
      border,
      borderColor = colors.blue,
      borderWidth = '4px',
      flex,
      direction = 'column',
      align,
      justify,
      gap,
      wrap,
      grid,
      cols,
      fill,
      style,
      children,
      as: Tag = 'div',
      ...rest
    },
    ref,
  ) => {
    const resolvedBg = bg ? (bgMap[bg as BgPreset] || bg) : undefined;

    const borderStyles: React.CSSProperties = {};
    if (border === 'left') {
      borderStyles.borderLeft = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'top') {
      borderStyles.borderTop = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'bottom') {
      borderStyles.borderBottom = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'all') {
      borderStyles.border = `${borderWidth} solid ${borderColor}`;
    } else if (border === 'subtle') {
      borderStyles.border = borders.subtle.dark;
    }

    const baseStyle: React.CSSProperties = sx(
      { borderRadius: 0, boxSizing: 'border-box' as const },
      resolvedBg ? { background: resolvedBg } : undefined,
      p ? { padding: p === 'none' ? 0 : spacing[p as keyof typeof spacing] } : undefined,
      px ? { paddingLeft: px === 'none' ? 0 : spacing[px as keyof typeof spacing], paddingRight: px === 'none' ? 0 : spacing[px as keyof typeof spacing] } : undefined,
      py ? { paddingTop: py === 'none' ? 0 : spacing[py as keyof typeof spacing], paddingBottom: py === 'none' ? 0 : spacing[py as keyof typeof spacing] } : undefined,
      shadow && shadow !== 'none' ? { boxShadow: shadows[shadow].dark } : undefined,
      borderStyles,
      flex
        ? { display: 'flex', flexDirection: direction, alignItems: align, justifyContent: justify }
        : undefined,
      gap ? { gap: gap === 'none' ? 0 : spacing[gap as keyof typeof spacing] } : undefined,
      wrap ? { flexWrap: 'wrap' as const } : undefined,
      grid
        ? {
            display: 'grid',
            gridTemplateColumns:
              typeof cols === 'number'
                ? `repeat(${cols}, 1fr)`
                : cols || 'repeat(auto-fit, minmax(200px, 1fr))',
          }
        : undefined,
      fill ? { width: '100%' } : undefined,
      style,
    );

    return (
      <Tag ref={ref as any} style={baseStyle} {...rest}>
        {children}
      </Tag>
    );
  },
);

Box.displayName = 'Box';

