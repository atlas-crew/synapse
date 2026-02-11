import React from 'react';
import { colors, fontFamily, fontWeight, spacing } from '../tokens/tokens';

/**
 * SectionHeader — Section/page title with optional actions, eyebrow, and description.
 *
 * Usage:
 *   <SectionHeader title="Traffic Analytics" />
 *   <SectionHeader
 *     eyebrow="REAL-TIME"
 *     title="Fleet Overview"
 *     description="Active sensors across all regions"
 *     actions={<Button>Export</Button>}
 *   />
 *   <SectionHeader title="Threat Hunting" variant="numbered" number={3} />
 */

type Variant = 'default' | 'bordered' | 'numbered';

interface SectionHeaderProps {
  title: string;
  /** Optional title element id for aria-labelledby wiring */
  titleId?: string;
  eyebrow?: string;
  description?: string;
  /** Optional icon displayed before title */
  icon?: React.ReactNode;
  /** Right-side actions */
  actions?: React.ReactNode;
  /** Visual variant */
  variant?: Variant;
  /** For 'numbered' variant */
  number?: number;
  /** Title size */
  size?: 'h1' | 'h2' | 'h3' | 'h4';
  /** Bottom margin */
  mb?: keyof typeof spacing;
  /** Optional title style overrides */
  titleStyle?: React.CSSProperties;
  style?: React.CSSProperties;
}

const headingSizes = {
  h1: { fontSize: '3rem', lineHeight: '56px' },
  h2: { fontSize: '1.875rem', lineHeight: '38px' },
  h3: { fontSize: '1.75rem', lineHeight: '36px' },
  h4: { fontSize: '1.5rem', lineHeight: '32px' },
};

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  titleId,
  eyebrow,
  description,
  icon,
  actions,
  variant = 'default',
  number,
  size = 'h2',
  mb = 'lg',
  titleStyle,
  style,
}) => {
  if (variant === 'numbered') {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: spacing.md,
          background: colors.navy,
          padding: `${spacing.md} ${spacing.lg}`,
          marginBottom: spacing[mb],
          ...style,
        }}
      >
        <div
          style={{
            background: colors.blue,
            color: '#FFFFFF',
            fontFamily,
            fontWeight: fontWeight.medium,
            fontSize: '16px',
            width: '36px',
            height: '36px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: 0,
            flexShrink: 0,
          }}
        >
          {number}
        </div>
        <span
          id={titleId}
          style={{
            fontFamily,
            fontWeight: fontWeight.light,
            ...headingSizes[size],
            color: '#F0F4F8',
            ...titleStyle,
          }}
        >
          {title}
        </span>
      </div>
    );
  }

  return (
    <div
      style={{
        borderBottom: variant === 'bordered' ? `2px solid ${colors.blue}` : undefined,
        paddingBottom: variant === 'bordered' ? spacing.md : undefined,
        marginBottom: spacing[mb],
        ...style,
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: actions ? 'center' : 'flex-start',
        }}
      >
        <div>
          {eyebrow && (
            <div
              style={{
                fontFamily,
                fontWeight: fontWeight.bold,
                fontSize: '12px',
                color: colors.magenta,
                textTransform: 'uppercase',
                letterSpacing: '0.1em',
                marginBottom: spacing.xs,
              }}
            >
              {eyebrow}
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>
            {icon && (
              <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                {icon}
              </span>
            )}
            <div
              id={titleId}
              style={{
                fontFamily,
                fontWeight: fontWeight.light,
                ...headingSizes[size],
                color: '#F0F4F8',
                margin: 0,
                ...titleStyle,
              }}
            >
              {title}
            </div>
          </div>
          {description && (
            <div
              style={{
                fontFamily,
                fontWeight: fontWeight.regular,
                fontSize: '14px',
                color: colors.gray.mid,
                marginTop: spacing.xs,
              }}
            >
              {description}
            </div>
          )}
        </div>
        {actions && <div style={{ flexShrink: 0 }}>{actions}</div>}
      </div>
    </div>
  );
};

SectionHeader.displayName = 'SectionHeader';
