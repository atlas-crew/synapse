import React from 'react';
import { colors, fontFamily, fontWeight, spacing } from '../tokens/tokens';
import { alpha } from '../utils/helpers';

/**
 * Alert — Left-bordered notification/callout block.
 *
 * Usage:
 *   <Alert status="success">Sensor deployed successfully.</Alert>
 *   <Alert status="error" title="Connection Lost">Sensor us-east-2 offline.</Alert>
 *   <Alert status="warning" dismissible onDismiss={() => {}}>Rate limit approaching.</Alert>
 */

type AlertStatus = 'success' | 'warning' | 'error' | 'info';

interface AlertProps {
  status?: AlertStatus;
  title?: string;
  dismissible?: boolean;
  onDismiss?: () => void;
  style?: React.CSSProperties;
  children: React.ReactNode;
}

const statusMap: Record<AlertStatus, string> = {
  success: colors.green,
  warning: colors.orange,
  error: colors.red,
  info: colors.blue,
};

export const Alert: React.FC<AlertProps> = ({
  status = 'info',
  title,
  dismissible,
  onDismiss,
  style,
  children,
}) => {
  const color = statusMap[status];

  return (
    <div
      style={{
        background: alpha(color, 0.1),
        borderLeft: `3px solid ${color}`,
        borderRadius: 0,
        padding: `${spacing.md} ${spacing.lg}`,
        fontFamily,
        fontSize: '14px',
        color: '#F0F4F8',
        display: 'flex',
        alignItems: 'flex-start',
        gap: spacing.sm,
        ...style,
      }}
    >
      <div style={{ flex: 1 }}>
        {title && (
          <div
            style={{
              fontWeight: fontWeight.medium,
              marginBottom: spacing.xs,
              color: '#F0F4F8',
            }}
          >
            {title}
          </div>
        )}
        <div style={{ fontWeight: fontWeight.regular, lineHeight: '20px' }}>
          {children}
        </div>
      </div>
      {dismissible && (
        <button
          onClick={onDismiss}
          style={{
            background: 'none',
            border: 'none',
            color: colors.gray.mid,
            cursor: 'pointer',
            fontSize: '18px',
            padding: 0,
            lineHeight: 1,
            flexShrink: 0,
          }}
          aria-label="Dismiss"
        >
          ×
        </button>
      )}
    </div>
  );
};

Alert.displayName = 'Alert';

