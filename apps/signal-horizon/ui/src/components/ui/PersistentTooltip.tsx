/**
 * PersistentTooltip - WCAG 1.4.13 compliant Recharts tooltip wrapper
 *
 * Recharts tooltips vanish the moment the cursor leaves a data point.
 * WCAG 1.4.13 (Content on Hover or Focus) requires that additional content
 * triggered by pointer hover:
 *   1. Can be dismissed (Escape key)
 *   2. Can be hovered (the tooltip itself stays while the cursor is on it)
 *   3. Is persistent (remains until the user deliberately moves away)
 *
 * Usage:
 *   <Tooltip content={<PersistentTooltip />} />
 *
 * The component receives Recharts' standard TooltipProps via the `content`
 * rendering mechanism, then wraps the default tooltip content in an
 * interactive container with mouse-enter/leave + keyboard handlers.
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import type { TooltipProps } from 'recharts';
import type {
  ValueType,
  NameType,
} from 'recharts/types/component/DefaultTooltipContent';
import { Text, colors, tooltipDefaults } from '@/ui';

// ─── Constants ────────────────────────────────────────────────────────────────

/** Grace period (ms) between Recharts hiding the tooltip and us actually hiding it. */
const HIDE_DELAY_MS = 300;

// ─── Component ────────────────────────────────────────────────────────────────

type PersistentTooltipProps = TooltipProps<ValueType, NameType> & {
  /** Override the hide-delay grace period in ms. Default 300. */
  hideDelay?: number;
};

export function PersistentTooltip({
  active,
  payload,
  label,
  hideDelay = HIDE_DELAY_MS,
}: PersistentTooltipProps) {
  // Whether the cursor is hovering over the tooltip container itself.
  const [hovering, setHovering] = useState(false);
  // Whether the tooltip should render at all.
  const [visible, setVisible] = useState(false);
  // Snapshot of the last valid payload so content doesn't flash during the grace window.
  const lastPayload = useRef(payload);
  const lastLabel = useRef(label);
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep the latest valid payload cached.
  if (active && payload && payload.length > 0) {
    lastPayload.current = payload;
    lastLabel.current = label;
  }

  // ── Visibility logic ────────────────────────────────────────────────────────

  useEffect(() => {
    if (active) {
      // Recharts says "show" -> cancel any pending hide and show immediately.
      if (hideTimer.current) {
        clearTimeout(hideTimer.current);
        hideTimer.current = null;
      }
      setVisible(true);
    } else if (!hovering) {
      // Recharts says "hide" and user is NOT hovering the tooltip -> schedule hide.
      hideTimer.current = setTimeout(() => {
        setVisible(false);
        hideTimer.current = null;
      }, hideDelay);
    }
    // If `hovering` is true we intentionally do nothing (keep it visible).

    return () => {
      if (hideTimer.current) {
        clearTimeout(hideTimer.current);
        hideTimer.current = null;
      }
    };
  }, [active, hovering, hideDelay]);

  // ── Escape-key dismissal ────────────────────────────────────────────────────

  const dismiss = useCallback(() => {
    setVisible(false);
    setHovering(false);
    if (hideTimer.current) {
      clearTimeout(hideTimer.current);
      hideTimer.current = null;
    }
  }, []);

  useEffect(() => {
    if (!visible) return;

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        dismiss();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [visible, dismiss]);

  // ── Mouse handlers ──────────────────────────────────────────────────────────

  const onMouseEnter = useCallback(() => {
    if (hideTimer.current) {
      clearTimeout(hideTimer.current);
      hideTimer.current = null;
    }
    setHovering(true);
  }, []);

  const onMouseLeave = useCallback(() => {
    setHovering(false);
    // Start the hide countdown.
    hideTimer.current = setTimeout(() => {
      setVisible(false);
      hideTimer.current = null;
    }, hideDelay);
  }, [hideDelay]);

  // ── Render ──────────────────────────────────────────────────────────────────

  const items = lastPayload.current;
  if (!visible || !items || items.length === 0) {
    return null;
  }

  return (
    <div
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      role="status"
      aria-live="polite"
      style={{
        ...tooltipDefaults.contentStyle,
        padding: '10px 14px',
        pointerEvents: 'auto',
        // Prevent Recharts' wrapper from clipping the interactive area.
        position: 'relative',
        zIndex: 10,
      }}
    >
      {lastLabel.current != null && (
        <Text as="p" style={{ ...tooltipDefaults.labelStyle, margin: '0 0 4px' }} noMargin>
          {lastLabel.current}
        </Text>
      )}
      <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
        {items.map((entry, idx) => (
          <li
            key={entry.dataKey?.toString() ?? idx}
            style={{
              ...tooltipDefaults.itemStyle,
              padding: '2px 0',
            }}
          >
            <span
              className="inline-block align-middle mr-1.5"
              style={{
                width: 10,
                height: 10,
                backgroundColor:
                  (entry.color as string) ?? colors.skyBlue,
              }}
            />
            <span className="align-middle">
              {entry.name}: {typeof entry.value === 'number' ? entry.value.toLocaleString() : entry.value}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
