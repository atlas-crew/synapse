import React from 'react';
import { clsx } from 'clsx';

/**
 * Panel — Page-zone wrapper with semantic accent bar.
 *
 * Codifies the card pattern previously hand-rolled in AdminSettingsPage:
 * a `<section>` element with `bg-surface-card`, a 4px colored top accent
 * bar, generous padding, and an elevated shadow. Use Panel to group
 * related controls or data into a named zone on a page.
 *
 * This is the "page-zone" layer of the design system, distinct from the
 * "widget" layer owned by `MetricCard`, `ChartPanel`, and `StatCard`.
 * Zones wrap multiple widgets; widgets are self-contained data displays.
 *
 * Usage:
 *   <Panel tone="info">
 *     <SectionHeader title="Tenant Privacy" />
 *     <Stack gap="md">...</Stack>
 *   </Panel>
 *
 *   <Panel tone="destructive" padding="lg" spacing="md">
 *     <SectionHeader title="Danger Zone" />
 *     <Button variant="magenta">Revoke All Tokens</Button>
 *   </Panel>
 *
 *   <Panel tone="advanced" as="div">
 *     (renders as <div> instead of <section>)
 *   </Panel>
 *
 * ## Tone vocabulary
 *
 * | tone          | accent color         | when to use                                    |
 * |---------------|----------------------|------------------------------------------------|
 * | `default`     | neutral border       | informational zones, summaries                 |
 * | `info`        | ac-blue              | primary/core settings, main control zones      |
 * | `success`     | status-success green | positive/active states, healthy connections    |
 * | `warning`     | ac-orange            | cautionary zones, impactful but recoverable    |
 * | `destructive` | status-error (red)   | danger zones — deletions, revocations, resets  |
 * | `advanced`    | ac-magenta           | advanced/expert-mode controls, experimental    |
 * | `system`      | ink-muted            | system info, read-only metadata                |
 *
 * The semantic color coding teaches users "red top bar = destructive,
 * magenta = advanced" across the entire app, not just AdminSettings.
 * Apply the same `tone` consistently when the same kind of action
 * appears in a different page.
 *
 * ## Padding
 *
 * - `sm` = p-4   (16px) — compact data panels, sidebars
 * - `md` = p-6   (24px) — standard control zones
 * - `lg` = p-8   (32px) — [default] primary page sections, matches
 *                        the AdminSettings feel
 *
 * ## Spacing (internal vertical rhythm)
 *
 * Adds `space-y-*` between direct children. Matches the AdminSettings
 * pattern of `space-y-6` inside each `<section>`.
 *
 * - `none` = no internal spacing (children manage their own)
 * - `sm`   = space-y-3
 * - `md`   = space-y-6 [default]
 * - `lg`   = space-y-8
 */

export type PanelTone =
  | 'default'
  | 'info'
  | 'success'
  | 'warning'
  | 'destructive'
  | 'advanced'
  | 'system';

export type PanelPadding = 'none' | 'sm' | 'md' | 'lg';

export type PanelSpacing = 'none' | 'sm' | 'md' | 'lg';

type PanelElement = 'section' | 'div' | 'article' | 'aside';

interface PanelProps extends React.HTMLAttributes<HTMLElement> {
  /**
   * Semantic color of the top accent bar. See tone vocabulary table
   * in the component docstring.
   */
  tone?: PanelTone;
  /**
   * Internal padding. Defaults to 'lg' (p-8) to match the AdminSettings
   * feel. Use 'sm' for compact panels, 'md' for standard control zones.
   */
  padding?: PanelPadding;
  /**
   * Internal vertical rhythm between direct children. Defaults to 'md'
   * (space-y-6) matching AdminSettings. Use 'none' if the children
   * manage their own spacing.
   */
  spacing?: PanelSpacing;
  /**
   * Polymorphic element tag. Defaults to `section` for semantic HTML.
   * Use `div` when the panel is not a top-level page zone, or `article`
   * for self-contained content blocks.
   */
  as?: PanelElement;
  /**
   * Hide the top accent bar entirely. Use sparingly — the accent is
   * part of Panel's identity and omitting it makes the panel harder
   * to distinguish from an inline bordered div. Intended for nested
   * panels where an outer panel already provides the accent.
   */
  noAccent?: boolean;
}

const toneAccentClass: Record<PanelTone, string> = {
  default: 'border-border-subtle',
  info: 'border-ac-blue',
  success: 'border-status-success',
  warning: 'border-ac-orange',
  destructive: 'border-status-error',
  advanced: 'border-ac-magenta',
  system: 'border-ink-muted',
};

const paddingClass: Record<PanelPadding, string> = {
  none: '',
  sm: 'p-4',
  md: 'p-6',
  lg: 'p-8',
};

const spacingClass: Record<PanelSpacing, string> = {
  none: '',
  sm: 'space-y-3',
  md: 'space-y-6',
  lg: 'space-y-8',
};

// ───────────────────────────────────────────────────────────────────────────
// Compound slots: <Panel.Header> and <Panel.Body>
// ───────────────────────────────────────────────────────────────────────────
//
// When a Panel contains at least one Panel.Header or Panel.Body child, it
// automatically drops its own padding and spacing so the slots can control
// the internal layout directly. This lets Header bleed a subtle background
// tint all the way to the Panel's edges (minus the accent bar), matching
// the existing `.card-header` / `.card-body` pattern used in OverviewPage's
// Top Attackers / Top Fingerprints sections and across most Hunting pages.
//
// Detection is by React element type comparison — no context, no prop
// threading, no hooks. The cost is that `<Panel.Header>` and `<Panel.Body>`
// must be direct children of Panel (not nested inside another wrapper)
// for the detection to fire. This is intentional: if you're wrapping slots
// in a fragment or another div, you probably don't want the auto-padding
// behavior anyway.

interface PanelHeaderProps extends React.HTMLAttributes<HTMLDivElement> {}

interface PanelBodyProps extends React.HTMLAttributes<HTMLDivElement> {
  /**
   * Override the body's internal padding. Defaults to `md` (p-6). Use
   * `none` when the body wraps a full-bleed child like a DataTable or
   * a list that manages its own padding.
   */
  padding?: PanelPadding;
}

/**
 * Panel.Header — optional dense header bar at the top of a Panel.
 *
 * Styled with a subtle background tint and a bottom separator so the
 * header visually distinguishes itself from the body. Defaults to a
 * flex row with `justify-between align-center` so a title and actions
 * naturally lay out on opposite sides.
 *
 * Usage:
 *   <Panel tone="default">
 *     <Panel.Header>
 *       <SectionHeader title="Top Attackers" size="h4" />
 *       <Button variant="ghost" size="sm">View all</Button>
 *     </Panel.Header>
 *     <Panel.Body>...</Panel.Body>
 *   </Panel>
 */
const PanelHeader: React.FC<PanelHeaderProps> = ({
  className,
  children,
  ...rest
}) => (
  <div
    className={clsx(
      'px-6 py-4 bg-surface-subtle/50 border-b border-border-subtle',
      'flex items-center justify-between gap-4',
      'shrink-0',
      className,
    )}
    {...rest}
  >
    {children}
  </div>
);
PanelHeader.displayName = 'Panel.Header';

/**
 * Panel.Body — optional content slot beneath a Panel.Header.
 *
 * Defaults to `padding="md"` (p-6). Use `padding="none"` for full-bleed
 * children like lists, tables, or iframes that manage their own padding.
 */
const PanelBody: React.FC<PanelBodyProps> = ({
  padding = 'md',
  className,
  children,
  ...rest
}) => (
  <div
    className={clsx(
      padding !== 'none' && paddingClass[padding],
      className,
    )}
    {...rest}
  >
    {children}
  </div>
);
PanelBody.displayName = 'Panel.Body';

// ───────────────────────────────────────────────────────────────────────────
// Panel parent component
// ───────────────────────────────────────────────────────────────────────────

const PanelImpl: React.FC<PanelProps> = ({
  tone = 'default',
  padding = 'lg',
  spacing = 'md',
  as = 'section',
  noAccent = false,
  className,
  children,
  ...rest
}) => {
  // Auto-detect slotted usage: if any direct child is Panel.Header or
  // Panel.Body, drop Panel's own padding and spacing so slots control
  // the interior layout.
  const childArray = React.Children.toArray(children);
  const hasSlots = childArray.some(
    (child) =>
      React.isValidElement(child) &&
      (child.type === PanelHeader || child.type === PanelBody),
  );

  const effectivePadding = hasSlots ? undefined : paddingClass[padding];
  const effectiveSpacing = hasSlots ? '' : spacingClass[spacing];

  const Component = as as keyof React.JSX.IntrinsicElements;
  const classes = clsx(
    'bg-surface-card shadow-card',
    noAccent ? 'border border-border-subtle' : ['border-t-4', toneAccentClass[tone]],
    effectivePadding,
    effectiveSpacing,
    // When slots take over, the parent becomes a flex column so Body can
    // flex-grow and Header can stay pinned at the top. Without this, a
    // Panel.Body with flex-grow inside a non-flex Panel does nothing.
    hasSlots && 'flex flex-col',
    className,
  );
  return React.createElement(Component, { className: classes, ...rest }, children);
};

// Attach compound slots to Panel as static properties so users can write
// <Panel.Header> and <Panel.Body> via standard compound-component syntax.
type PanelComponent = React.FC<PanelProps> & {
  Header: typeof PanelHeader;
  Body: typeof PanelBody;
};

export const Panel = PanelImpl as PanelComponent;
Panel.Header = PanelHeader;
Panel.Body = PanelBody;
