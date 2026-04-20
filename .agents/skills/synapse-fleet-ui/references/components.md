# Component Catalog

This catalog lists the available UI components in the Apparatus Design System. Always prefer these over custom implementations.

## Layout & Primitives

- **Box**: Basic layout unit. Support layout props (sx, m, p, bg).
- **Stack**: Container for items in a horizontal or vertical stack.
- **Grid**: Responsive grid system.
- **Divider**: Horizontal or vertical line for content separation.
- **Panel**: Card-like container with flexible padding and tones (primary, secondary, subtle).

## Typography

- **Text**: Standard text component with size (xs, sm, md, lg, xl) and weight (light, regular, bold) props.
- **SectionHeader**: Page or section title with optional actions or subtitles.

## Data Visualization

- **MetricCard**: Displays a single numeric KPI with a label and optional trend.
- **KpiStrip**: A row of multiple MetricCards for dashboard overviews.
- **StatCard**: Advanced card with metric, trend sparkline, and detail labels.
- **ChartPanel**: Wrapper for Recharts instances with standardized header and padding.
- **DataTable**: Responsive table with sorting, filtering, and custom cell rendering.
- **ProgressBar**: Visual indicator for percentage progress.

## Interactive Controls

- **Button**: Actions with variants (primary, secondary, outline, ghost).
- **Tabs**: Tabbed navigation or content switching.
- **Modal**: Focused overlay for critical actions.
- **Drawer**: Slide-out panel for secondary content.
- **TimeRangeSelector**: Standard dashboard time range picker.
- **Input / Select**: Themed form controls for user data entry.
- **Tooltip**: Non-intrusive informational overlays.

## Status & Feedback

- **StatusBadge**: Color-coded indicator for states (active, blocked, warning, etc.).
- **Alert**: Inline notification for success, warning, or error messages.
- **EmptyState**: Standard placeholder for empty data views.
- **Spinner / LoadingOverlay**: Visual indicators for background processing.

## Application Shell

- **AppShell**: Root layout component with integrated Sidebar and main content area.
- **Sidebar**: Main application navigation sidebar.
- **Breadcrumb**: Utility for hierarchical page navigation.

## Design Rule Reminder
- **Radius**: `borderRadius: 0` is hardcoded into these components.
- **Font**: "Rubik" is the default.
- **Padding**: All components use `spacing` tokens (e.g., `padding: spacing.md`).
