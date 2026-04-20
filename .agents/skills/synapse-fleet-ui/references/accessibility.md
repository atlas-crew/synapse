# Accessibility Guidelines (WCAG 2.2 AA)

Signal Horizon dashboards must be fully accessible by default.

## Semantic HTML & Landmarks

- **Page Structure**: Use `<header>`, `<nav>`, `<main>`, `<aside>`, and `<footer>`.
- **Heading Hierarchy**: Maintain a logical structure (H1–H6). Exactly one H1 per view. Never skip levels.
- **Lists**: Use `<ul>` and `<li>` for repeated structural elements.

## Focus Management

- **Visible Focus**: All interactive elements must have a high-contrast visible focus indicator. Never set `outline: none` without a replacement.
- **Skip Navigation**: Every view must include a "Skip to main content" link as the first focusable element.
- **Modals**: Focus must be trapped within the modal when open and restored to the trigger element on close. Pressing Escape must close the modal.

## Forms & Inputs

- **Labels**: Every input must have a programmatically associated `<label>`. Placeholder text is NOT a replacement.
- **Error Handling**: Set `aria-invalid="true"` on invalid inputs. Link error messages using `aria-describedby`.
- **Live Regions**: Use `aria-live="polite"` or `role="alert"` for dynamic notifications and status updates.

## Images & Media

- **Alt Text**: Provide descriptive alt text for informative images. Use `alt=""` for purely decorative ones.
- **Icons**: Functional icons (e.g., in buttons) must have descriptive labels for screen readers.

## Interactive Component Patterns

- **Tabs**: `role="tablist"`, `role="tab"`, `role="tabpanel"`. Support arrow key navigation.
- **Accordions**: Use `aria-expanded` and `aria-controls`.
- **Modals**: `role="dialog"`, `aria-modal="true"`.

## Color & Contrast

- **Contrast Ratio**: Normal text must meet 4.5:1. Large text and UI components (borders, icons) must meet 3:1.
- **Color Independence**: Never convey state using color alone. Use text labels or status icons.
