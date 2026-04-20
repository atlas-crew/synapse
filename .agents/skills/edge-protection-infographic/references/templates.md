# Infographic Template Guide

The source of truth for infographics is HTML under `brand/infographics/html/`.

## Placeholders

- `__TITLE__`: Main heading.
- `__SUBTITLE__`: One-sentence description.
- `__TAGLINE__`: Footer primary tagline.
- `__TAGLINE_SUB__`: Footer supporting tagline.
- `__PAGE_HEIGHT__`: Total height in pixels (used for `@page` rule).
- `__SLUG__`: Filename base (for OG metadata).

## CSS Typography Classes

- `.t-display`: Large headings (36px).
- `.t-label`: Small uppercase labels (11px).
- `.t-body`: Body text (13px).
- `.t-metric`: Large numeric displays (32px).

## Design Components

### Section Container
```html
<div class="section">
  <div class="section-head">
    <div class="section-dot" style="background:var(--blue);"></div>
    <span class="t-label" style="color:var(--blue);">Section Title</span>
    <div class="section-line"></div>
  </div>
  <!-- section content -->
</div>
```

### Hero Stats
```html
<div class="hero-stats">
  <div class="hero-stat">
    <div class="glow" style="background:var(--blue);"></div>
    <div class="value t-metric">99.9%</div>
    <div class="label t-label">Uptime</div>
  </div>
  <!-- more stats -->
</div>
```

## Brand Colors (CSS Variables)

| Variable | Color | Hex |
|----------|-------|-----|
| `--blue` | Primary | #1E90FF |
| `--violet`| Accent | #8B5CF6 |
| `--coral` | Secondary | #F97316 |
| `--green` | Success | #10B981 |
| `--red`   | Error   | #EF4444 |
| `--amber` | Warning | #F59E0B |
| `--cyan`  | Info    | #06B6D4 |
| `--bg`    | Background | #080e1a |
| `--surface`| Surface | #0c1220 |
| `--text`   | Text | #e8ecf4 |
| `--text-sec`| Secondary Text | #8899b0 |
| `--muted`  | Muted | #5a6f8a |
