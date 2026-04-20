---
name: edge-protection-infographic
description: Author, render, and manage Synapse Edge Protection infographics. Use when creating new infographics in brand/infographics/html/ or rendering existing ones to PNG/PDF using the justfile.
---

# Edge Protection Infographic Pipeline

This skill manages the author-once pipeline (HTML source → PNG/PDF output) for technical infographics.

## Bundled Utilities

- **`scripts/validate_setup.cjs`**: Validates system dependencies (ImageMagick, Google Chrome) for rendering.
  - Usage: `node scripts/validate_setup.cjs`

## Workflow

### 1. Create a New Infographic

Use the `just` recipe to scaffold from the template:
```bash
just infographic-new <name> "<Title>"
```
This creates `brand/infographics/html/<name>.html`.

### 2. Edit Content

Edit the HTML file using the [Template Guide](references/templates.md). Use standard sections and brand colors.
- **Page Height**: Adjust the `@page` height and the `__PAGE_HEIGHT__` placeholder if content overflows.
- **OG Images**: Place supporting images in `brand/infographics/assets/` (if any).

### 3. Render

Before rendering, ensure your environment is ready:
```bash
node scripts/validate_setup.cjs
```

Then render the HTML to PNG (for web) and PDF (for print/sharing):
```bash
just infographic-render <name>
```

### 4. Sync

Sync the HTML source to the public docs site:
```bash
just infographic-sync
```

## Best Practices

- **Atomic Commits**: Commit the HTML source, PNG, and PDF together as a single unit.
- **Single Page**: Ensure the PDF output is exactly one page. If it spans two, increase the `@page` height in the HTML.
- **Typography**: Use the 'Recursive' font via the provided Google Fonts link.
- **Color Palette**: Stick to the CSS variables defined in `:root` (e.g., `--blue`, `--violet`, `--coral`).

## Resources

- [Template Guide](references/templates.md): HTML structure, CSS classes, and placeholder reference.
