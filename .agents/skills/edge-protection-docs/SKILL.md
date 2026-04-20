---
name: edge-protection-docs
description: Manage the Edge Protection documentation ecosystem. Use when creating or modifying documents in site/ (user-facing) or docs/ (developer-facing) directories.
---

# Edge Protection Documentation Strategy

This skill ensures a strict separation between user-facing documentation and internal developer notes, following the project's [Documentation Navigator](references/categories.md).

## Workflow

### 1. Categorize

Before creating a new document, determine its audience:
- **User-facing**: High-level guides, installation, configuration, and API references. Place under `site/`.
- **Developer-facing**: Internal implementation notes, troubleshooting recipes, and design plans. Place under `docs/`.

### 2. Name

- **Kebab-case**: Always use `kebab-case-filenames.md`.
- **Location**: Never place markdown in the repo root except for `README.md`, `CONTRIBUTING.md`, and `CHANGELOG.md`.

### 3. Update Site (VitePress)

If adding a file to `site/`:
1. Place it in the correct subdirectory (e.g., `site/deployment/`).
2. Add a link to the sidebar in `site/.vitepress/config.mts`.
3. Ensure it uses brand-compliant themes and fonts (Automatic via VitePress config).

### 4. Update Navigator

If adding a file to `docs/`:
1. Place it in the correct subdirectory (e.g., `docs/development/`).
2. Add a one-sentence summary and link to `docs/NAVIGATOR.md`.

## Best Practices

- **Atomic Commits**: Commit the new document and its sidebar/navigator entry together.
- **Redirects**: When renaming features (e.g., Horizon → Synapse Fleet), update old links and use redirect stubs if necessary.
- **Assets**: Place images in `site/public/` for user docs and `docs/assets/` for developer docs.

## Resources

- [Documentation Categories](references/categories.md): Detailed map of where different document types live.
- `docs/NAVIGATOR.md`: The canonical internal map of the `docs/` directory.
