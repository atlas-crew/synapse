# Task Structure Guide

All tasks in `backlog/` follow a strict markdown format with YAML frontmatter.

## YAML Frontmatter

```yaml
---
id: TASK-N         # Unique ID, e.g., TASK-32
title: Task Title  # Concise, descriptive title
status: To Do      # Draft, To Do, In Progress, Done
assignee: []       # List of assignees
created_date: 'YYYY-MM-DD HH:MM'
updated_date: 'YYYY-MM-DD HH:MM'
labels: []         # Project tags (e.g., waf, ui, api, devops)
milestone: m-N     # Milestone ID
dependencies: []   # List of TASK-N IDs
references: []     # List of file paths or URLs
priority: medium   # low, medium, high
---
```

## Markdown Sections

### Description
Enclosed in `<!-- SECTION:DESCRIPTION:BEGIN -->` and `<!-- SECTION:DESCRIPTION:END -->`. Provide the "what" and "why".

### Acceptance Criteria
Enclosed in `<!-- AC:BEGIN -->` and `<!-- AC:END -->`. Use a list of `[ ]` or `[x]` items with unique `#N` IDs.

### Final Summary
Enclosed in `<!-- SECTION:FINAL_SUMMARY:BEGIN -->` and `<!-- SECTION:FINAL_SUMMARY:END -->`. Completed only when status is `Done`.
- **Summary**: High-level overview of the work done.
- **Key Changes**: Bulleted list of major changes.
- **Tests**: List of new or updated tests.
- **Verification**: Evidence of successful execution.

## File Naming Convention
Tasks are stored in `backlog/tasks/` or `backlog/completed/` with the filename:
`task-N - Title-With-Hyphens.md`
