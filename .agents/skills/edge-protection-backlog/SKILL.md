---
name: edge-protection-backlog
description: Manage the Edge Protection project backlog. Use when creating, updating, or archiving tasks in the backlog/ directory.
---

# Edge Protection Backlog Management

This skill provides the procedural knowledge required to manage the project's task lifecycle using the `backlog/` directory and its associated tools.

## Workflow

### 1. Browse & Search

Use the `mcp__backlog__task_list` and `mcp__backlog__task_search` tools to find existing tasks.
- **Milestones**: Tasks are grouped by milestones (e.g., `m-6`, `m-8`). Use `mcp__backlog__milestone_list` to see available milestones.
- **Status**: Tasks move from `Draft` → `To Do` → `In Progress` → `Done`.

### 2. Create a New Task

Use `mcp__backlog__task_create` to initialize a new task.
- **Naming**: The tool automatically handles the `task-N - Title.md` filename convention.
- **Metadata**: Always include a `priority` (low, medium, high), `milestone`, and relevant `labels`.
- **Description**: Use the standard template with `<!-- SECTION:DESCRIPTION:BEGIN -->` tags.

### 3. Work on a Task

When starting a task:
1. Move status to `In Progress` using `mcp__backlog__task_edit`.
2. Update `implementationNotes` or `planAppend` as you progress.
3. Check off `acceptanceCriteriaCheck` items as they are completed.

### 4. Complete a Task

When a task is finished:
1. Update status to `Done`.
2. Fill out the `finalSummary` using the [Task Structure Guide](references/task-structure.md).
3. Use `mcp__backlog__task_complete` to move the file to `backlog/completed/`.

## Best Practices

- **Atomic Tasks**: Each task should represent one logical, reviewable change.
- **Clear Acceptance Criteria**: Define exactly what "done" looks like before starting.
- **Dependencies**: Use the `dependencies` field to link related tasks.
- **Documentation**: Link to relevant `docs/` or `site/` files in the `references` section.

## Resources

- [Task Structure Guide](references/task-structure.md): Detailed breakdown of the YAML frontmatter and markdown sections.
- `backlog://workflow/overview`: Project-specific backlog workflow overview.
