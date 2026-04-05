---
id: TASK-21
title: Add Defense posture management to Horizon
status: Done
assignee: []
created_date: '2026-04-03 18:31'
updated_date: '2026-04-05 07:05'
labels:
  - apparatus
  - defense
  - api
  - ui
milestone: m-3
dependencies:
  - TASK-9
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus defense features (tarpit, honeypot, MTD) for centralized management from Horizon:

**API routes:**
- `GET /api/v1/apparatus/defense/tarpit` — list trapped IPs
- `POST /api/v1/apparatus/defense/tarpit/:ip/release` — release an IP
- `GET /api/v1/apparatus/defense/deception` — honeypot event history
- `GET /api/v1/apparatus/defense/mtd` — MTD status (enabled, profile, rotation schedule)
- `POST /api/v1/apparatus/defense/mtd/rotate` — force MTD profile rotation

**UI:**
- Defense dashboard showing tarpit status, trapped IP count, recent honeypot hits
- Tarpit management table with release controls
- Deception event timeline (honeypot_hit, shell_command, sqli_probe)
- MTD status card with rotation controls

This complements the existing DLP Dashboard page under Fleet Operations.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
API routes done — defense (tarpit-list/tarpit-release/deception-history/mtd-status/mtd-rotate). UI deferred to future iteration.
<!-- SECTION:NOTES:END -->
