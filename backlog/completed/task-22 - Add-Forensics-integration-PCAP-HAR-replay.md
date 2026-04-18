---
id: TASK-22
title: Add Forensics integration (PCAP + HAR replay)
status: Done
assignee: []
created_date: '2026-04-03 18:31'
updated_date: '2026-04-05 07:05'
labels:
  - apparatus
  - forensics
  - api
  - ui
milestone: m-3
dependencies:
  - TASK-9
priority: low
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus forensics capabilities for incident investigation from Horizon:

**API routes:**
- `POST /api/v1/apparatus/forensics/pcap` — start packet capture (duration, filter, maxPackets)
- `POST /api/v1/apparatus/forensics/har/replay` — replay a HAR file against Apparatus

**UI:**
- PCAP capture controls in the Threat Hunting section (trigger capture, download results)
- HAR replay panel for re-executing recorded traffic during incident analysis
- Integration with the Request Timeline page for contextual forensics

Lower priority since this is specialized investigation tooling, but high value for advanced SOC operators doing deep-dive analysis.
<!-- SECTION:DESCRIPTION:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
API routes done — forensics (pcap/har-replay). UI deferred to future iteration.
<!-- SECTION:NOTES:END -->
