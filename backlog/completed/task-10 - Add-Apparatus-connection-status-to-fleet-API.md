---
id: TASK-10
title: Add Apparatus connection status to fleet API
status: Done
assignee: []
created_date: '2026-04-03 18:29'
updated_date: '2026-04-03 20:17'
labels:
  - apparatus
  - api
milestone: m-0
dependencies:
  - TASK-9
priority: medium
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Expose Apparatus connection status through Horizon's existing fleet/management API. Add to the `/api/v1/management/integrations` response (or create it if it doesn't exist):

```json
{
  "apparatus": {
    "connected": true,
    "url": "http://apparatus:8090",
    "version": "0.9.1",
    "lastHealthCheck": "2026-04-03T..."
  }
}
```

The UI can use this to show Apparatus connection state in the admin panel and conditionally enable Apparatus features.
<!-- SECTION:DESCRIPTION:END -->
