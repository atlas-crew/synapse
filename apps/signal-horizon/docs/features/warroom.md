# Feature: War Room

The War Room is a collaborative space for incident response, enabling analysts to investigate campaigns, take rapid action, and automate activity logging.

## Core Functionality

### 1. Collaboration Timeline
Every War Room has a persistent activity log that tracks:
- **Messages**: Manual notes and updates from analysts.
- **System Actions**: Automated logs when blocks are created or removed.
- **Campaign Links**: Tracking which campaigns are being investigated in this room.
- **Status Changes**: Changes in priority or room status.

### 2. Rapid Response (Quick Blocks)
Analysts can create blocklist entries directly from the War Room.
- **Contextual Blocking**: Blocks created here are automatically tagged with the War Room ID and the reason for the block.
- **Fleet-Wide Propagation**: Blocks can be pushed to the entire sensor fleet with a single click.

### 3. Campaign Association
Link one or more campaigns to a War Room to centralize all relevant threat intelligence.
- **Correlated View**: View all indicators (IPs, Fingerprints) across all linked campaigns in one place.
- **Timeline Integration**: New activity in linked campaigns is automatically logged in the War Room.

### 4. Horizon Bot Automation
The `@horizon-bot` provides automated assistance:
- **Auto-Creation**: High-severity campaigns can automatically trigger the creation of a War Room.
- **Summarization**: Periodic summaries of activity in the room.
- **Alerting**: Notifying external systems (Slack, PagerDuty) about War Room activity.

## Workflow

1. **Escalation**: A high-severity campaign is detected. An analyst clicks "Escalate to War Room".
2. **Investigation**: Analysts join the room, link additional related campaigns, and share findings via messages.
3. **Containment**: High-risk IPs identified during investigation are blocked via the "Quick Block" tool.
4. **Resolution**: Once the threat is contained, the War Room is marked as `CLOSED`. A final summary is generated for the post-mortem.

## API Integration

- `POST /api/v1/warrooms`: Create a new room.
- `POST /api/v1/warrooms/:id/messages`: Add a message to the timeline.
- `POST /api/v1/warrooms/:id/blocks`: Create a block from within the room.
- `GET /api/v1/warrooms/:id/activities`: Fetch the full history of the room.
