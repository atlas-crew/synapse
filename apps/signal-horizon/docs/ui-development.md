# UI Development Guide

The Signal Horizon UI is a modern, real-time dashboard built with React, Vite, and Tailwind CSS. It follows the Atlas Crew brand system.

## Tech Stack

- **React 19**: Frontend framework.
- **Vite**: Build tool and dev server.
- **Tailwind CSS**: Utility-first styling.
- **Zustand**: Lightweight state management.
- **Recharts**: Data visualization and charts.
- **Lucide React**: Icon library.
- **Framer Motion**: Smooth UI transitions and animations.

## Architecture

### 1. State Management (Zustand)
Global state is managed using focused stores in `ui/src/stores/`:
- `horizonStore.ts`: Core application state (campaigns, threats, dashboard snapshots).
- `fleetStore.ts`: Fleet-specific state (sensor metrics, sync status, command tracking).

### 2. Custom Hooks
Reusable logic is extracted into hooks in `ui/src/hooks/`:
- `useWebSocket.ts`: Manages the connection to the Dashboard Gateway, including auth and topic subscription.
- `useFleetMetrics.ts`: Periodically fetches aggregated fleet data.
- `useSensors.ts`: Handles sensor list filtering and pagination.

### 3. Components
- `ui/src/components/`: Shared, atomic UI components (Buttons, Cards, Modals).
- `ui/src/pages/`: Page-level components that wire together hooks and stores.

## Brand Integration

Signal Horizon strictly adheres to the **Atlas Crew Brand Guidelines**.

### Design Principles
- **No Rounded Corners**: All buttons, cards, and inputs must have `border-radius: 0`.
- **Typography**: Uses the **Rubik** font family.
  - Headlines: Rubik Light (300).
  - Body: Rubik Regular (400).
  - UI Labels/Buttons: Rubik Medium (500).
- **Color Palette**:
  - Primary Blue: `#0057B7`.
  - Navy: `#001E62`.
  - Accent Magenta: `#D62598` (used sparingly for highlights).

### Tailwind Configuration
The brand system is baked into `ui/tailwind.config.js` via custom theme extensions.

```javascript
// Example theme extension
theme: {
  extend: {
    colors: {
      'ac-blue': '#0057B7',
      'ac-navy': '#001E62',
      'ac-magenta': '#D62598',
    },
    borderRadius: {
      'none': '0',
    }
  }
}
```

## Development Workflow

### Adding a New Page
1. Create the page component in `ui/src/pages/`.
2. Define the route in `ui/src/routes/` (or add to `App.tsx`).
3. If real-time data is needed, use the `useWebSocket` hook to subscribe to the relevant topic.

### Testing
We use **Vitest** and **React Testing Library**.
- Run tests: `npm run test`
- Location: Look for `.test.tsx` files alongside components.

## Data Visualization Guidelines
- Use **Recharts** for all graphs.
- P50/P90/P99 latencies should use consistent colors across all charts.
- Dark theme support is mandatory for all visualization components.
