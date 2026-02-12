# Signal Horizon Component Audit
_Generated: 2026-02-12 14:54_

## Summary

**Total findings: 268**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 268 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 18 | `components/fleet/FileBrowser.tsx` |
| 17 | `pages/AdminSettingsPage.tsx` |
| 12 | `pages/fleet/BandwidthDashboardPage.tsx` |
| 11 | `pages/beam/threats/ThreatActivityPage.tsx` |
| 9 | `pages/fleet/sensor-detail/ConfigurationTab.tsx` |
| 9 | `pages/beam/threats/BlockedRequestsPage.tsx` |
| 9 | `pages/beam/threats/AttackPatternsPage.tsx` |
| 9 | `components/fleet/LogViewer.tsx` |
| 8 | `pages/beam/catalog/SchemaChangesPage.tsx` |
| 8 | `pages/beam/catalog/ApiCatalogPage.tsx` |
| 8 | `pages/beam/BeamDashboardPage.tsx` |
| 8 | `components/fleet/RolloutManager.tsx` |
| 8 | `components/LoadingStates.tsx` |
| 7 | `pages/fleet/RuleDistributionPage.tsx` |
| 7 | `pages/fleet/GlobalSessionSearchPage.tsx` |
| 6 | `pages/soc/SessionsPage.tsx` |
| 6 | `pages/beam/analytics/ErrorAnalysisPage.tsx` |
| 5 | `pages/fleet/SensorConfigPage.tsx` |
| 5 | `pages/fleet/OnboardingPage.tsx` |
| 5 | `pages/fleet/FleetHealthPage.tsx` |
| 5 | `pages/beam/analytics/ResponseTimesPage.tsx` |
| 5 | `pages/WarRoomPage.tsx` |
| 5 | `pages/OverviewPage.tsx` |
| 4 | `pages/soc/SessionDetailPage.tsx` |
| 4 | `pages/soc/LiveMapPage.tsx` |
| 4 | `pages/soc/CampaignsPage.tsx` |
| 4 | `pages/fleet/SensorKeysPage.tsx` |
| 4 | `pages/beam/catalog/ServicesPage.tsx` |
| 4 | `pages/beam/analytics/TrafficAnalyticsPage.tsx` |
| 4 | `pages/SupportPage.tsx` |
| 3 | `pages/soc/ActorDetailPage.tsx` |
| 3 | `pages/fleet/DlpDashboardPage.tsx` |
| 3 | `pages/fleet/CapacityForecastPage.tsx` |
| 3 | `pages/CampaignDetailPage.tsx` |
| 2 | `pages/fleet/sensor-detail/OverviewTab.tsx` |
| 2 | `pages/fleet/FleetUpdatesPage.tsx` |
| 2 | `pages/fleet/FleetOverviewPage.tsx` |
| 2 | `components/warroom/PlaybookRunner.tsx` |
| 1 | `pages/hunting/RequestTimelinePage.tsx` |

---

## Detailed Findings

### Stack (row+align+gap)
Tailwind flex + items-center + gap → use <Stack direction=row align=center>

| File | Line | Match |
|------|------|-------|
| `components/warroom/PlaybookRunner.tsx` | 81 | `<h3 className="font-medium text-ac-blue flex items-center gap-2">` |
| `components/warroom/PlaybookRunner.tsx` | 110 | `<div className="flex items-center gap-3">` |
| `components/warroom/PlaybookSelector.tsx` | 20 | `<div className="flex items-center gap-2">` |
| `components/fleet/LogViewer.tsx` | 389 | `<div className="flex items-center gap-3">` |
| `components/fleet/LogViewer.tsx` | 394 | `<div className="flex items-center gap-1.5">` |
| `components/fleet/LogViewer.tsx` | 409 | `<div className="flex items-center gap-2">` |
| `components/fleet/LogViewer.tsx` | 435 | `<div className="flex items-center gap-3">` |
| `components/fleet/LogViewer.tsx` | 485 | `<div className="flex items-center gap-4 mt-2 pt-2 border-t border-border-subtle"` |
| `components/fleet/LogViewer.tsx` | 489 | `className="flex items-center gap-1.5 cursor-pointer select-none"` |
| `components/fleet/LogViewer.tsx` | 507 | `<div className="flex items-center gap-2">` |
| `components/fleet/LogViewer.tsx` | 533 | `className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-se` |
| `components/fleet/LogViewer.tsx` | 543 | `className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-ink-se` |
| `components/fleet/SessionSearchResults.tsx` | 314 | `<div className="flex items-center justify-end gap-2">` |
| `components/fleet/RolloutManager.tsx` | 264 | `<div className="flex items-center gap-2">` |
| `components/fleet/RolloutManager.tsx` | 542 | `<div className="flex items-center gap-3">` |
| `components/fleet/RolloutManager.tsx` | 556 | `className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-status-err` |
| `components/fleet/RolloutManager.tsx` | 631 | `className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-s` |
| `components/fleet/RolloutManager.tsx` | 706 | `<div className="flex items-center gap-2">` |
| `components/fleet/RolloutManager.tsx` | 714 | `<div className="flex items-center gap-2">` |
| `components/fleet/RolloutManager.tsx` | 730 | `<div className="flex items-center gap-2">` |
| `components/fleet/RolloutManager.tsx` | 901 | `className="flex items-center gap-2 px-6 py-2 text-sm font-medium text-white bg-a` |
| `components/fleet/FileBrowser.tsx` | 190 | `<nav className="flex items-center gap-1 text-sm overflow-x-auto">` |
| `components/fleet/FileBrowser.tsx` | 193 | `className="flex items-center gap-1 px-2 py-1 hover:bg-surface-subtle text-ink-se` |
| `components/fleet/FileBrowser.tsx` | 204 | `<div key={partPath} className="flex items-center gap-1 shrink-0">` |
| `components/fleet/FileBrowser.tsx` | 274 | `<div className="flex items-center gap-2">` |
| `components/fleet/FileBrowser.tsx` | 304 | `<div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacit` |
| `components/fleet/FileBrowser.tsx` | 382 | `<div className="flex items-center gap-1 shrink-0">` |
| `components/fleet/FileBrowser.tsx` | 432 | `<span className="text-status-success flex items-center gap-1">` |
| `components/fleet/FileBrowser.tsx` | 506 | `<div className="flex items-center gap-2">` |
| `components/fleet/FileBrowser.tsx` | 756 | `<div className="flex items-center gap-3">` |

