# Signal Horizon Component Audit
_Generated: 2026-02-12 14:06_

## Summary

**Total findings: 343**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 343 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 18 | `components/fleet/FileBrowser.tsx` |
| 17 | `pages/AdminSettingsPage.tsx` |
| 12 | `pages/fleet/BandwidthDashboardPage.tsx` |
| 11 | `pages/beam/threats/ThreatActivityPage.tsx` |
| 11 | `components/fleet/SessionSearchResults.tsx` |
| 9 | `pages/fleet/sensor-detail/ConfigurationTab.tsx` |
| 9 | `pages/beam/threats/BlockedRequestsPage.tsx` |
| 9 | `pages/beam/threats/AttackPatternsPage.tsx` |
| 9 | `components/ui/CommandPalette.tsx` |
| 9 | `components/fleet/LogViewer.tsx` |
| 8 | `pages/beam/catalog/SchemaChangesPage.tsx` |
| 8 | `pages/beam/catalog/ApiCatalogPage.tsx` |
| 8 | `pages/beam/BeamDashboardPage.tsx` |
| 8 | `components/fleet/RolloutManager.tsx` |
| 8 | `components/LoadingStates.tsx` |
| 7 | `pages/fleet/RuleDistributionPage.tsx` |
| 7 | `pages/fleet/GlobalSessionSearchPage.tsx` |
| 7 | `components/fleet/SynapseConfigEditor.tsx` |
| 7 | `components/fleet/ServiceControlPanel.tsx` |
| 7 | `components/fleet/RemoteShell.tsx` |
| 6 | `pages/soc/SessionsPage.tsx` |
| 6 | `pages/beam/analytics/ErrorAnalysisPage.tsx` |
| 5 | `pages/fleet/SensorConfigPage.tsx` |
| 5 | `pages/fleet/OnboardingPage.tsx` |
| 5 | `pages/fleet/FleetHealthPage.tsx` |
| 5 | `pages/beam/analytics/ResponseTimesPage.tsx` |
| 5 | `pages/WarRoomPage.tsx` |
| 5 | `pages/OverviewPage.tsx` |
| 5 | `components/fleet/pingora/CrawlerConfig.tsx` |
| 4 | `pages/soc/SessionDetailPage.tsx` |
| 4 | `pages/soc/LiveMapPage.tsx` |
| 4 | `pages/soc/CampaignsPage.tsx` |
| 4 | `pages/fleet/SensorKeysPage.tsx` |
| 4 | `pages/beam/catalog/ServicesPage.tsx` |
| 4 | `pages/beam/analytics/TrafficAnalyticsPage.tsx` |
| 4 | `pages/SupportPage.tsx` |
| 4 | `components/fleet/pingora/EntityConfig.tsx` |
| 4 | `components/fleet/pingora/DlpConfig.tsx` |
| 3 | `pages/soc/CampaignDetailPage.tsx` |

---

## Detailed Findings

### Stack (row+align+gap)
Tailwind flex + items-center + gap → use <Stack direction=row align=center>

| File | Line | Match |
|------|------|-------|
| `components/ui/CommandPalette.tsx` | 573 | `<div className="flex items-center gap-1.5 px-2 py-1 border border-border-subtle ` |
| `components/ui/CommandPalette.tsx` | 600 | `<div className="flex items-center gap-2">` |
| `components/ui/CommandPalette.tsx` | 609 | `<span className="text-[8px] font-mono text-ink-muted/60 flex items-center gap-1"` |
| `components/ui/CommandPalette.tsx` | 636 | `<div className="flex items-center gap-4 min-w-0">` |
| `components/ui/CommandPalette.tsx` | 647 | `<div className="flex items-center gap-2 flex-shrink-0">` |
| `components/ui/CommandPalette.tsx` | 675 | `<div className="flex items-center gap-4">` |
| `components/ui/CommandPalette.tsx` | 676 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 682 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 689 | `<div className="flex items-center gap-1.5">` |
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
| `components/fleet/ServiceControlPanel.tsx` | 152 | `<div className="flex items-center gap-2">` |
| `components/fleet/ServiceControlPanel.tsx` | 181 | `<div className="flex items-center justify-center gap-1 text-xs text-ink-muted">` |
| `components/fleet/ServiceControlPanel.tsx` | 188 | `<div className="flex items-center justify-end gap-2 w-full">` |
| `components/fleet/ServiceControlPanel.tsx` | 472 | `<div className="flex items-center gap-1.5 text-xs text-ink-secondary">` |
| `components/fleet/ServiceControlPanel.tsx` | 482 | `<div className="flex items-center gap-2">` |
| `components/fleet/ServiceControlPanel.tsx` | 493 | `<div className="flex items-center gap-2">` |
| `components/fleet/ServiceControlPanel.tsx` | 622 | `<div className="flex items-center justify-center gap-2 py-2 px-3 bg-status-warni` |
| `components/fleet/SensorTable.tsx` | 79 | `<div className="flex items-center gap-2">` |
| `components/fleet/SynapseConfigEditor.tsx` | 364 | `<div className="flex items-center gap-2 mb-4">` |

