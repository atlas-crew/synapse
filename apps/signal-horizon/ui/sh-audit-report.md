# Signal Horizon Component Audit
_Generated: 2026-02-11 14:08_

## Summary

**Total findings: 468**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 464 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |
| Stack (col+gap) | 4 | Tailwind flex-col + gap → use <Stack direction=column> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 18 | `pages/AdminSettingsPage.tsx` |
| 18 | `components/fleet/FileBrowser.tsx` |
| 16 | `App.tsx` |
| 12 | `pages/fleet/BandwidthDashboardPage.tsx` |
| 12 | `components/fleet/DiagnosticsPanel.tsx` |
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
| 7 | `components/hunting/HuntResultsTable.tsx` |
| 7 | `components/hunting/HuntQueryBuilder.tsx` |
| 7 | `components/fleet/SynapseConfigEditor.tsx` |
| 7 | `components/fleet/ServiceControlPanel.tsx` |
| 7 | `components/fleet/RemoteShell.tsx` |
| 6 | `pages/soc/SessionsPage.tsx` |
| 6 | `pages/beam/analytics/ErrorAnalysisPage.tsx` |
| 6 | `components/hunting/BehavioralAnomaliesPanel.tsx` |
| 6 | `components/fleet/WebTerminal.tsx` |
| 5 | `pages/fleet/SensorConfigPage.tsx` |
| 5 | `pages/fleet/OnboardingPage.tsx` |
| 5 | `pages/fleet/FleetHealthPage.tsx` |
| 5 | `pages/beam/analytics/ResponseTimesPage.tsx` |
| 5 | `pages/WarRoomPage.tsx` |
| 5 | `pages/OverviewPage.tsx` |
| 5 | `components/soc/CampaignGraph.tsx` |
| 5 | `components/fleet/pingora/CrawlerConfig.tsx` |
| 4 | `pages/soc/SessionDetailPage.tsx` |
| 4 | `pages/soc/LiveMapPage.tsx` |
| 4 | `pages/soc/CampaignsPage.tsx` |

---

## Detailed Findings

### Stack (col+gap)
Tailwind flex-col + gap → use <Stack direction=column>

| File | Line | Match |
|------|------|-------|
| `App.tsx` | 551 | `<div className="flex flex-col items-center gap-2">` |
| `components/AdminSettingsSkeleton.tsx` | 12 | `<div className="flex flex-col lg:flex-row gap-8">` |
| `pages/AdminSettingsPage.tsx` | 487 | `<div className="flex flex-col lg:flex-row gap-8">` |
| `pages/fleet/ConnectivityPage.tsx` | 481 | `<div className="flex flex-col md:flex-row md:items-end gap-3 mb-4">` |

### Stack (row+align+gap)
Tailwind flex + items-center + gap → use <Stack direction=row align=center>

| File | Line | Match |
|------|------|-------|
| `App.tsx` | 249 | `<div className="flex items-center gap-2.5">` |
| `App.tsx` | 337 | `<div className="flex items-center gap-6">` |
| `App.tsx` | 339 | `<div className="hidden lg:flex items-center gap-6">` |
| `App.tsx` | 340 | `<Link to="/campaigns" className="flex items-center gap-2 hover:text-white transi` |
| `App.tsx` | 348 | `<Link to="/" className="flex items-center gap-2 hover:text-white transition-colo` |
| `App.tsx` | 356 | `<Link to="/search" className="flex items-center gap-2 hover:text-white transitio` |
| `App.tsx` | 362 | `<Link to="/fleet" className="flex items-center gap-2 hover:text-white transition` |
| `App.tsx` | 371 | `<Link to="/fleet/connectivity" className="flex items-center gap-2 pl-4 border-l ` |
| `App.tsx` | 391 | `<div className="flex items-center gap-2">` |
| `App.tsx` | 394 | `className="flex items-center gap-2 px-3 h-8 bg-white/10 border border-white/20 h` |
| `App.tsx` | 408 | `className="hidden md:flex items-center gap-2 border border-white/20 px-2 h-8 tex` |
| `App.tsx` | 466 | `<div className={clsx('flex items-center', sidebarCollapsed ? 'justify-center' : ` |
| `App.tsx` | 551 | `<div className="flex flex-col items-center gap-2">` |
| `App.tsx` | 560 | `<div className="flex items-center gap-2 text-sm">` |
| `App.tsx` | 593 | `<div className="flex items-center gap-2 text-xs">` |
| `components/ui/CommandPalette.tsx` | 573 | `<div className="flex items-center gap-1.5 px-2 py-1 border border-border-subtle ` |
| `components/ui/CommandPalette.tsx` | 600 | `<div className="flex items-center gap-2">` |
| `components/ui/CommandPalette.tsx` | 609 | `<span className="text-[8px] font-mono text-ink-muted/60 flex items-center gap-1"` |
| `components/ui/CommandPalette.tsx` | 636 | `<div className="flex items-center gap-4 min-w-0">` |
| `components/ui/CommandPalette.tsx` | 647 | `<div className="flex items-center gap-2 flex-shrink-0">` |
| `components/ui/CommandPalette.tsx` | 675 | `<div className="flex items-center gap-4">` |
| `components/ui/CommandPalette.tsx` | 676 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 682 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 689 | `<div className="flex items-center gap-1.5">` |
| `components/ui/ShortcutHelpModal.tsx` | 37 | `<div className="flex items-center gap-1">` |
| `components/soc/CampaignGraph.tsx` | 314 | `<div className="flex items-center gap-3 text-ink-muted">` |
| `components/soc/CampaignGraph.tsx` | 357 | `<div className="flex items-center gap-1.5">` |
| `components/soc/CampaignGraph.tsx` | 361 | `<div className="flex items-center gap-1.5">` |
| `components/soc/CampaignGraph.tsx` | 365 | `<div className="flex items-center gap-1.5">` |
| `components/soc/CampaignGraph.tsx` | 369 | `<div className="flex items-center gap-1.5">` |

