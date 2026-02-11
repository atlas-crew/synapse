# Signal Horizon Component Audit
_Generated: 2026-02-11 13:19_

## Summary

**Total findings: 539**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 487 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |
| Stack (row+justify+gap) | 27 | Tailwind flex + justify-between + gap → use <Stack direction=row justify=space-between> |
| Stack (col+gap) | 25 | Tailwind flex-col + gap → use <Stack direction=column> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 21 | `pages/AdminSettingsPage.tsx` |
| 21 | `components/fleet/FileBrowser.tsx` |
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 17 | `pages/fleet/sensor-detail/ConfigurationTab.tsx` |
| 16 | `App.tsx` |
| 12 | `pages/fleet/BandwidthDashboardPage.tsx` |
| 12 | `components/fleet/DiagnosticsPanel.tsx` |
| 11 | `pages/beam/threats/ThreatActivityPage.tsx` |
| 11 | `components/fleet/SessionSearchResults.tsx` |
| 11 | `components/fleet/RemoteShell.tsx` |
| 10 | `components/fleet/WebTerminal.tsx` |
| 10 | `components/fleet/ServiceControlPanel.tsx` |
| 10 | `components/LoadingStates.tsx` |
| 9 | `pages/fleet/SensorConfigPage.tsx` |
| 9 | `pages/beam/threats/BlockedRequestsPage.tsx` |
| 9 | `pages/beam/threats/AttackPatternsPage.tsx` |
| 9 | `components/ui/CommandPalette.tsx` |
| 9 | `components/hunting/BehavioralAnomaliesPanel.tsx` |
| 9 | `components/fleet/LogViewer.tsx` |
| 8 | `pages/beam/catalog/SchemaChangesPage.tsx` |
| 8 | `pages/beam/catalog/ApiCatalogPage.tsx` |
| 8 | `pages/beam/BeamDashboardPage.tsx` |
| 8 | `components/fleet/RolloutManager.tsx` |
| 7 | `pages/fleet/RuleDistributionPage.tsx` |
| 7 | `pages/fleet/GlobalSessionSearchPage.tsx` |
| 7 | `pages/OverviewPage.tsx` |
| 7 | `components/hunting/HuntResultsTable.tsx` |
| 7 | `components/hunting/HuntQueryBuilder.tsx` |
| 7 | `components/fleet/SynapseConfigEditor.tsx` |
| 6 | `pages/soc/SessionsPage.tsx` |
| 6 | `pages/beam/analytics/ErrorAnalysisPage.tsx` |
| 6 | `pages/WarRoomPage.tsx` |
| 6 | `pages/SupportPage.tsx` |
| 6 | `components/soc/CampaignGraph.tsx` |
| 6 | `components/AuthCoverageMap/AuthCoverageMap.tsx` |
| 5 | `pages/hunting/RequestTimelinePage.tsx` |
| 5 | `pages/fleet/OnboardingPage.tsx` |
| 5 | `pages/fleet/FleetHealthPage.tsx` |
| 5 | `pages/fleet/ConfigManagerPage.tsx` |
| 5 | `pages/beam/analytics/ResponseTimesPage.tsx` |

---

## Detailed Findings

### Stack (col+gap)
Tailwind flex-col + gap → use <Stack direction=column>

| File | Line | Match |
|------|------|-------|
| `App.tsx` | 551 | `<div className="flex flex-col items-center gap-2">` |
| `components/ui/Toast.tsx` | 86 | `className="fixed top-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none"` |
| `components/AdminSettingsSkeleton.tsx` | 12 | `<div className="flex flex-col lg:flex-row gap-8">` |
| `components/warroom/PlaybookRunner.tsx` | 109 | `<div key={index} className="flex flex-col gap-2">` |
| `components/AuthCoverageMap/AuthCoverageMap.tsx` | 148 | `<div className="p-4 border-b border-border-subtle flex flex-col md:flex-row md:i` |
| `components/fleet/WebTerminal.tsx` | 264 | `<div className="flex flex-col items-center gap-3">` |
| `components/fleet/WebTerminal.tsx` | 273 | `<div className="flex flex-col items-center gap-3 max-w-md text-center">` |
| `components/fleet/ServiceControlPanel.tsx` | 454 | `<div className={clsx('flex items-center justify-between', compact && 'flex-col i` |
| `components/fleet/RemoteShell.tsx` | 386 | `<div className="flex flex-col items-center gap-3">` |
| `components/fleet/RemoteShell.tsx` | 400 | `<div className="flex flex-col items-center gap-3 max-w-md text-center">` |
| `components/fleet/EmbeddedDashboard.tsx` | 233 | `<div className="flex flex-col items-center gap-3">` |
| `components/fleet/FileBrowser.tsx` | 376 | `<div className="flex flex-col gap-1 p-2 bg-surface-subtle">` |
| `components/LoadingStates.tsx` | 170 | `className="flex flex-col items-center justify-center gap-3 py-8"` |
| `pages/OverviewPage.tsx` | 497 | `<div key={a.label} className="flex flex-col gap-1.5">` |
| `pages/OverviewPage.tsx` | 540 | `<div key={f.label} className="flex flex-col gap-1.5">` |
| `pages/SupportPage.tsx` | 997 | `<div className="flex flex-col items-center justify-center h-64 gap-4">` |
| `pages/AdminSettingsPage.tsx` | 487 | `<div className="flex flex-col lg:flex-row gap-8">` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 288 | `<div className="flex flex-col items-center justify-center py-12 gap-4">` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 339 | `<div className="flex flex-col items-center justify-center py-12 gap-4">` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 497 | `<div className="flex flex-col items-center justify-center py-8 gap-3">` |
| `pages/fleet/sensor-detail/NetworkTab.tsx` | 26 | `<div key={idx} className="flex-1 flex flex-col gap-px">` |
| `pages/fleet/ConnectivityPage.tsx` | 480 | `<div className="flex flex-col md:flex-row md:items-end gap-3 mb-4">` |
| `pages/fleet/SensorConfigPage.tsx` | 189 | `<div className="p-12 flex flex-col items-center justify-center gap-4">` |
| `pages/fleet/SensorConfigPage.tsx` | 274 | `<div className="h-full p-6 flex flex-col gap-4">` |
| `pages/fleet/ConfigManagerPage.tsx` | 1239 | `<div className="flex-1 overflow-hidden flex flex-col gap-3 min-h-0">` |

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

### Stack (row+justify+gap)
Tailwind flex + justify-between + gap → use <Stack direction=row justify=space-between>

| File | Line | Match |
|------|------|-------|
| `components/soc/CampaignGraph.tsx` | 344 | `<div key={key} className="flex justify-between gap-4 text-[11px]">` |
| `components/warroom/PlaybookRunner.tsx` | 125 | `<div className="flex-1 flex items-center justify-between gap-4">` |
| `components/hunting/SigmaLeadsPanel.tsx` | 84 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/SigmaRulesPanel.tsx` | 101 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 122 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 238 | `<div className="flex items-center justify-between gap-3">` |
| `components/hunting/ClickHouseOpsPanel.tsx` | 100 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/RecentRequestsPanel.tsx` | 68 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/LowAndSlowPanel.tsx` | 76 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/FleetIntelligencePanel.tsx` | 88 | `<div className="flex items-start justify-between gap-4 p-4 border-b border-borde` |
| `components/hunting/RequestTimelineGraph.tsx` | 111 | `<div className="flex items-center justify-between gap-3">` |
| `components/hunting/RequestTimelineGraph.tsx` | 227 | `<div className="flex items-start justify-between gap-3">` |
| `components/AuthCoverageMap/AuthCoverageMap.tsx` | 148 | `<div className="p-4 border-b border-border-subtle flex flex-col md:flex-row md:i` |
| `components/fleet/ServiceControlPanel.tsx` | 454 | `<div className={clsx('flex items-center justify-between', compact && 'flex-col i` |
| `components/fleet/FileBrowser.tsx` | 377 | `<div className="flex items-center justify-between gap-2">` |
| `pages/WarRoomPage.tsx` | 361 | `<div className="flex items-end justify-between gap-4">` |
| `pages/hunting/RequestTimelinePage.tsx` | 214 | `<div className="card-header flex items-center justify-between gap-4">` |
| `pages/hunting/RequestTimelinePage.tsx` | 368 | `<div className="card-header flex items-center justify-between gap-4">` |
| `pages/AdminSettingsPage.tsx` | 858 | `<div className="flex items-start justify-between gap-4">` |
| `pages/AdminSettingsPage.tsx` | 1482 | `<div className="flex items-center justify-between gap-4">` |
| `pages/fleet/sensor-detail/OverviewTab.tsx` | 286 | `className="flex items-center justify-between gap-4 border border-border-subtle b` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 232 | `<div className="flex justify-between items-center gap-4 p-4 bg-surface-inset">` |
| `pages/fleet/ConnectivityPage.tsx` | 525 | `<div className="flex items-start justify-between gap-3">` |
| `pages/fleet/SensorConfigPage.tsx` | 283 | `<div className="border border-border-subtle bg-surface-card p-4 flex items-start` |
| `pages/fleet/ConfigManagerPage.tsx` | 974 | `<div key={log.id} className="p-4 flex items-start justify-between gap-4">` |
| `pages/fleet/ConfigManagerPage.tsx` | 1175 | `<div className="flex items-center justify-between gap-4 mb-2">` |
| `pages/fleet/SensorDetailPage.tsx` | 163 | `<div className="flex items-start justify-between gap-6 p-6 bg-surface-inset">` |

