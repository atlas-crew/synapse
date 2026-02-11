# Signal Horizon Component Audit
_Generated: 2026-02-11 14:20_

## Summary

**Total findings: 456**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 456 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 18 | `components/fleet/FileBrowser.tsx` |
| 17 | `pages/AdminSettingsPage.tsx` |
| 14 | `App.tsx` |
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
| 5 | `components/fleet/pingora/CrawlerConfig.tsx` |
| 4 | `pages/soc/SessionDetailPage.tsx` |
| 4 | `pages/soc/LiveMapPage.tsx` |
| 4 | `pages/soc/CampaignsPage.tsx` |
| 4 | `pages/fleet/SensorKeysPage.tsx` |

---

## Detailed Findings

### Stack (row+align+gap)
Tailwind flex + items-center + gap → use <Stack direction=row align=center>

| File | Line | Match |
|------|------|-------|
| `App.tsx` | 250 | `<div className="flex items-center gap-2.5">` |
| `App.tsx` | 338 | `<div className="flex items-center gap-6">` |
| `App.tsx` | 340 | `<div className="hidden lg:flex items-center gap-6">` |
| `App.tsx` | 341 | `<Link to="/campaigns" className="flex items-center gap-2 hover:text-white transi` |
| `App.tsx` | 349 | `<Link to="/" className="flex items-center gap-2 hover:text-white transition-colo` |
| `App.tsx` | 357 | `<Link to="/search" className="flex items-center gap-2 hover:text-white transitio` |
| `App.tsx` | 363 | `<Link to="/fleet" className="flex items-center gap-2 hover:text-white transition` |
| `App.tsx` | 372 | `<Link to="/fleet/connectivity" className="flex items-center gap-2 pl-4 border-l ` |
| `App.tsx` | 392 | `<div className="flex items-center gap-2">` |
| `App.tsx` | 395 | `className="flex items-center gap-2 px-3 h-8 bg-white/10 border border-white/20 h` |
| `App.tsx` | 409 | `className="hidden md:flex items-center gap-2 border border-white/20 px-2 h-8 tex` |
| `App.tsx` | 467 | `<div className={clsx('flex items-center', sidebarCollapsed ? 'justify-center' : ` |
| `App.tsx` | 561 | `<div className="flex items-center gap-2 text-sm">` |
| `App.tsx` | 594 | `<div className="flex items-center gap-2 text-xs">` |
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
| `components/soc/ActiveCampaignList.tsx` | 85 | `<div className="flex items-center gap-3 mb-1">` |
| `components/soc/ActiveCampaignList.tsx` | 101 | `<div className="flex items-center gap-4 text-[10px] text-ink-muted group-hover:t` |
| `components/soc/ActiveCampaignList.tsx` | 104 | `<span className="flex items-center gap-1">` |
| `components/soc/ActiveCampaignList.tsx` | 111 | `<div className="flex items-center gap-4">` |
| `components/soc/LiveAttackMap.tsx` | 256 | `<div className="flex items-center gap-3">` |
| `components/soc/ThreatTrajectoryFeed.tsx` | 113 | `<div className="mt-2 flex items-center gap-3">` |

