# Signal Horizon Component Audit
_Generated: 2026-02-11 18:27_

## Summary

**Total findings: 423**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 423 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 19 | `pages/fleet/ReleasesPage.tsx` |
| 18 | `components/fleet/FileBrowser.tsx` |
| 17 | `pages/AdminSettingsPage.tsx` |
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
| 4 | `pages/beam/catalog/ServicesPage.tsx` |
| 4 | `pages/beam/analytics/TrafficAnalyticsPage.tsx` |

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
| `components/warroom/PlaybookSelector.tsx` | 109 | `<div className="flex items-center gap-2">` |
| `components/hunting/SigmaLeadsPanel.tsx` | 107 | `className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-in` |
| `components/hunting/SigmaLeadsPanel.tsx` | 144 | `<div className="ml-auto flex items-center gap-2">` |
| `components/hunting/SigmaRulesPanel.tsx` | 124 | `className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-in` |
| `components/hunting/SigmaRulesPanel.tsx` | 140 | `<div className="flex items-center gap-2">` |
| `components/hunting/SigmaRulesPanel.tsx` | 207 | `className="px-2 py-1 border border-border-subtle bg-surface-base text-xs text-a1` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 141 | `<div className="flex items-center gap-2">` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 146 | `className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-in` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 164 | `<div className="flex items-center gap-2">` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 189 | `<div className="ml-auto flex items-center gap-2">` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 227 | `<span className="inline-flex items-center gap-2">` |
| `components/hunting/BehavioralAnomaliesPanel.tsx` | 253 | `<div className="flex items-center gap-2">` |
| `components/hunting/ClickHouseOpsPanel.tsx` | 123 | `className="px-3 py-2 border border-border-subtle bg-surface-base text-sm text-in` |
| `components/hunting/ClickHouseOpsPanel.tsx` | 139 | `<div className="flex flex-wrap items-center gap-3">` |
| `components/hunting/ClickHouseOpsPanel.tsx` | 156 | `<div className="flex items-center gap-2 px-3 py-2 border-b border-border-subtle"` |
| `components/hunting/SavedQueries.tsx` | 111 | `<div className="flex items-center gap-2 flex-1 min-w-0">` |
| `components/hunting/SavedQueries.tsx` | 121 | `<div className="flex items-center gap-1 mt-0.5 text-xs text-ink-muted">` |
| `components/hunting/SavedQueries.tsx` | 130 | `<div className="flex items-center gap-1 shrink-0">` |
| `components/hunting/SavedQueries.tsx` | 171 | `<div className="flex items-center gap-4">` |

