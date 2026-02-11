# Signal Horizon Component Audit
_Generated: 2026-02-11 12:00_

## Summary

**Total findings: 624**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 487 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |
| Box | 33 | Raw styled div → use <Box> primitive |
| Stack (row+justify+gap) | 27 | Tailwind flex + justify-between + gap → use <Stack direction=row justify=space-between> |
| Stack (col+gap) | 25 | Tailwind flex-col + gap → use <Stack direction=column> |
| Tabs | 15 | Raw tab implementations → use <Tabs> |
| Stack (inline) | 15 | Inline flex style → use <Stack> primitive |
| Modal | 15 | Raw modal/overlay patterns → use <Modal> |
| Text | 7 | Raw styled text elements → use <Text> primitive |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 30 | `pages/AdminSettingsPage.tsx` |
| 22 | `pages/fleet/sensor-detail/ConfigurationTab.tsx` |
| 22 | `pages/fleet/ReleasesPage.tsx` |
| 22 | `components/fleet/FileBrowser.tsx` |
| 16 | `App.tsx` |
| 13 | `pages/fleet/BandwidthDashboardPage.tsx` |
| 12 | `components/fleet/DiagnosticsPanel.tsx` |
| 11 | `pages/soc/SessionsPage.tsx` |
| 11 | `pages/beam/threats/ThreatActivityPage.tsx` |
| 11 | `components/ui/CommandPalette.tsx` |
| 11 | `components/fleet/SessionSearchResults.tsx` |
| 11 | `components/fleet/ServiceControlPanel.tsx` |
| 11 | `components/fleet/RemoteShell.tsx` |
| 10 | `pages/soc/ActorsPage.tsx` |
| 10 | `pages/beam/threats/BlockedRequestsPage.tsx` |
| 10 | `pages/OverviewPage.tsx` |
| 10 | `components/fleet/WebTerminal.tsx` |
| 10 | `components/fleet/RolloutManager.tsx` |
| 10 | `components/fleet/LogViewer.tsx` |
| 10 | `components/LoadingStates.tsx` |
| 9 | `pages/soc/CampaignsPage.tsx` |
| 9 | `pages/fleet/SensorConfigPage.tsx` |
| 9 | `pages/fleet/FleetOverviewPage.tsx` |
| 9 | `pages/beam/threats/AttackPatternsPage.tsx` |
| 9 | `pages/beam/BeamDashboardPage.tsx` |
| 9 | `components/hunting/BehavioralAnomaliesPanel.tsx` |
| 8 | `pages/beam/catalog/SchemaChangesPage.tsx` |
| 8 | `pages/beam/catalog/ApiCatalogPage.tsx` |
| 7 | `pages/hunting/RequestTimelinePage.tsx` |
| 7 | `pages/fleet/SensorKeysPage.tsx` |
| 7 | `pages/fleet/RuleDistributionPage.tsx` |
| 7 | `pages/fleet/GlobalSessionSearchPage.tsx` |
| 7 | `pages/fleet/ConfigManagerPage.tsx` |
| 7 | `components/hunting/HuntResultsTable.tsx` |
| 7 | `components/hunting/HuntQueryBuilder.tsx` |
| 7 | `components/fleet/SynapseConfigEditor.tsx` |
| 6 | `pages/soc/SessionDetailPage.tsx` |
| 6 | `pages/soc/LiveMapPage.tsx` |
| 6 | `pages/beam/analytics/ErrorAnalysisPage.tsx` |
| 6 | `pages/WarRoomPage.tsx` |

---

## Detailed Findings

### Box
Raw styled div → use <Box> primitive

| File | Line | Match |
|------|------|-------|
| `components/fleet/LogViewer.tsx` | 120 | `<div style={style} className="group">` |
| `pages/soc/SocSearchPage.tsx` | 126 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/SocSearchPage.tsx` | 128 | `<div style={{ width: 180 }}>` |
| `pages/soc/SessionsPage.tsx` | 131 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/SessionsPage.tsx` | 133 | `<div style={{ width: 180 }}>` |
| `pages/soc/SessionsPage.tsx` | 181 | `<div style={{ width: 180 }}>` |
| `pages/soc/SessionsPage.tsx` | 203 | `{error && <div style={{ color: colors.red }}>Failed to load sessions.</div>}` |
| `pages/soc/CampaignsPage.tsx` | 129 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/CampaignsPage.tsx` | 131 | `<div style={{ width: 180 }}>` |
| `pages/soc/CampaignsPage.tsx` | 178 | `<div style={{ width: 180 }}>` |
| `pages/soc/CampaignsPage.tsx` | 191 | `{error && <div style={{ color: colors.red }}>Failed to load campaigns.</div>}` |
| `pages/soc/ActorDetailPage.tsx` | 158 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/ActorsPage.tsx` | 105 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/ActorsPage.tsx` | 107 | `<div style={{ width: 180 }}>` |
| `pages/soc/ActorsPage.tsx` | 147 | `<div style={{ width: 160 }}>` |
| `pages/soc/ActorsPage.tsx` | 155 | `<div style={{ width: 180 }}>` |
| `pages/soc/ActorsPage.tsx` | 163 | `<div style={{ width: 96 }}>` |
| `pages/soc/ActorsPage.tsx` | 177 | `{error && <div style={{ color: colors.red }}>Failed to load actors.</div>}` |
| `pages/soc/LiveMapPage.tsx` | 15 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/SessionDetailPage.tsx` | 108 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/CampaignDetailPage.tsx` | 213 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/OverviewPage.tsx` | 295 | `<div style={{ display: 'flex', gap: '8px' }}>` |
| `pages/ApiIntelligencePage.tsx` | 169 | `<div style={{ width: 320 }}>` |
| `pages/hunting/RequestTimelinePage.tsx` | 161 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/hunting/CampaignTimelinePage.tsx` | 123 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/CampaignDetailPage.tsx` | 126 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/fleet/FleetOverviewPage.tsx` | 218 | `<div style={{ display: 'flex', gap: spacing.sm }}>` |
| `pages/fleet/FleetOverviewPage.tsx` | 322 | `<div style={{ width: 260 }}>` |
| `pages/fleet/FleetOverviewPage.tsx` | 331 | `<div style={{ width: 160 }}>` |
| `pages/fleet/FleetOverviewPage.tsx` | 445 | `<div style={{ width: `${onlinePct}%`, background: colors.status.success }} />` |

### Text
Raw styled text elements → use <Text> primitive

| File | Line | Match |
|------|------|-------|
| `components/ui/PersistentTooltip.tsx` | 152 | `<p style={{ ...tooltipDefaults.labelStyle, margin: '0 0 4px' }}>` |
| `components/beam/analytics/StatusCodesDonut.tsx` | 68 | `<span style={{ fontFamily, fontSize: 12 }} className="text-ink-secondary">` |
| `pages/soc/LiveMapPage.tsx` | 17 | `<span style={{ display: 'inline-flex', alignItems: 'center', gap: spacing.xs }}>` |
| `pages/OverviewPage.tsx` | 447 | `<span style={{ color: colors.orange }}>Elevated</span>` |
| `pages/IntelPage.tsx` | 240 | `<span style={{ color: colors.red }}>{fp.hits.toLocaleString()} hits</span>` |
| `pages/beam/BeamDashboardPage.tsx` | 597 | `<span style={{ color: colors.green, fontSize: '14px' }}>Protected</span>` |
| `pages/fleet/BandwidthDashboardPage.tsx` | 607 | `<span style={{ color: colors.green }}>Live</span>` |

### Stack (inline)
Inline flex style → use <Stack> primitive

| File | Line | Match |
|------|------|-------|
| `components/ui/PersistentTooltip.tsx` | 162 | `display: 'flex',` |
| `pages/soc/SocSearchPage.tsx` | 126 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/SessionsPage.tsx` | 131 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/CampaignsPage.tsx` | 129 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/ActorDetailPage.tsx` | 158 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/ActorsPage.tsx` | 105 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/LiveMapPage.tsx` | 15 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/SessionDetailPage.tsx` | 108 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/soc/CampaignDetailPage.tsx` | 213 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/OverviewPage.tsx` | 295 | `<div style={{ display: 'flex', gap: '8px' }}>` |
| `pages/hunting/RequestTimelinePage.tsx` | 161 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/hunting/CampaignTimelinePage.tsx` | 123 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/CampaignDetailPage.tsx` | 126 | `<div style={{ display: 'flex', alignItems: 'center', gap: spacing.sm }}>` |
| `pages/fleet/FleetOverviewPage.tsx` | 218 | `<div style={{ display: 'flex', gap: spacing.sm }}>` |
| `pages/fleet/SensorDetailPage.tsx` | 109 | `<div style={{ marginTop: 16, display: 'flex', justifyContent: 'center' }}>` |

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
| `components/fleet/ServiceControlPanel.tsx` | 475 | `<div className={clsx('flex items-center justify-between', compact && 'flex-col i` |
| `components/fleet/RemoteShell.tsx` | 386 | `<div className="flex flex-col items-center gap-3">` |
| `components/fleet/RemoteShell.tsx` | 400 | `<div className="flex flex-col items-center gap-3 max-w-md text-center">` |
| `components/fleet/EmbeddedDashboard.tsx` | 232 | `<div className="flex flex-col items-center gap-3">` |
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
| `pages/fleet/ConfigManagerPage.tsx` | 1253 | `<div className="flex-1 overflow-hidden flex flex-col gap-3 min-h-0">` |

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
| `components/ui/CommandPalette.tsx` | 569 | `<div className="flex items-center gap-1.5 px-2 py-1 border border-border-subtle ` |
| `components/ui/CommandPalette.tsx` | 596 | `<div className="flex items-center gap-2">` |
| `components/ui/CommandPalette.tsx` | 605 | `<span className="text-[8px] font-mono text-ink-muted/60 flex items-center gap-1"` |
| `components/ui/CommandPalette.tsx` | 632 | `<div className="flex items-center gap-4 min-w-0">` |
| `components/ui/CommandPalette.tsx` | 643 | `<div className="flex items-center gap-2 flex-shrink-0">` |
| `components/ui/CommandPalette.tsx` | 671 | `<div className="flex items-center gap-4">` |
| `components/ui/CommandPalette.tsx` | 672 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 678 | `<div className="flex items-center gap-1.5">` |
| `components/ui/CommandPalette.tsx` | 685 | `<div className="flex items-center gap-1.5">` |
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
| `components/fleet/ServiceControlPanel.tsx` | 475 | `<div className={clsx('flex items-center justify-between', compact && 'flex-col i` |
| `components/fleet/FileBrowser.tsx` | 377 | `<div className="flex items-center justify-between gap-2">` |
| `pages/WarRoomPage.tsx` | 361 | `<div className="flex items-end justify-between gap-4">` |
| `pages/hunting/RequestTimelinePage.tsx` | 214 | `<div className="card-header flex items-center justify-between gap-4">` |
| `pages/hunting/RequestTimelinePage.tsx` | 368 | `<div className="card-header flex items-center justify-between gap-4">` |
| `pages/AdminSettingsPage.tsx` | 878 | `<div className="flex items-start justify-between gap-4">` |
| `pages/AdminSettingsPage.tsx` | 1511 | `<div className="flex items-center justify-between gap-4">` |
| `pages/fleet/sensor-detail/OverviewTab.tsx` | 286 | `className="flex items-center justify-between gap-4 border border-border-subtle b` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 232 | `<div className="flex justify-between items-center gap-4 p-4 bg-surface-inset">` |
| `pages/fleet/ConnectivityPage.tsx` | 525 | `<div className="flex items-start justify-between gap-3">` |
| `pages/fleet/SensorConfigPage.tsx` | 283 | `<div className="border border-border-subtle bg-surface-card p-4 flex items-start` |
| `pages/fleet/ConfigManagerPage.tsx` | 974 | `<div key={log.id} className="p-4 flex items-start justify-between gap-4">` |
| `pages/fleet/ConfigManagerPage.tsx` | 1189 | `<div className="flex items-center justify-between gap-4 mb-2">` |
| `pages/fleet/SensorDetailPage.tsx` | 163 | `<div className="flex items-start justify-between gap-6 p-6 bg-surface-inset">` |

### Modal
Raw modal/overlay patterns → use <Modal>

| File | Line | Match |
|------|------|-------|
| `components/ui/CommandPalette.tsx` | 533 | `<div className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh] ` |
| `components/ui/CommandPalette.tsx` | 538 | `className="fixed inset-0 bg-black/60 backdrop-blur-sm"` |
| `components/fleet/ServiceControlPanel.tsx` | 150 | `<div className="fixed inset-0 z-50 flex items-center justify-center p-4">` |
| `components/fleet/RolloutManager.tsx` | 616 | `<div className="fixed inset-0 z-50 flex items-center justify-center p-4">` |
| `components/fleet/EmbeddedDashboard.tsx` | 142 | `state.fullscreen && 'fixed inset-0 z-50'` |
| `components/fleet/FileBrowser.tsx` | 481 | `<div className="fixed inset-0 z-50 flex items-center justify-center p-4">` |
| `pages/beam/threats/BlockedRequestsPage.tsx` | 284 | `className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4"` |
| `pages/fleet/ReleasesPage.tsx` | 211 | `<div className="fixed inset-0 z-50 flex items-center justify-center p-4">` |
| `pages/fleet/ReleasesPage.tsx` | 451 | `<div className="fixed inset-0 z-50 flex items-center justify-center p-4">` |
| `pages/fleet/ReleasesPage.tsx` | 561 | `<div className="fixed inset-0 z-10" onClick={() => setShowMenu(false)} />` |
| `pages/fleet/SensorKeysPage.tsx` | 391 | `<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"` |
| `pages/fleet/SensorKeysPage.tsx` | 421 | `<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"` |
| `pages/fleet/SensorKeysPage.tsx` | 498 | `<div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"` |
| `pages/fleet/ConfigManagerPage.tsx` | 1000 | `className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50"` |
| `pages/fleet/ConfigManagerPage.tsx` | 1116 | `className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50"` |

### Tabs
Raw tab implementations → use <Tabs>

| File | Line | Match |
|------|------|-------|
| `pages/AdminSettingsPage.tsx` | 492 | `role="tablist"` |
| `pages/AdminSettingsPage.tsx` | 513 | `role="tab"` |
| `pages/AdminSettingsPage.tsx` | 558 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 792 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 1036 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 1207 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 1444 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 1841 | `role="tabpanel"` |
| `pages/AdminSettingsPage.tsx` | 2006 | `role="tabpanel"` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 273 | `<div role="tabpanel" id="tabpanel-config-drift" aria-labelledby="tab-config-drif` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 284 | `<div role="tabpanel" id="tabpanel-config-pingora" aria-labelledby="tab-config-pi` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 333 | `<div role="tabpanel" id="tabpanel-config-general" aria-labelledby="tab-config-ge` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 418 | `<div role="tabpanel" id="tabpanel-config-kernel" aria-labelledby="tab-config-ker` |
| `pages/fleet/sensor-detail/ConfigurationTab.tsx` | 492 | `<div role="tabpanel" id="tabpanel-config-history" aria-labelledby="tab-config-hi` |
| `pages/fleet/SensorDetailPage.tsx` | 224 | `<div role="tabpanel" id={`tabpanel-${activeTab}`} aria-labelledby={`tab-${active` |

