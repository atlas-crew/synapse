# Signal Horizon Component Audit
_Generated: 2026-02-12 18:53_

## Summary

**Total findings: 126**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 126 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 8 | `pages/beam/catalog/SchemaChangesPage.tsx` |
| 8 | `pages/beam/catalog/ApiCatalogPage.tsx` |
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
| 2 | `pages/fleet/FleetOverviewPage.tsx` |
| 1 | `pages/hunting/RequestTimelinePage.tsx` |
| 1 | `pages/fleet/sensor-detail/shared.tsx` |
| 1 | `pages/fleet/sensor-detail/PerformanceTab.tsx` |
| 1 | `pages/fleet/SensorDetailPage.tsx` |
| 1 | `pages/fleet/ConfigManagerPage.tsx` |
| 1 | `pages/IntelPage.tsx` |
| 1 | `pages/ApiIntelligencePage.tsx` |
| 1 | `components/fleet/SessionSearchResults.tsx` |
| 1 | `components/api-intelligence/ViolationsFeed.tsx` |
| 1 | `components/api-intelligence/ApiTreemap.tsx` |

---

## Detailed Findings

### Stack (row+align+gap)
Tailwind flex + items-center + gap → use <Stack direction=row align=center>

| File | Line | Match |
|------|------|-------|
| `components/fleet/SessionSearchResults.tsx` | 314 | `<div className="flex items-center justify-end gap-2">` |
| `components/api-intelligence/ViolationsFeed.tsx` | 41 | `<span className="text-[10px] text-ink-muted flex items-center gap-1">` |
| `components/api-intelligence/ApiTreemap.tsx` | 139 | `<div key={service.name} className="flex items-center gap-2">` |
| `pages/WarRoomPage.tsx` | 118 | `<div className="flex items-center gap-3 mb-1">` |
| `pages/WarRoomPage.tsx` | 143 | `<div className="flex items-center gap-6">` |
| `pages/WarRoomPage.tsx` | 148 | `<div className="flex items-center gap-3">` |
| `pages/WarRoomPage.tsx` | 286 | `<div className="flex items-center gap-3">` |
| `pages/WarRoomPage.tsx` | 300 | `<div className="flex items-center gap-1.5 mt-2 text-[10px] font-mono text-ink-mu` |
| `pages/soc/SessionsPage.tsx` | 178 | `<div className="card-header flex flex-wrap items-center gap-3">` |
| `pages/soc/SessionsPage.tsx` | 180 | `<div className="ml-auto flex flex-wrap items-center gap-3">` |
| `pages/soc/SessionsPage.tsx` | 189 | `<label className="flex items-center gap-2 text-sm text-ink-secondary">` |
| `pages/soc/SessionsPage.tsx` | 286 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/SessionsPage.tsx` | 295 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/SessionsPage.tsx` | 321 | `<div className="card p-4 flex items-center gap-4">` |
| `pages/soc/CampaignsPage.tsx` | 168 | `<div className="card-header flex flex-wrap items-center gap-3">` |
| `pages/soc/CampaignsPage.tsx` | 280 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/CampaignsPage.tsx` | 288 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/CampaignsPage.tsx` | 312 | `<div className="card p-4 flex items-center gap-4">` |
| `pages/soc/ActorDetailPage.tsx` | 183 | `<div className="flex items-center gap-3">` |
| `pages/soc/ActorDetailPage.tsx` | 287 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/ActorDetailPage.tsx` | 296 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/LiveMapPage.tsx` | 17 | `<span className="inline-flex items-center gap-1">` |
| `pages/soc/LiveMapPage.tsx` | 34 | `<h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap` |
| `pages/soc/LiveMapPage.tsx` | 41 | `<h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap` |
| `pages/soc/LiveMapPage.tsx` | 48 | `<h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap` |
| `pages/soc/SessionDetailPage.tsx` | 139 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/SessionDetailPage.tsx` | 158 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/SessionDetailPage.tsx` | 167 | `<div className="flex items-center gap-2 text-sm text-ink-muted uppercase trackin` |
| `pages/soc/SessionDetailPage.tsx` | 188 | `<div key={`${alert.alertType}-${index}`} className="flex flex-wrap items-center ` |
| `pages/OverviewPage.tsx` | 325 | `<div className="flex items-center gap-3">` |

