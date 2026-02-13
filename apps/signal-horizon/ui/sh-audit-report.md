# Signal Horizon Component Audit
_Generated: 2026-02-12 19:25_

## Summary

**Total findings: 64**

### Findings by Component

| Component | Hits | Action |
|-----------|------|--------|
| Stack (row+align+gap) | 64 | Tailwind flex + items-center + gap → use <Stack direction=row align=center> |

### Files by Hit Count (Work Order)

Priority files to migrate first (most raw patterns):

| Hits | File |
|------|------|
| 5 | `pages/fleet/OnboardingPage.tsx` |
| 5 | `pages/beam/analytics/ResponseTimesPage.tsx` |
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
| `pages/ApiIntelligencePage.tsx` | 161 | `<div className="flex items-center gap-2">` |
| `pages/hunting/RequestTimelinePage.tsx` | 390 | `<div className="flex items-center gap-3">` |
| `pages/SupportPage.tsx` | 252 | `<div className="flex items-center gap-10">` |
| `pages/SupportPage.tsx` | 263 | `<nav className="flex items-center gap-2">` |
| `pages/SupportPage.tsx` | 1003 | `<div className="flex items-center gap-2 text-[10px] font-bold text-ink-muted upp` |
| `pages/SupportPage.tsx` | 1010 | `<div className="flex items-center gap-4 mb-10 pb-6 border-b border-border-subtle` |
| `pages/IntelPage.tsx` | 139 | `<div className="flex items-center gap-3">` |
| `pages/beam/catalog/ServicesPage.tsx` | 327 | `<div className="flex items-center gap-4">` |
| `pages/beam/catalog/ServicesPage.tsx` | 336 | `<div className="flex items-center gap-6">` |
| `pages/beam/catalog/ServicesPage.tsx` | 366 | `<div className={clsx('flex items-center gap-1', status.color)}>` |
| `pages/beam/catalog/ServicesPage.tsx` | 398 | `<div className="flex items-center gap-3">` |
| `pages/beam/analytics/ResponseTimesPage.tsx` | 179 | `<div className="flex items-center gap-4 text-sm">` |

