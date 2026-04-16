import { Routes, Route, NavLink, Navigate, useLocation, Link } from 'react-router-dom';
import { useEffect, useCallback, Suspense, useMemo, useState, lazy } from 'react';
import {
  LayoutDashboard,
  Target,
  Users,
  Search,
  BarChart3,
  Shield,
  Wifi,
  WifiOff,
  Settings,
  Key,
  Sun,
  Moon,
  ChevronDown,
  ChevronRight,
  Activity,
  Package,
  Server,
  AlertTriangle,
  Bell,
  UserPlus,
  Globe,
  HelpCircle,
  PanelLeftClose,
  PanelLeftOpen,
  Cpu,
  GitBranch,
  Crosshair,
} from 'lucide-react';
import { clsx } from 'clsx';

import signalHorizonLogoDark from './assets/brand/signal-logo-dark.svg';
import synapseSidebarLockup from './assets/brand/synapse-sidebar-lockup.svg';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner, LoadingSpinner } from './components/LoadingStates';
import { ToastProvider } from './components/ui/Toast';
import { DemoModeControls } from './components/beam/DemoModeControls';
import { DemoTourModal } from './components/feedback/DemoTourModal';
import { useDemoLiveUpdates, useIsDemo, DEMO_HIDDEN_PATHS } from './stores/demoModeStore';
import { useApparatusStatus } from './hooks/useApparatusStatus';
import { SignalHorizonPageWrapper } from './components/signal/SignalHorizonPageWrapper';
import { CommandPalette } from './components/ui/CommandPalette';
import { ShortcutHelpModal } from './components/ui/ShortcutHelpModal';
import OverviewPage from './pages/OverviewPage';
import LiveMapPage from './pages/soc/LiveMapPage';
import CampaignsPage from './pages/soc/CampaignsPage';
import CampaignDetailPage from './pages/soc/CampaignDetailPage';
import ActorsPage from './pages/soc/ActorsPage';
import ActorDetailPage from './pages/soc/ActorDetailPage';
import SessionsPage from './pages/soc/SessionsPage';
import SessionDetailPage from './pages/soc/SessionDetailPage';
import SocSearchPage from './pages/soc/SocSearchPage';
import WarRoomPage from './pages/WarRoomPage';
import HuntingPage from './pages/HuntingPage';
import RequestTimelinePage from './pages/hunting/RequestTimelinePage';
import CampaignTimelinePage from './pages/hunting/CampaignTimelinePage';
import IntelPage from './pages/IntelPage';
import ApiIntelligencePage from './pages/ApiIntelligencePage';
import AdminSettingsPage from './pages/AdminSettingsPage';
import DesignLabPage from './pages/DesignLabPage';
import DesignSystemPage from './pages/DesignSystemPage';
const BreachDrillsPage = lazy(() => import('./pages/BreachDrillsPage'));
const AutopilotPage = lazy(() => import('./pages/AutopilotPage'));
const ScenariosPage = lazy(() => import('./pages/ScenariosPage'));
const SupplyChainPage = lazy(() => import('./pages/SupplyChainPage'));
const JwtTestingPage = lazy(() => import('./pages/JwtTestingPage'));
const RedTeamScannerPage = lazy(() => import('./pages/RedTeamScannerPage'));
const DlpScannerPage = lazy(() => import('./pages/DlpScannerPage'));
const AuthCoverageMap = lazy(() => import('./components/AuthCoverageMap/AuthCoverageMap.js'));
import CapacityForecastPage from './pages/fleet/CapacityForecastPage';
import { SupportPage } from './pages/SupportPage';
import { fleetRoutes } from './routes/fleet.routes';
import { beamRoutes } from './routes/beam.routes';
import { useWebSocket } from './hooks/useWebSocket';
import { useHorizonStore } from './stores/horizonStore';
import { Stack } from '@/ui';

// Threat Intelligence: observational / read-side views. These are the
// panels an analyst opens first thing in the morning to see what real
// attackers are actually doing.
const primaryNavItems = [
  { path: '/', icon: LayoutDashboard, label: 'Threat Overview' },
  { path: '/live-map', icon: Globe, label: 'Live Threat Map' },
  { path: '/campaigns', icon: Target, label: 'Campaigns' },
  { path: '/actors', icon: UserPlus, label: 'Actors' },
  { path: '/sessions', icon: Activity, label: 'Sessions' },
  { path: '/search', icon: Search, label: 'Global Search' },
  { path: '/hunting', icon: Search, label: 'Threat Hunting' },
  { path: '/intel', icon: BarChart3, label: 'Global Intel' },
  { path: '/api-intelligence', icon: Package, label: 'API Intelligence' },
  { path: '/auth-coverage', icon: Shield, label: 'Auth Coverage' },
  { path: '/warroom', icon: Users, label: 'War Room' },
];

// Active Defense: write-side / Apparatus-backed views. These are the
// panels where an operator *shapes* the system — proactively testing,
// simulating, or exercising defenses. Separated from Threat Intelligence
// because the mental model is different (you do things to the system
// here, you watch the system there) and because Apparatus is a
// coherent sub-product with its own backend.
const activeDefenseNavItems = [
  { path: '/drills', icon: Shield, label: 'Breach Drills' },
  { path: '/autopilot', icon: Cpu, label: 'Autopilot' },
  { path: '/supply-chain', icon: GitBranch, label: 'Supply Chain' },
  { path: '/jwt-testing', icon: Key, label: 'JWT Testing' },
  { path: '/redteam', icon: Crosshair, label: 'Red Team Scanner' },
];

const supportNavItems = [
  { path: '/support', icon: HelpCircle, label: 'Support & Docs' },
];

const fleetNavItems = [
  { path: '/fleet', icon: Server, label: 'Fleet Overview' },
  { path: '/fleet/config', icon: Settings, label: 'Fleet Configuration' },
  { path: '/fleet/dlp', icon: Shield, label: 'DLP Dashboard' },
  { path: '/dlp-scanner', icon: Shield, label: 'DLP Scanner' },
  { path: '/fleet/forecast', icon: BarChart3, label: 'Capacity Forecast' },
  { path: '/fleet/health', icon: Activity, label: 'Fleet Health' },
  { path: '/fleet/updates', icon: Package, label: 'Fleet Updates' },
  { path: '/scenarios', icon: Activity, label: 'Scenarios' },
  { path: '/fleet/rules', icon: Shield, label: 'Rule Distribution' },
  { path: '/fleet/connectivity', icon: Wifi, label: 'Connectivity' },
  { path: '/fleet/keys', icon: Key, label: 'API Keys' },
  { path: '/fleet/onboarding', icon: UserPlus, label: 'Onboarding' },
];

const beamNavItems = [
  { path: '/beam', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/beam/analytics', icon: BarChart3, label: 'Analytics' },
  { path: '/beam/catalog', icon: Package, label: 'API Catalog' },
  { path: '/beam/threats', icon: Target, label: 'Threats' },
];

const settingsNavItems = [
  { path: '/settings/admin', icon: Settings, label: 'Admin Settings' },
];

function getInitialTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'dark';
  const stored = window.localStorage.getItem('signal-horizon-theme');
  if (stored === 'light' || stored === 'dark') return stored;
  // Respect OS color scheme preference
  if (window.matchMedia?.('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function App() {
  const location = useLocation();
  const { connect, isConnected, connectionState } = useWebSocket();
  const sensorCount = useHorizonStore((s) => s.sensorStats.CONNECTED || 0);
  const campaigns = useHorizonStore((s) => s.campaigns);
  const threats = useHorizonStore((s) => s.threats);
  const alerts = useHorizonStore((s) => s.alerts);
  const timeRange = useHorizonStore((s) => s.timeRange);
  const setTimeRange = useHorizonStore((s) => s.setTimeRange);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => getInitialTheme());
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [isShortcutHelpOpen, setIsShortcutHelpOpen] = useState(false);
  const isDemo = useIsDemo();
  useDemoLiveUpdates();
  const { status: apparatusStatus } = useApparatusStatus();
  const [isTimeRangeOpen, setIsTimeRangeOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    if (typeof window === 'undefined') return false;
    return window.localStorage.getItem('signal-horizon-sidebar-collapsed') === 'true';
  });

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      window.localStorage.setItem('signal-horizon-sidebar-collapsed', String(next));
      return next;
    });
  }, []);

  // Collapsible nav sections - persisted to localStorage
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>(() => {
    if (typeof window === 'undefined') return {};
    try {
      const stored = window.localStorage.getItem('signal-horizon-sidebar-sections');
      return stored ? JSON.parse(stored) : {};
    } catch {
      return {};
    }
  });

  const toggleSection = useCallback((key: string) => {
    setCollapsedSections((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      window.localStorage.setItem('signal-horizon-sidebar-sections', JSON.stringify(next));
      return next;
    });
  }, []);

  const activeCampaigns = campaigns.filter((c) => c.status === 'ACTIVE').length;
  const criticalThreats = threats.filter((t) => t.riskScore >= 80).length;
  const unreadAlerts = alerts.filter((a) => a.timestamp > Date.now() - 3600000).length; // Last hour

  useEffect(() => {
    const timeout = window.setTimeout(() => {
      connect();
    }, 0);

    return () => {
      window.clearTimeout(timeout);
    };
  }, [connect]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    window.localStorage.setItem('signal-horizon-theme', theme);
  }, [theme]);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ctrl+B / Cmd+B: toggle sidebar
      if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
        e.preventDefault();
        toggleSidebar();
      }
      // Ctrl+K / Cmd+K: toggle CommandPalette
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setIsCommandPaletteOpen((prev) => !prev);
      }
      // ? : show shortcuts help
      if (
        e.key === '?' &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey &&
        !(e.target instanceof HTMLInputElement) &&
        !(e.target instanceof HTMLTextAreaElement) &&
        !(e.target instanceof HTMLSelectElement)
      ) {
        setIsShortcutHelpOpen(true);
      }
      // / : focus search (like GitHub) - only if not in an input
      if (
        e.key === '/' &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.altKey &&
        !(e.target instanceof HTMLInputElement) &&
        !(e.target instanceof HTMLTextAreaElement) &&
        !(e.target instanceof HTMLSelectElement)
      ) {
        e.preventDefault();
        setIsCommandPaletteOpen(true);
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [toggleSidebar]);

  const themeIcon = useMemo(() => (theme === 'dark' ? Sun : Moon), [theme]);
  const ThemeIcon = themeIcon;

  // Render a collapsible nav section with colored accent bar
  const renderCollapsibleSection = (
    key: string,
    label: string,
    items: typeof primaryNavItems,
    accent: string,
  ) => {
    const isSectionOpen = !collapsedSections[key];
    const hasActive = items.some((item) =>
      item.path === '/'
        ? location.pathname === '/'
        : location.pathname === item.path || location.pathname.startsWith(item.path + '/')
    );

    return (
      <div key={key} className="sidebar-nav-section">
        {!sidebarCollapsed ? (
          <button
            type="button"
            onClick={() => toggleSection(key)}
            aria-expanded={isSectionOpen}
            className="w-full flex items-center justify-between px-3 py-2 mb-0.5 group transition-colors hover:bg-surface-card focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50"
          >
            <Stack direction="row" align="center" style={{ gap: '10px' }}>
              <span
                className={clsx(
                  'w-0.5 h-3.5 flex-shrink-0 transition-opacity',
                  accent,
                  !isSectionOpen && !hasActive && 'opacity-30'
                )}
              />
              <span className="text-[10px] tracking-[0.2em] uppercase text-ink-secondary group-hover:text-ink-primary transition-colors font-medium">
                {label}
              </span>
              {!isSectionOpen && hasActive && (
                <span className={clsx('w-1.5 h-1.5 flex-shrink-0 animate-pulse', accent)} />
              )}
            </Stack>
            <ChevronRight
              className={clsx(
                'w-3 h-3 text-ink-muted transition-transform duration-200',
                isSectionOpen && 'rotate-90'
              )}
            />
          </button>
        ) : (
          <div className="flex justify-center py-2.5">
            <span className={clsx('w-5 h-px opacity-40', accent)} />
          </div>
        )}
        <div
          className="sidebar-section-content"
          data-collapsed={!sidebarCollapsed && !isSectionOpen ? 'true' : 'false'}
        >
          <div className="overflow-hidden">
            <div className="space-y-0.5">
              {items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  title={sidebarCollapsed ? item.label : undefined}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center py-2 text-sm transition-colors border-l-2 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50 overflow-hidden whitespace-nowrap',
                      sidebarCollapsed ? 'justify-center px-0' : 'gap-3 px-3',
                      isActive
                        ? 'bg-surface-card text-link border-link'
                        : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                    )
                  }
                >
                  <item.icon className="w-4 h-4 flex-shrink-0" />
                  {!sidebarCollapsed && <span>{item.label}</span>}
                </NavLink>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <ToastProvider>
    <div className="min-h-screen flex flex-col bg-surface-base text-ink-primary radar-sweep">
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
        theme={theme}
        setTheme={setTheme}
        toggleSidebar={toggleSidebar}
      />
      <ShortcutHelpModal
        isOpen={isShortcutHelpOpen}
        onClose={() => setIsShortcutHelpOpen(false)}
      />
      <DemoTourModal />
      {/* Skip to main content — WCAG 2.4.1 */}


      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:px-4 focus:py-2 focus:bg-ac-blue focus:text-white focus:outline-none"
      >
        Skip to main content
      </a>

      {/* Top Header - Command Bar with gradient depth
           Navy header maintains brand identity in both light and dark modes */}
      <header className="h-14 border-b border-ac-navy-light bg-ac-navy relative z-10 surface-hero-gradient edge-highlight">
        <div className="h-full px-4 flex items-center justify-between">
          <Stack direction="row" align="center" gap="lg">
            {/* Status Indicators - Tactical Display */}
            <Stack direction="row" align="center" gap="lg" className="!hidden lg:!flex">
              <Link to="/campaigns" className="hover:text-white transition-colors group">
                <Stack direction="row" align="center" gap="sm">
                  <span className={clsx('relative', activeCampaigns > 0 && 'threat-pulse')}>
                    <Target className={clsx('w-4 h-4 transition-colors', activeCampaigns > 0 ? 'text-ac-red' : 'text-white/70 group-hover:text-white')} />
                  </span>
                  <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                    <span className={clsx('font-semibold', activeCampaigns > 0 ? 'text-ac-red' : 'text-white')}>{activeCampaigns}</span> ACTIVE
                  </span>
                </Stack>
              </Link>
              <Link to="/" className="hover:text-white transition-colors group">
                <Stack direction="row" align="center" gap="sm">
                  <span className={clsx('relative', criticalThreats > 0 && 'status-blink')}>
                    <AlertTriangle className={clsx('w-4 h-4 transition-colors', criticalThreats > 0 ? 'text-ac-orange' : 'text-white/70 group-hover:text-white')} />
                  </span>
                  <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                    <span className={clsx('font-semibold', criticalThreats > 0 ? 'text-ac-orange' : 'text-white')}>{criticalThreats}</span> CRITICAL
                  </span>
                </Stack>
              </Link>
              <Link to="/search" className="hover:text-white transition-colors group">
                <Stack direction="row" align="center" gap="sm">
                  <Bell className={clsx('w-4 h-4 transition-colors', unreadAlerts > 0 ? 'text-ac-blue-tint' : 'text-white/70 group-hover:text-white')} />
                  <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                    <span className={clsx('font-semibold', unreadAlerts > 0 ? 'text-ac-blue-tint' : 'text-white')}>{unreadAlerts}</span> ALERTS
                  </span>
                </Stack>
              </Link>
              <Link to="/fleet" className="hover:text-white transition-colors group">
                <Stack direction="row" align="center" gap="sm">
                  <span className={clsx(sensorCount > 0 && 'status-blink')}>
                    <Server className={clsx('w-4 h-4 transition-colors', sensorCount > 0 ? 'text-ac-green' : 'text-white/70 group-hover:text-white')} />
                  </span>
                  <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                    <span className={clsx('font-semibold', sensorCount > 0 ? 'text-ac-green' : 'text-white')}>{sensorCount}</span> ONLINE
                  </span>
                </Stack>
              </Link>
              {/* API Connection Status */}
              <Link to="/fleet/connectivity" className="pl-4 border-l border-white/20 hover:text-white transition-colors group">
                <Stack direction="row" align="center" gap="sm">
                  {connectionState === 'connected' ? (
                    <Wifi className="w-4 h-4 text-status-success" />
                  ) : connectionState === 'connecting' ? (
                    <Wifi className="w-4 h-4 text-ac-orange animate-pulse" />
                  ) : (
                    <WifiOff className="w-4 h-4 text-ac-red" />
                  )}
                  <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                    <span className={clsx(
                      'font-semibold uppercase',
                      connectionState === 'connected' ? 'text-status-success' :
                      connectionState === 'connecting' ? 'text-ac-orange' : 'text-ac-red'
                    )}>
                      {connectionState === 'connected' ? 'HUB' : connectionState === 'connecting' ? 'CONNECTING' : 'OFFLINE'}
                    </span>
                  </span>
                </Stack>
              </Link>
              {/* Apparatus Connection Status */}
              {apparatusStatus.state !== 'disabled' && (
                <Link to="/settings/admin" className="hover:text-white transition-colors group">
                  <Stack direction="row" align="center" gap="sm">
                    <Target className={clsx('w-4 h-4', apparatusStatus.state === 'connected' ? 'text-ac-magenta' : 'text-white/40')} />
                    <span className="text-xs text-white/70 font-mono transition-colors group-hover:text-white">
                      <span className={clsx('font-semibold uppercase', apparatusStatus.state === 'connected' ? 'text-ac-magenta' : 'text-white/40')}>
                        APT
                      </span>
                    </span>
                  </Stack>
                </Link>
              )}
            </Stack>
          </Stack>
          <Stack direction="row" align="center" gap="sm">
            <button
              onClick={() => setIsCommandPaletteOpen(true)}
              className="px-3 h-8 bg-white/10 border border-white/20 hover:bg-white/20 transition-colors text-white hover:text-white mr-2"
              title="Open Command Palette (Ctrl+K)"
            >
              <Stack direction="row" align="center" gap="sm">
                <Search className="w-3.5 h-3.5" />
                <span className="text-[10px] uppercase tracking-widest font-bold">Search</span>
                <kbd className="ml-2 px-1.5 py-0.5 bg-white/10 border border-white/20 text-[9px] font-sans text-white/90">
                  {navigator.platform?.includes('Mac') ? '⌘K' : 'Ctrl+K'}
                </kbd>
              </Stack>
            </button>
            <DemoModeControls />
            <div className="relative">
              <button
                type="button"
                onClick={() => setIsTimeRangeOpen(!isTimeRangeOpen)}
                className="hidden md:flex border border-white/20 px-2 h-8 text-xs text-white/70 hover:bg-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
              >
                <Stack direction="row" align="center" gap="sm">
                  {(() => {
                    switch (timeRange) {
                      case '1h': return 'Last hour';
                      case '6h': return 'Last 6 hours';
                      case '24h': return 'Last 24 hours';
                      case '7d': return 'Last 7 days';
                      case '30d': return 'Last 30 days';
                      default: return timeRange;
                    }
                  })()}
                  <ChevronDown className={clsx("w-3 h-3 transition-transform", isTimeRangeOpen && "rotate-180")} />
                </Stack>
              </button>
              
              {isTimeRangeOpen && (
                <div className="absolute right-0 mt-1 w-40 bg-ac-card-dark border border-white/10 shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100 backdrop-blur-md">
                  {(['1h', '6h', '24h', '7d', '30d'] as const).map((range) => (
                    <button
                      key={range}
                      type="button"
                      onClick={() => {
                        setTimeRange(range);
                        setIsTimeRangeOpen(false);
                      }}
                      className={clsx(
                        "w-full text-left px-4 py-2.5 text-xs transition-all border-b border-white/5 last:border-0",
                        timeRange === range 
                          ? "bg-ac-blue text-white font-bold" 
                          : "text-white/60 hover:bg-white/10 hover:text-white"
                      )}
                    >
                      {range === '1h' ? 'Last hour' : 
                       range === '6h' ? 'Last 6 hours' : 
                       range === '24h' ? 'Last 24 hours' : 
                       range === '7d' ? 'Last 7 days' : 
                       'Last 30 days'}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="h-8 px-2 text-white/70 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
              aria-label="Toggle theme"
            >
              <ThemeIcon className="w-4 h-4" />
            </button>
          </Stack>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar with gradient depth */}
        <aside className={clsx('transition-all duration-200 bg-surface-subtle border-r border-border-subtle flex flex-col surface-sidebar relative', sidebarCollapsed ? 'w-16' : 'w-64')}>
          <div className={clsx('border-b border-border-subtle overflow-hidden flex items-center', sidebarCollapsed ? 'p-2 justify-center' : 'px-5 py-4')}>
            {sidebarCollapsed ? (
              <img
                src={signalHorizonLogoDark}
                alt="Signal Horizon"
                className="w-10 h-10"
              />
            ) : (
              <img
                src={synapseSidebarLockup}
                alt="Synapse Fleet"
                className="w-full max-w-[200px] h-auto"
              />
            )}
          </div>

          <nav aria-label="Main navigation" className={clsx('flex-1 py-4 overflow-y-auto', sidebarCollapsed ? 'px-1' : 'px-3')}>
            {renderCollapsibleSection('threat', 'Threat Intelligence', primaryNavItems, 'bg-ac-magenta')}
            {renderCollapsibleSection('sensor', 'Sensor Console', beamNavItems, 'bg-ac-sky')}
            {renderCollapsibleSection('fleet', 'Fleet Operations', isDemo ? fleetNavItems.filter((i) => !DEMO_HIDDEN_PATHS.has(i.path)) : fleetNavItems, 'bg-ac-green')}
            {renderCollapsibleSection('active-defense', 'Active Defense', activeDefenseNavItems, 'bg-ac-orange')}

            {!sidebarCollapsed && !isDemo && (
              <div className="sidebar-nav-section">
                <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2 mt-1">Settings</p>
                <div className="space-y-0.5">
                  {settingsNavItems.map((item) => (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      className={({ isActive }) =>
                        clsx(
                          'flex items-center py-2 text-sm transition-colors border-l-2 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50 overflow-hidden whitespace-nowrap gap-3 px-3',
                          isActive
                            ? 'bg-surface-card text-link border-link'
                            : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                        )
                      }
                    >
                      <item.icon className="w-4 h-4 flex-shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            )}

            <div className="sidebar-nav-section">
              {!sidebarCollapsed && <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2 mt-1">Support</p>}
              <div className="space-y-0.5">
                {supportNavItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    title={sidebarCollapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center py-2 text-sm transition-colors border-l-2 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50 overflow-hidden whitespace-nowrap',
                        sidebarCollapsed ? 'justify-center px-0' : 'gap-3 px-3',
                        isActive
                          ? 'bg-surface-card text-link border-link'
                          : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                      )
                    }
                  >
                    <item.icon className="w-4 h-4 flex-shrink-0" />
                    {!sidebarCollapsed && <span>{item.label}</span>}
                  </NavLink>
                ))}
              </div>
            </div>
          </nav>

          {/* Connection Status & Collapse Toggle */}
          <div className={clsx('border-t border-border-subtle', sidebarCollapsed ? 'p-2' : 'p-4')}>
            {sidebarCollapsed ? (
              <Stack direction="column" align="center" gap="sm">
                {isConnected ? (
                  <Wifi className="w-4 h-4 text-ac-green" />
                ) : (
                  <WifiOff className="w-4 h-4 text-ac-gray-mid" />
                )}
              </Stack>
            ) : (
              <>
                <Stack direction="row" align="center" gap="sm" className="text-sm">
                  {isConnected ? (
                    <>
                      <Wifi className="w-4 h-4 text-ac-green" />
                      <span className="text-ac-green">Connected</span>
                    </>
                  ) : (
                    <>
                      <WifiOff className="w-4 h-4 text-ac-gray-mid" />
                      <span className="text-ink-muted">
                        {connectionState === 'connecting' ? 'Connecting...' : 'Disconnected'}
                      </span>
                    </>
                  )}
                </Stack>
                <div className="mt-2 text-xs text-ink-muted">
                  {sensorCount} sensors online
                </div>
              </>
            )}
            <button
              type="button"
              onClick={toggleSidebar}
              className={clsx(
                'flex items-center justify-center text-ink-muted hover:text-ink-primary transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50',
                sidebarCollapsed ? 'w-full mt-2 py-1' : 'mt-3 w-full py-1'
              )}
              aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              title={sidebarCollapsed ? 'Expand sidebar (Ctrl+B)' : 'Collapse sidebar (Ctrl+B)'}
            >
              {sidebarCollapsed ? (
                <PanelLeftOpen className="w-4 h-4" />
              ) : (
                <Stack direction="row" align="center" gap="sm" className="text-xs">
                  <PanelLeftClose className="w-4 h-4" />
                  <span>Collapse</span>
                  <kbd className="ml-auto text-[10px] text-ink-muted border border-border-subtle px-1 py-0.5">
                    {navigator.platform?.includes('Mac') ? '\u2318' : 'Ctrl'}B
                  </kbd>
                </Stack>
              )}
            </button>
          </div>
        </aside>

        {/* Main Content */}
        <main id="main-content" className="flex-1 overflow-auto flex flex-col">
          <ConnectionBanner
            isConnected={isConnected}
            isReconnecting={connectionState === 'connecting'}
          />

          {/* Reset the global error boundary on navigation so sidebar links can recover after a bad page render. */}
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<LoadingSpinner message="Loading Signal Horizon..." size="lg" />}>
              <Routes>
                <Route path="/" element={<SignalHorizonPageWrapper><OverviewPage /></SignalHorizonPageWrapper>} />
                <Route path="/live-map" element={<SignalHorizonPageWrapper><LiveMapPage /></SignalHorizonPageWrapper>} />
                <Route path="/campaigns" element={<SignalHorizonPageWrapper><CampaignsPage /></SignalHorizonPageWrapper>} />
                <Route path="/campaigns/:id" element={<SignalHorizonPageWrapper><CampaignDetailPage /></SignalHorizonPageWrapper>} />
                <Route path="/actors" element={<SignalHorizonPageWrapper><ActorsPage /></SignalHorizonPageWrapper>} />
                <Route path="/actors/:id" element={<SignalHorizonPageWrapper><ActorDetailPage /></SignalHorizonPageWrapper>} />
                <Route path="/sessions" element={<SignalHorizonPageWrapper><SessionsPage /></SignalHorizonPageWrapper>} />
                <Route path="/sessions/:id" element={<SignalHorizonPageWrapper><SessionDetailPage /></SignalHorizonPageWrapper>} />
                <Route path="/search" element={<SignalHorizonPageWrapper><SocSearchPage /></SignalHorizonPageWrapper>} />
                <Route path="/warroom" element={<SignalHorizonPageWrapper><WarRoomPage /></SignalHorizonPageWrapper>} />
                <Route path="/warroom/:id" element={<SignalHorizonPageWrapper><WarRoomPage /></SignalHorizonPageWrapper>} />
                <Route path="/hunting" element={<SignalHorizonPageWrapper><HuntingPage /></SignalHorizonPageWrapper>} />
                <Route path="/hunting/request" element={<SignalHorizonPageWrapper><RequestTimelinePage /></SignalHorizonPageWrapper>} />
                <Route path="/hunting/request/:requestId" element={<SignalHorizonPageWrapper><RequestTimelinePage /></SignalHorizonPageWrapper>} />
                <Route path="/hunting/campaign/:campaignId?" element={<SignalHorizonPageWrapper><CampaignTimelinePage /></SignalHorizonPageWrapper>} />
                <Route path="/intel" element={<SignalHorizonPageWrapper><IntelPage /></SignalHorizonPageWrapper>} />
                <Route path="/api-intelligence" element={<SignalHorizonPageWrapper><ApiIntelligencePage /></SignalHorizonPageWrapper>} />
                <Route path="/auth-coverage" element={<Suspense fallback={<LoadingSpinner message="Loading auth coverage map..." size="lg" />}><SignalHorizonPageWrapper><AuthCoverageMap /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/fleet/forecast" element={<SignalHorizonPageWrapper><CapacityForecastPage /></SignalHorizonPageWrapper>} />
                <Route path="/support/:docId?" element={<SupportPage />} />
                <Route path="/settings/admin" element={<SignalHorizonPageWrapper><AdminSettingsPage /></SignalHorizonPageWrapper>} />
                <Route path="/drills" element={<Suspense fallback={<LoadingSpinner message="Loading breach drills..." size="lg" />}><SignalHorizonPageWrapper><BreachDrillsPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/autopilot" element={<Suspense fallback={<LoadingSpinner message="Loading autopilot..." size="lg" />}><SignalHorizonPageWrapper><AutopilotPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/scenarios" element={<Suspense fallback={<LoadingSpinner message="Loading scenarios..." size="lg" />}><SignalHorizonPageWrapper><ScenariosPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/supply-chain" element={<Suspense fallback={<LoadingSpinner message="Loading supply chain simulator..." size="lg" />}><SignalHorizonPageWrapper><SupplyChainPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/jwt-testing" element={<Suspense fallback={<LoadingSpinner message="Loading JWT testing..." size="lg" />}><SignalHorizonPageWrapper><JwtTestingPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/redteam" element={<Suspense fallback={<LoadingSpinner message="Loading red team scanner..." size="lg" />}><SignalHorizonPageWrapper><RedTeamScannerPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/dlp-scanner" element={<Suspense fallback={<LoadingSpinner message="Loading DLP scanner..." size="lg" />}><SignalHorizonPageWrapper><DlpScannerPage /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/design-lab" element={<DesignLabPage />} />
                <Route path="/design-system" element={<SignalHorizonPageWrapper><DesignSystemPage /></SignalHorizonPageWrapper>} />

                {fleetRoutes.map((route) => (
                  <Route key={route.path} path={route.path} element={route.element} />
                ))}
                {beamRoutes.map((route) => (
                  <Route key={route.path} path={route.path} element={route.element} />
                ))}
                
                {/* Fallback - MUST be last */}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
    </ToastProvider>
  );
}

export default App;
