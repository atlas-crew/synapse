import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
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
} from 'lucide-react';
import { clsx } from 'clsx';

import signalHorizonLogoLight from './assets/brand/signal-logo-light.svg';
import signalHorizonLogoDark from './assets/brand/signal-logo-dark.svg';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner, LoadingSpinner } from './components/LoadingStates';
import { DemoModeControls } from './components/beam/DemoModeControls';
import { SignalHorizonPageWrapper } from './components/signal/SignalHorizonPageWrapper';
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
import IntelPage from './pages/IntelPage';
import ApiIntelligencePage from './pages/ApiIntelligencePage';
const AuthCoverageMap = lazy(() => import('./components/AuthCoverageMap/AuthCoverageMap.js'));
import CapacityForecastPage from './pages/fleet/CapacityForecastPage';
import { SupportPage } from './pages/SupportPage';
import { fleetRoutes } from './routes/fleet.routes';
import { beamRoutes } from './routes/beam.routes';
import { useWebSocket } from './hooks/useWebSocket';
import { useHorizonStore } from './stores/horizonStore';

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

const supportNavItems = [
  { path: '/support', icon: HelpCircle, label: 'Support & Docs' },
];

const fleetNavItems = [
  { path: '/fleet', icon: Server, label: 'Fleet Overview' },
  { path: '/fleet/config', icon: Settings, label: 'Fleet Configuration' },
  { path: '/fleet/dlp', icon: Shield, label: 'DLP Dashboard' },
  { path: '/fleet/forecast', icon: BarChart3, label: 'Capacity Forecast' },
  { path: '/fleet/health', icon: Activity, label: 'Fleet Health' },
  { path: '/fleet/updates', icon: Package, label: 'Fleet Updates' },
  { path: '/fleet/rules', icon: Shield, label: 'Rule Distribution' },
  { path: '/fleet/connectivity', icon: Wifi, label: 'Connectivity' },
  { path: '/fleet/keys', icon: Key, label: 'API Keys' },
  { path: '/fleet/onboarding', icon: UserPlus, label: 'Onboarding' },
];

const beamNavItems = [
  { path: '/beam', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/beam/analytics', icon: BarChart3, label: 'Analytics' },
  { path: '/beam/catalog', icon: Package, label: 'API Catalog' },
  { path: '/beam/rules', icon: Shield, label: 'Rules' },
  { path: '/beam/threats', icon: Target, label: 'Threats' },
];

const settingsItems = [
  { label: 'Sharing Preferences' },
  { label: 'Auto-Block Rules' },
  { label: 'API Access' },
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
  const { connect, isConnected, connectionState } = useWebSocket();
  const sensorCount = useHorizonStore((s) => s.sensorStats.CONNECTED || 0);
  const campaigns = useHorizonStore((s) => s.campaigns);
  const threats = useHorizonStore((s) => s.threats);
  const alerts = useHorizonStore((s) => s.alerts);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => getInitialTheme());
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
      // Ctrl+K / Cmd+K: focus search (placeholder for CommandPalette)
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        // CommandPalette not implemented yet - no-op
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
        // CommandPalette not implemented yet - no-op
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [toggleSidebar]);

  const themeIcon = useMemo(() => (theme === 'dark' ? Sun : Moon), [theme]);
  const ThemeIcon = themeIcon;

  return (
    <div className="min-h-screen flex flex-col bg-surface-base text-ink-primary radar-sweep">
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
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <span className="tracking-[0.2em] text-xs text-white/60">Atlas Crew</span>
            </div>
            {/* Status Indicators - Tactical Display */}
            <div className="hidden lg:flex items-center gap-6">
              <div className="flex items-center gap-2">
                <span className={clsx('relative', activeCampaigns > 0 && 'threat-pulse')}>
                  <Target className={clsx('w-4 h-4', activeCampaigns > 0 ? 'text-ac-magenta' : 'text-white/70')} />
                </span>
                <span className="text-xs text-white/70 font-mono">
                  <span className={clsx('font-semibold', activeCampaigns > 0 ? 'text-ac-magenta' : 'text-white')}>{activeCampaigns}</span> ACTIVE
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={clsx('relative', criticalThreats > 0 && 'status-blink')}>
                  <AlertTriangle className={clsx('w-4 h-4', criticalThreats > 0 ? 'text-ac-orange' : 'text-white/70')} />
                </span>
                <span className="text-xs text-white/70 font-mono">
                  <span className={clsx('font-semibold', criticalThreats > 0 ? 'text-ac-orange' : 'text-white')}>{criticalThreats}</span> CRITICAL
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Bell className={clsx('w-4 h-4', unreadAlerts > 0 ? 'text-ac-blue-tint' : 'text-white/70')} />
                <span className="text-xs text-white/70 font-mono">
                  <span className={clsx('font-semibold', unreadAlerts > 0 ? 'text-ac-blue-tint' : 'text-white')}>{unreadAlerts}</span> ALERTS
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={clsx(sensorCount > 0 && 'status-blink')}>
                  <Server className={clsx('w-4 h-4', sensorCount > 0 ? 'text-ac-green' : 'text-white/70')} />
                </span>
                <span className="text-xs text-white/70 font-mono">
                  <span className={clsx('font-semibold', sensorCount > 0 ? 'text-ac-green' : 'text-white')}>{sensorCount}</span> ONLINE
                </span>
              </div>
              {/* API Connection Status */}
              <div className="flex items-center gap-2 pl-4 border-l border-white/20">
                {connectionState === 'connected' ? (
                  <Wifi className="w-4 h-4 text-ac-green" />
                ) : connectionState === 'connecting' ? (
                  <Wifi className="w-4 h-4 text-ac-orange animate-pulse" />
                ) : (
                  <WifiOff className="w-4 h-4 text-ac-red" />
                )}
                <span className="text-xs text-white/70 font-mono">
                  <span className={clsx(
                    'font-semibold uppercase',
                    connectionState === 'connected' ? 'text-ac-green' :
                    connectionState === 'connecting' ? 'text-ac-orange' : 'text-ac-red'
                  )}>
                    {connectionState === 'connected' ? 'HUB' : connectionState === 'connecting' ? 'CONNECTING' : 'OFFLINE'}
                  </span>
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <DemoModeControls />
            <div className="hidden md:flex items-center gap-2 border border-white/20 px-2 h-8 text-xs text-white/70">
              acme-corp
              <ChevronDown className="w-3 h-3" />
            </div>
            <div className="hidden md:flex items-center gap-2 border border-white/20 px-2 h-8 text-xs text-white/70">
              Last 7 days
              <ChevronDown className="w-3 h-3" />
            </div>
            <button
              type="button"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="h-8 px-2 text-white/70 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
              aria-label="Toggle theme"
            >
              <ThemeIcon className="w-4 h-4" />
            </button>
            <button type="button" className="h-8 px-2 text-white/70 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-ac-blue/50" aria-label="Settings">
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar with gradient depth */}
        <aside className={clsx('transition-all duration-200 bg-surface-subtle border-r border-border-subtle flex flex-col surface-sidebar relative', sidebarCollapsed ? 'w-16' : 'w-64')}>
          <div className={clsx('border-b border-border-subtle overflow-hidden', sidebarCollapsed ? 'p-2' : 'p-4')}>
            <div className={clsx('flex items-center', sidebarCollapsed ? 'justify-center' : 'gap-3')}>
              <div className="w-11 h-11 flex-shrink-0 flex items-center justify-center">
                <img
                  src={signalHorizonLogoLight}
                  alt="Signal Horizon"
                  className="w-11 h-11 block dark:hidden"
                />
                <img
                  src={signalHorizonLogoDark}
                  alt="Signal Horizon"
                  className="w-11 h-11 hidden dark:block"
                />
              </div>
              {!sidebarCollapsed && (
                <div>
                  <div className="text-sm font-medium text-ink-primary tracking-wide">SIGNAL HORIZON</div>
                  <p className="text-xs text-ink-muted">See Further. Act Faster.</p>
                </div>
              )}
            </div>
            {!sidebarCollapsed && (
              <div className="mt-3 flex items-center gap-2">
                <span className="text-[10px] tracking-[0.18em] uppercase text-ac-magenta border border-ac-magenta/40 px-2 py-0.5 status-blink">
                  LIVE
                </span>
                <span className="text-[10px] tracking-[0.1em] uppercase text-ink-muted">
                  Collective Defense
                </span>
              </div>
            )}
          </div>

          <nav aria-label="Main navigation" className={clsx('flex-1 py-4 space-y-6 overflow-y-auto', sidebarCollapsed ? 'px-1' : 'px-3')}>
            <div>
              {!sidebarCollapsed && <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2">Threat Intelligence</p>}
              <div className="space-y-1">
                {primaryNavItems.map((item) => (
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

            <div>
              {!sidebarCollapsed && <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2">Sensor Console</p>}
              <div className="space-y-1">
                {beamNavItems.map((item) => (
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

            <div>
              {!sidebarCollapsed && <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2">Fleet Operations</p>}
              <div className="space-y-1">
                {fleetNavItems.map((item) => (
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

            {!sidebarCollapsed && (
              <div>
                <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2">Settings</p>
                <div className="space-y-1">
                  {settingsItems.map((item) => (
                    <div
                      key={item.label}
                      className="flex items-center gap-3 px-3 py-2 text-sm text-ink-disabled cursor-not-allowed opacity-50"
                      aria-disabled="true"
                      title={`${item.label} (coming soon)`}
                    >
                      {item.label}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div>
              {!sidebarCollapsed && <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-secondary mb-2">Support</p>}
              <div className="space-y-1">
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
              <div className="flex flex-col items-center gap-2">
                {isConnected ? (
                  <Wifi className="w-4 h-4 text-ac-green" />
                ) : (
                  <WifiOff className="w-4 h-4 text-ac-gray-mid" />
                )}
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 text-sm">
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
                </div>
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
                <div className="flex items-center gap-2 text-xs">
                  <PanelLeftClose className="w-4 h-4" />
                  <span>Collapse</span>
                  <kbd className="ml-auto text-[10px] text-ink-muted border border-border-subtle px-1 py-0.5">
                    {navigator.platform?.includes('Mac') ? '\u2318' : 'Ctrl'}B
                  </kbd>
                </div>
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

          <ErrorBoundary>
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
                <Route path="/intel" element={<SignalHorizonPageWrapper><IntelPage /></SignalHorizonPageWrapper>} />
                <Route path="/api-intelligence" element={<SignalHorizonPageWrapper><ApiIntelligencePage /></SignalHorizonPageWrapper>} />
                <Route path="/auth-coverage" element={<Suspense fallback={<LoadingSpinner message="Loading auth coverage map..." size="lg" />}><SignalHorizonPageWrapper><AuthCoverageMap /></SignalHorizonPageWrapper></Suspense>} />
                <Route path="/fleet/forecast" element={<SignalHorizonPageWrapper><CapacityForecastPage /></SignalHorizonPageWrapper>} />
                <Route path="/support" element={<SupportPage />} />
                
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
  );
}

export default App;
