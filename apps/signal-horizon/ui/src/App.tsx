import { Routes, Route, NavLink } from 'react-router-dom';
import { useEffect, Suspense, useMemo, useState } from 'react';
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
} from 'lucide-react';
import { clsx } from 'clsx';

import signalHorizonLogoLight from './assets/brand/signal-horizon-icon-light.svg';
import signalHorizonLogoDark from './assets/brand/signal-horizon-icon-dark.svg';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner, LoadingSpinner } from './components/LoadingStates';
import { DemoModeControls } from './components/beam/DemoModeControls';
import { SignalHorizonPageWrapper } from './components/signal/SignalHorizonPageWrapper';
import OverviewPage from './pages/OverviewPage';
import CampaignsPage from './pages/soc/CampaignsPage';
import CampaignDetailPage from './pages/soc/CampaignDetailPage';
import ActorsPage from './pages/soc/ActorsPage';
import ActorDetailPage from './pages/soc/ActorDetailPage';
import SessionsPage from './pages/soc/SessionsPage';
import SessionDetailPage from './pages/soc/SessionDetailPage';
import SocSearchPage from './pages/soc/SocSearchPage';
import WarRoomPage from './pages/WarRoomPage';
import HuntingPage from './pages/HuntingPage';
import IntelPage from './pages/IntelPage';
import ApiIntelligencePage from './pages/ApiIntelligencePage';
import { fleetRoutes } from './routes/fleet.routes';
import { beamRoutes } from './routes/beam.routes';
import { useWebSocket } from './hooks/useWebSocket';
import { useHorizonStore } from './stores/horizonStore';

const primaryNavItems = [
  { path: '/', icon: LayoutDashboard, label: 'Threat Overview' },
  { path: '/campaigns', icon: Target, label: 'Campaigns' },
  { path: '/actors', icon: UserPlus, label: 'Actors' },
  { path: '/sessions', icon: Activity, label: 'Sessions' },
  { path: '/search', icon: Search, label: 'Global Search' },
  { path: '/hunting', icon: Search, label: 'Threat Hunting' },
  { path: '/intel', icon: BarChart3, label: 'Global Intel' },
  { path: '/api-intelligence', icon: Package, label: 'API Intelligence' },
  { path: '/warroom', icon: Users, label: 'War Room' },
];

const fleetNavItems = [
  { path: '/fleet', icon: Server, label: 'Fleet Overview' },
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
  if (typeof window === 'undefined') return 'light';
  const stored = window.localStorage.getItem('signal-horizon-theme');
  if (stored === 'light' || stored === 'dark') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function App() {
  const { connect, isConnected, connectionState } = useWebSocket();
  const sensorCount = useHorizonStore((s) => s.sensorStats.CONNECTED || 0);
  const campaigns = useHorizonStore((s) => s.campaigns);
  const threats = useHorizonStore((s) => s.threats);
  const alerts = useHorizonStore((s) => s.alerts);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => getInitialTheme());

  const activeCampaigns = campaigns.filter((c) => c.status === 'ACTIVE').length;
  const criticalThreats = threats.filter((t) => t.riskScore >= 80).length;
  const unreadAlerts = alerts.filter((a) => a.timestamp > Date.now() - 3600000).length; // Last hour

  useEffect(() => {
    // Connect to WebSocket on mount
    connect();
    // No cleanup - let the hook manage its own connection lifecycle
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    window.localStorage.setItem('signal-horizon-theme', theme);
  }, [theme]);

  const themeIcon = useMemo(() => (theme === 'dark' ? Sun : Moon), [theme]);
  const ThemeIcon = themeIcon;

  return (
    <div className="min-h-screen flex flex-col bg-surface-base text-ink-primary">
      {/* Top Header */}
      <header className="h-14 border-b border-border-subtle bg-surface-hero">
        <div className="h-full px-4 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-sm font-semibold text-ink-primary">
              <span className="tracking-[0.2em] text-xs text-ink-muted">Atlas Crew</span>
            </div>
            {/* Status Indicators */}
            <div className="hidden lg:flex items-center gap-6">
              <div className="flex items-center gap-2">
                <Target className={clsx('w-4 h-4', activeCampaigns > 0 ? 'text-ac-red' : 'text-ink-muted')} />
                <span className="text-xs text-ink-secondary">
                  <span className={clsx('font-semibold', activeCampaigns > 0 && 'text-ac-red')}>{activeCampaigns}</span> Active Campaigns
                </span>
              </div>
              <div className="flex items-center gap-2">
                <AlertTriangle className={clsx('w-4 h-4', criticalThreats > 0 ? 'text-ac-orange' : 'text-ink-muted')} />
                <span className="text-xs text-ink-secondary">
                  <span className={clsx('font-semibold', criticalThreats > 0 && 'text-ac-orange')}>{criticalThreats}</span> Critical Threats
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Bell className={clsx('w-4 h-4', unreadAlerts > 0 ? 'text-ac-cyan' : 'text-ink-muted')} />
                <span className="text-xs text-ink-secondary">
                  <span className={clsx('font-semibold', unreadAlerts > 0 && 'text-ac-cyan')}>{unreadAlerts}</span> Recent Alerts
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Server className={clsx('w-4 h-4', sensorCount > 0 ? 'text-ac-green' : 'text-ink-muted')} />
                <span className="text-xs text-ink-secondary">
                  <span className={clsx('font-semibold', sensorCount > 0 && 'text-ac-green')}>{sensorCount}</span> Sensors
                </span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <DemoModeControls />
            <div className="hidden md:flex items-center gap-2 border border-border-subtle px-2 h-8 text-xs text-ink-secondary">
              acme-corp
              <ChevronDown className="w-3 h-3" />
            </div>
            <div className="hidden md:flex items-center gap-2 border border-border-subtle px-2 h-8 text-xs text-ink-secondary">
              Last 7 days
              <ChevronDown className="w-3 h-3" />
            </div>
            <button
              type="button"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              className="btn-ghost h-8 px-2 text-ink-secondary"
              aria-label="Toggle theme"
            >
              <ThemeIcon className="w-4 h-4" />
            </button>
            <button type="button" className="btn-ghost h-8 px-2 text-ink-secondary">
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex flex-1 min-h-0">
        {/* Sidebar */}
        <aside className="w-64 bg-surface-subtle border-r border-border-subtle flex flex-col">
          <div className="p-4 border-b border-border-subtle">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 flex items-center justify-center">
                <img
                  src={signalHorizonLogoLight}
                  alt="Signal Horizon"
                  className="w-9 h-9 block dark:hidden"
                />
                <img
                  src={signalHorizonLogoDark}
                  alt="Signal Horizon"
                  className="w-9 h-9 hidden dark:block"
                />
              </div>
              <div>
                <p className="text-xs tracking-[0.2em] uppercase text-ink-muted">Signal Horizon</p>
                <h1 className="text-sm font-medium text-ink-primary">Fleet Intelligence</h1>
              </div>
            </div>
            <div className="mt-3 flex items-center gap-2">
              <span className="text-[10px] tracking-[0.18em] uppercase text-ac-magenta border border-ac-magenta/40 px-2 py-0.5">
                Collective Defense
              </span>
            </div>
          </div>

          <nav className="flex-1 px-3 py-4 space-y-6 overflow-y-auto">
            <div>
              <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-muted mb-2">Signal Horizon</p>
              <div className="space-y-1">
                {primaryNavItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center gap-3 px-3 py-2 text-sm transition-colors border-l-2',
                        isActive
                          ? 'bg-surface-card text-link border-link'
                          : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                      )
                    }
                  >
                    <item.icon className="w-4 h-4" />
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>

            <div>
              <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-muted mb-2">Fleet Operations</p>
              <div className="space-y-1">
                {fleetNavItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center gap-3 px-3 py-2 text-sm transition-colors border-l-2',
                        isActive
                          ? 'bg-surface-card text-link border-link'
                          : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                      )
                    }
                  >
                    <item.icon className="w-4 h-4" />
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>

            <div>
              <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-muted mb-2">Beam Console</p>
              <div className="space-y-1">
                {beamNavItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center gap-3 px-3 py-2 text-sm transition-colors border-l-2',
                        isActive
                          ? 'bg-surface-card text-link border-link'
                          : 'border-transparent text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
                      )
                    }
                  >
                    <item.icon className="w-4 h-4" />
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>

            <div>
              <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-muted mb-2">Settings</p>
              <div className="space-y-1">
                {settingsItems.map((item) => (
                  <div
                    key={item.label}
                    className="flex items-center gap-3 px-3 py-2 text-sm text-ink-muted"
                  >
                    {item.label}
                  </div>
                ))}
              </div>
            </div>
          </nav>

          {/* Connection Status */}
          <div className="p-4 border-t border-border-subtle">
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
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 overflow-auto flex flex-col">
          <ConnectionBanner
            isConnected={isConnected}
            isReconnecting={connectionState === 'connecting'}
          />

          <ErrorBoundary>
            <Suspense fallback={<LoadingSpinner message="Loading page..." size="lg" />}>
              <Routes>
                <Route path="/" element={<SignalHorizonPageWrapper><OverviewPage /></SignalHorizonPageWrapper>} />
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
                <Route path="/intel" element={<SignalHorizonPageWrapper><IntelPage /></SignalHorizonPageWrapper>} />
                <Route path="/api-intelligence" element={<SignalHorizonPageWrapper><ApiIntelligencePage /></SignalHorizonPageWrapper>} />
                {fleetRoutes.map((route) => (
                  <Route key={route.path} path={route.path} element={route.element} />
                ))}
                {beamRoutes.map((route) => (
                  <Route key={route.path} path={route.path} element={route.element} />
                ))}
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export default App;
