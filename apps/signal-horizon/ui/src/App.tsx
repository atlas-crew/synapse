import { Routes, Route, NavLink } from 'react-router-dom';
import { useEffect, Suspense, useMemo, useState } from 'react';
import {
  LayoutDashboard,
  Target,
  Users,
  Search,
  BarChart3,
  Wifi,
  WifiOff,
  Settings,
  Sun,
  Moon,
  ChevronDown,
  Activity,
  Package,
  Shield,
  Server,
} from 'lucide-react';
import { clsx } from 'clsx';

import signalHorizonLogoLight from './assets/brand/signal-horizon-icon-light.svg';
import signalHorizonLogoDark from './assets/brand/signal-horizon-icon-dark.svg';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner, LoadingSpinner } from './components/LoadingStates';
import OverviewPage from './pages/OverviewPage';
import CampaignDetailPage from './pages/CampaignDetailPage';
import WarRoomPage from './pages/WarRoomPage';
import HuntingPage from './pages/HuntingPage';
import IntelPage from './pages/IntelPage';
import { fleetRoutes } from './routes/fleet.routes';
import { apexRoutes } from './routes/apex.routes';
import { useWebSocket } from './hooks/useWebSocket';
import { useHorizonStore } from './stores/horizonStore';

const topNavItems = [
  { label: 'Dashboard' },
  { label: 'Entities' },
  { label: 'Threats' },
  { label: 'API Catalog' },
  { label: 'Bot Mgmt' },
  { label: 'Signal Array' },
  { label: 'Signal Horizon', active: true },
];

const primaryNavItems = [
  { path: '/', icon: LayoutDashboard, label: 'Threat Overview' },
  { path: '/campaigns', icon: Target, label: 'Active Campaigns' },
  { path: '/hunting', icon: Search, label: 'Threat Hunting' },
  { path: '/intel', icon: BarChart3, label: 'Global Intel' },
  { path: '/warroom', icon: Users, label: 'War Room' },
];

const fleetNavItems = [
  { path: '/fleet', icon: Server, label: 'Fleet Overview' },
  { path: '/fleet/health', icon: Activity, label: 'Fleet Health' },
  { path: '/fleet/updates', icon: Package, label: 'Fleet Updates' },
  { path: '/fleet/rules', icon: Shield, label: 'Rule Distribution' },
];

const apexNavItems = [
  { path: '/apex/analytics', icon: BarChart3, label: 'Analytics' },
  // { path: '/apex/catalog', icon: Package, label: 'API Catalog' },
  // { path: '/apex/rules', icon: Shield, label: 'Rules' },
  // { path: '/apex/threats', icon: Target, label: 'Threats' },
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
  const { connect, disconnect, isConnected, connectionState } = useWebSocket();
  const sensorCount = useHorizonStore((s) => s.sensorStats.CONNECTED || 0);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => getInitialTheme());

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    window.localStorage.setItem('signal-horizon-theme', theme);
  }, [theme]);

  const themeIcon = useMemo(() => (theme === 'dark' ? Sun : Moon), [theme]);
  const ThemeIcon = themeIcon;

  return (
    <div className="min-h-screen flex flex-col bg-surface-base text-ink-primary">
      {/* Top Navigation */}
      <header className="h-14 border-b border-border-subtle bg-surface-hero">
        <div className="h-full px-4 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-sm font-semibold text-ink-primary">
              <span className="tracking-[0.2em] text-xs text-ink-muted">Atlas Crew</span>
            </div>
            <nav className="hidden lg:flex items-center gap-4 text-xs font-semibold tracking-[0.12em] uppercase text-ink-muted">
              {topNavItems.map((item) => (
                <button
                  key={item.label}
                  type="button"
                  className={clsx(
                    'px-2 py-1 transition-colors',
                    item.active
                      ? 'text-link border-b-2 border-link'
                      : 'hover:text-ink-primary'
                  )}
                >
                  {item.label}
                </button>
              ))}
            </nav>
          </div>
          <div className="flex items-center gap-2">
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
              <p className="px-3 text-[10px] tracking-[0.2em] uppercase text-ink-muted mb-2">Apex Console</p>
              <div className="space-y-1">
                {apexNavItems.map((item) => (
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
                <Route path="/" element={<OverviewPage />} />
                <Route path="/campaigns" element={<CampaignDetailPage />} />
                <Route path="/campaigns/:id" element={<CampaignDetailPage />} />
                <Route path="/warroom" element={<WarRoomPage />} />
                <Route path="/warroom/:id" element={<WarRoomPage />} />
                <Route path="/hunting" element={<HuntingPage />} />
                <Route path="/intel" element={<IntelPage />} />
                {fleetRoutes.map((route) => (
                  <Route key={route.path} path={route.path} element={route.element} />
                ))}
                {apexRoutes.map((route) => (
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
