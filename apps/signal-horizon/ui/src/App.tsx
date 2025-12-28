import { Routes, Route, NavLink } from 'react-router-dom';
import { useEffect, Suspense } from 'react';
import {
  LayoutDashboard,
  Target,
  Users,
  Search,
  BarChart3,
  Shield,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { clsx } from 'clsx';

import { ErrorBoundary } from './components/ErrorBoundary';
import { ConnectionBanner, LoadingSpinner } from './components/LoadingStates';
import OverviewPage from './pages/OverviewPage';
import CampaignDetailPage from './pages/CampaignDetailPage';
import WarRoomPage from './pages/WarRoomPage';
import HuntingPage from './pages/HuntingPage';
import IntelPage from './pages/IntelPage';
import { useWebSocket } from './hooks/useWebSocket';
import { useHorizonStore } from './stores/horizonStore';
import { apexRoutes } from './routes/apex.routes';

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Overview' },
  { path: '/campaigns', icon: Target, label: 'Campaigns' },
  { path: '/warroom', icon: Users, label: 'War Room' },
  { path: '/hunting', icon: Search, label: 'Hunting' },
  { path: '/intel', icon: BarChart3, label: 'Intel' },
  { path: '/apex', icon: Shield, label: 'Apex Protection' },
];

function App() {
  const { connect, disconnect, isConnected, connectionState } = useWebSocket();
  const sensorCount = useHorizonStore((s) => s.sensorStats.CONNECTED || 0);

  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return (
    <div className="min-h-screen bg-gray-950 flex">
      {/* Sidebar */}
      <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
        {/* Logo */}
        <div className="p-4 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-horizon-500 to-horizon-700 flex items-center justify-center">
              <span className="text-white font-bold text-lg">SH</span>
            </div>
            <div>
              <h1 className="font-semibold text-white">Signal Horizon</h1>
              <p className="text-xs text-gray-500">Fleet Intelligence</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-horizon-600/20 text-horizon-400'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800'
                )
              }
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* Connection Status */}
        <div className="p-4 border-t border-gray-800">
          <div className="flex items-center gap-2 text-sm">
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-green-400" />
                <span className="text-green-400">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-gray-500" />
                <span className="text-gray-500">
                  {connectionState === 'connecting' ? 'Connecting...' : 'Disconnected'}
                </span>
              </>
            )}
          </div>
          <div className="mt-2 text-xs text-gray-500">
            {sensorCount} sensors online
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto flex flex-col">
        {/* Connection status banner */}
        <ConnectionBanner
          isConnected={isConnected}
          isReconnecting={connectionState === 'connecting'}
        />

        {/* Routes wrapped in error boundary */}
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
              {apexRoutes.map((route, index) => (
                <Route key={index} path={route.path} element={route.element} />
              ))}
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  );
}

export default App;
