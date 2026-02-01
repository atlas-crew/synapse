import { RouteObject } from 'react-router-dom';
import { FleetErrorBoundary } from '../components/fleet/FleetErrorBoundary';
import { FleetPageWrapper } from '../components/fleet/FleetPageWrapper';
import { FleetOverviewPage } from '../pages/fleet/FleetOverviewPage';
import { FleetHealthPage } from '../pages/fleet/FleetHealthPage';
import { FleetUpdatesPage } from '../pages/fleet/FleetUpdatesPage';
import { RuleDistributionPage } from '../pages/fleet/RuleDistributionPage';
import { SensorDetailPage } from '../pages/fleet/SensorDetailPage';
import { SensorConfigPage } from '../pages/fleet/SensorConfigPage';
import { DlpDashboardPage } from '../pages/fleet/DlpDashboardPage';
import { ConfigManagerPage } from '../pages/fleet/ConfigManagerPage';
import { ConnectivityPage } from '../pages/fleet/ConnectivityPage';
import { SensorKeysPage } from '../pages/fleet/SensorKeysPage';
import { OnboardingPage } from '../pages/fleet/OnboardingPage';
import { ReleasesPage } from '../pages/fleet/ReleasesPage';
import BandwidthDashboardPage from '../pages/fleet/BandwidthDashboardPage';

/**
 * Fleet Management Routes
 * All fleet routes are wrapped with FleetErrorBoundary for error isolation
 * and FleetPageWrapper for demo mode banner display
 */
export const fleetRoutes: RouteObject[] = [
  {
    path: '/fleet',
    element: (
      <FleetErrorBoundary level="page" title="Fleet Overview Error">
        <FleetPageWrapper>
          <FleetOverviewPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/health',
    element: (
      <FleetErrorBoundary level="page" title="Fleet Health Error">
        <FleetPageWrapper>
          <FleetHealthPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/dlp',
    element: (
      <FleetErrorBoundary level="page" title="DLP Dashboard Error">
        <FleetPageWrapper>
          <DlpDashboardPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/updates',
    element: (
      <FleetErrorBoundary level="page" title="Fleet Updates Error">
        <FleetPageWrapper>
          <FleetUpdatesPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/rules',
    element: (
      <FleetErrorBoundary level="page" title="Rule Distribution Error">
        <FleetPageWrapper>
          <RuleDistributionPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/sensors/:id',
    element: (
      <FleetErrorBoundary level="page" title="Sensor Detail Error">
        <FleetPageWrapper>
          <SensorDetailPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/sensors/:id/config',
    element: (
      <FleetErrorBoundary level="page" title="Sensor Configuration Error">
        <FleetPageWrapper>
          <SensorConfigPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/config',
    element: (
      <FleetErrorBoundary level="page" title="Configuration Manager Error">
        <FleetPageWrapper>
          <ConfigManagerPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/connectivity',
    element: (
      <FleetErrorBoundary level="page" title="Connectivity Monitor Error">
        <FleetPageWrapper>
          <ConnectivityPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/keys',
    element: (
      <FleetErrorBoundary level="page" title="API Key Management Error">
        <FleetPageWrapper>
          <SensorKeysPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/onboarding',
    element: (
      <FleetErrorBoundary level="page" title="Sensor Onboarding Error">
        <FleetPageWrapper>
          <OnboardingPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/releases',
    element: (
      <FleetErrorBoundary level="page" title="Release Management Error">
        <FleetPageWrapper>
          <ReleasesPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
  {
    path: '/fleet/bandwidth',
    element: (
      <FleetErrorBoundary level="page" title="Bandwidth Dashboard Error">
        <FleetPageWrapper>
          <BandwidthDashboardPage />
        </FleetPageWrapper>
      </FleetErrorBoundary>
    ),
  },
];
