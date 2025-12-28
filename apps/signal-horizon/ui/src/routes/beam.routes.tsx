import { RouteObject } from 'react-router-dom';
import { BeamErrorBoundary } from '../components/beam/BeamErrorBoundary';
import BeamDashboardPage from '../pages/beam/BeamDashboardPage';
import TrafficAnalyticsPage from '../pages/beam/analytics/TrafficAnalyticsPage';
import ResponseTimesPage from '../pages/beam/analytics/ResponseTimesPage';
import ErrorAnalysisPage from '../pages/beam/analytics/ErrorAnalysisPage';
import ApiCatalogPage from '../pages/beam/catalog/ApiCatalogPage';
import ServicesPage from '../pages/beam/catalog/ServicesPage';
import SchemaChangesPage from '../pages/beam/catalog/SchemaChangesPage';
import ActiveRulesPage from '../pages/beam/rules/ActiveRulesPage';
import RuleTemplatesPage from '../pages/beam/rules/RuleTemplatesPage';
import CustomRulesPage from '../pages/beam/rules/CustomRulesPage';
import ThreatActivityPage from '../pages/beam/threats/ThreatActivityPage';
import BlockedRequestsPage from '../pages/beam/threats/BlockedRequestsPage';
import AttackPatternsPage from '../pages/beam/threats/AttackPatternsPage';

/**
 * Beam Protection Routes
 * All beam routes are wrapped with BeamErrorBoundary for error isolation
 * This ensures that failures in one beam page don't crash the entire application
 */
export const beamRoutes: RouteObject[] = [
  {
    path: '/beam',
    element: (
      <BeamErrorBoundary level="page" title="Dashboard Error">
        <BeamDashboardPage />
      </BeamErrorBoundary>
    ),
  },
  // Shortcut for sidebar nav
  {
    path: '/beam/analytics',
    element: (
      <BeamErrorBoundary level="page" title="Traffic Analytics Error">
        <TrafficAnalyticsPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/analytics/traffic',
    element: (
      <BeamErrorBoundary level="page" title="Traffic Analytics Error">
        <TrafficAnalyticsPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/analytics/response-times',
    element: (
      <BeamErrorBoundary level="page" title="Response Times Error">
        <ResponseTimesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/analytics/errors',
    element: (
      <BeamErrorBoundary level="page" title="Error Analysis Error">
        <ErrorAnalysisPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/catalog',
    element: (
      <BeamErrorBoundary level="page" title="API Catalog Error">
        <ApiCatalogPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/catalog/services',
    element: (
      <BeamErrorBoundary level="page" title="Services Error">
        <ServicesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/catalog/schema-changes',
    element: (
      <BeamErrorBoundary level="page" title="Schema Changes Error">
        <SchemaChangesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/rules',
    element: (
      <BeamErrorBoundary level="page" title="Rules Error">
        <ActiveRulesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/rules/templates',
    element: (
      <BeamErrorBoundary level="page" title="Rule Templates Error">
        <RuleTemplatesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/rules/custom',
    element: (
      <BeamErrorBoundary level="page" title="Custom Rules Error">
        <CustomRulesPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/threats',
    element: (
      <BeamErrorBoundary level="page" title="Threat Activity Error">
        <ThreatActivityPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/threats/blocked',
    element: (
      <BeamErrorBoundary level="page" title="Blocked Requests Error">
        <BlockedRequestsPage />
      </BeamErrorBoundary>
    ),
  },
  {
    path: '/beam/threats/patterns',
    element: (
      <BeamErrorBoundary level="page" title="Attack Patterns Error">
        <AttackPatternsPage />
      </BeamErrorBoundary>
    ),
  },
];
