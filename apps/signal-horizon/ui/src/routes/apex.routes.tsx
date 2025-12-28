import { RouteObject } from 'react-router-dom';
import { ApexErrorBoundary } from '../components/apex/ApexErrorBoundary';
import ApexDashboardPage from '../pages/apex/ApexDashboardPage';
import TrafficAnalyticsPage from '../pages/apex/analytics/TrafficAnalyticsPage';
import ResponseTimesPage from '../pages/apex/analytics/ResponseTimesPage';
import ErrorAnalysisPage from '../pages/apex/analytics/ErrorAnalysisPage';
import ApiCatalogPage from '../pages/apex/catalog/ApiCatalogPage';
import ServicesPage from '../pages/apex/catalog/ServicesPage';
import SchemaChangesPage from '../pages/apex/catalog/SchemaChangesPage';
import ActiveRulesPage from '../pages/apex/rules/ActiveRulesPage';
import RuleTemplatesPage from '../pages/apex/rules/RuleTemplatesPage';
import CustomRulesPage from '../pages/apex/rules/CustomRulesPage';
import ThreatActivityPage from '../pages/apex/threats/ThreatActivityPage';
import BlockedRequestsPage from '../pages/apex/threats/BlockedRequestsPage';
import AttackPatternsPage from '../pages/apex/threats/AttackPatternsPage';

/**
 * Apex Protection Routes
 * All apex routes are wrapped with ApexErrorBoundary for error isolation
 * This ensures that failures in one apex page don't crash the entire application
 */
export const apexRoutes: RouteObject[] = [
  {
    path: '/apex',
    element: (
      <ApexErrorBoundary level="page" title="Dashboard Error">
        <ApexDashboardPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/analytics/traffic',
    element: (
      <ApexErrorBoundary level="page" title="Traffic Analytics Error">
        <TrafficAnalyticsPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/analytics/response-times',
    element: (
      <ApexErrorBoundary level="page" title="Response Times Error">
        <ResponseTimesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/analytics/errors',
    element: (
      <ApexErrorBoundary level="page" title="Error Analysis Error">
        <ErrorAnalysisPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/catalog',
    element: (
      <ApexErrorBoundary level="page" title="API Catalog Error">
        <ApiCatalogPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/catalog/services',
    element: (
      <ApexErrorBoundary level="page" title="Services Error">
        <ServicesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/catalog/schema-changes',
    element: (
      <ApexErrorBoundary level="page" title="Schema Changes Error">
        <SchemaChangesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/rules',
    element: (
      <ApexErrorBoundary level="page" title="Rules Error">
        <ActiveRulesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/rules/templates',
    element: (
      <ApexErrorBoundary level="page" title="Rule Templates Error">
        <RuleTemplatesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/rules/custom',
    element: (
      <ApexErrorBoundary level="page" title="Custom Rules Error">
        <CustomRulesPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/threats',
    element: (
      <ApexErrorBoundary level="page" title="Threat Activity Error">
        <ThreatActivityPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/threats/blocked',
    element: (
      <ApexErrorBoundary level="page" title="Blocked Requests Error">
        <BlockedRequestsPage />
      </ApexErrorBoundary>
    ),
  },
  {
    path: '/apex/threats/patterns',
    element: (
      <ApexErrorBoundary level="page" title="Attack Patterns Error">
        <AttackPatternsPage />
      </ApexErrorBoundary>
    ),
  },
];
