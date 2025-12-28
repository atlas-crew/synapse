import { RouteObject } from 'react-router-dom';
import { TrafficAnalyticsPage } from '../pages/apex/analytics';

/**
 * Apex Protection Console Routes
 * Light-themed CtrlX design system pages for API protection management
 */
export const apexRoutes: RouteObject[] = [
  {
    path: '/apex',
    element: <TrafficAnalyticsPage />,
  },
  {
    path: '/apex/analytics',
    element: <TrafficAnalyticsPage />,
  },
  // Future Apex routes:
  // { path: '/apex/catalog', element: <ApiCatalogPage /> },
  // { path: '/apex/rules', element: <ActiveRulesPage /> },
  // { path: '/apex/threats', element: <ThreatActivityPage /> },
  // { path: '/apex/threats/:entityId', element: <EntityDetailPage /> },
];
