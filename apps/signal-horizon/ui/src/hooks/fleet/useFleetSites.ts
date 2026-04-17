import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import type { SensorSummary } from '../../types/fleet';
import { useDemoMode } from '../../stores/demoModeStore';

/**
 * A single site entry as seen from the fleet-wide sites page.
 *
 * Aggregates the Synapse `/sites` response shape with the sensor the
 * site is hosted on. The sensor hosts the site — one site can only
 * exist on one sensor at a time (sites are per-sensor config), but a
 * hostname can coincidentally match across sensors so we always carry
 * the sensor id as part of the row identity.
 */
export interface FleetSite {
  sensorId: string;
  sensorName: string;
  /** Synapse site hostname (may be a wildcard like "*.example.com"). */
  hostname: string;
  /** Upstream backends in `host:port` form. */
  upstreams: string[];
  /** Whether the site has TLS configured. */
  tlsEnabled: boolean;
  /** Whether the site's WAF is enabled. */
  wafEnabled: boolean;
  /** Optional rate limit in requests per second. */
  rateLimitRps?: number;
  /** Source access control default action, if configured. */
  accessDefault?: string;
  /** Arbitrary Synapse-side site metadata for the detail drawer. */
  raw: Record<string, unknown>;
}

async function fetchSensors(): Promise<SensorSummary[]> {
  const data = await apiFetch<{ sensors?: SensorSummary[] } | SensorSummary[]>(
    '/fleet/sensors',
  );
  // /fleet/sensors returns either a bare array or `{ sensors: [...] }`
  // depending on the caller — tolerate both.
  return Array.isArray(data) ? data : data.sensors ?? [];
}

// Normalise one site payload from Synapse's /sites response into the
// flat shape the FleetSites table wants. Synapse returns hostname +
// nested waf/rateLimit/tls/accessControl sub-objects; we extract the
// few fields the list needs for scanning and keep the full shape in
// `raw` for the eventual detail drawer.
function normalise(sensor: SensorSummary, site: Record<string, unknown>): FleetSite {
  const upstreams = Array.isArray(site.upstreams)
    ? (site.upstreams as Array<{ host?: string; port?: number } | string>).map((u) =>
        typeof u === 'string' ? u : `${u.host ?? '?'}:${u.port ?? '?'}`,
      )
    : [];
  const waf = site.waf as { enabled?: boolean } | null | undefined;
  const rateLimit = site.rate_limit as { rps?: number } | null | undefined;
  const accessControl = site.access_control as
    | { default_action?: string }
    | null
    | undefined;
  return {
    sensorId: sensor.id,
    sensorName: sensor.name ?? sensor.id,
    hostname: String(site.hostname ?? '(unknown)'),
    upstreams,
    tlsEnabled: site.tls !== null && site.tls !== undefined,
    wafEnabled: waf?.enabled ?? true,
    rateLimitRps: rateLimit?.rps,
    accessDefault: accessControl?.default_action,
    raw: site,
  };
}

async function fetchSitesForSensor(sensor: SensorSummary): Promise<FleetSite[]> {
  try {
    // Goes through the Synapse proxy allowlist; `/sites` was added in
    // the companion commit to ALLOWED_PATH_PREFIXES.
    const response = await apiFetch<unknown>(
      `/synapse/${encodeURIComponent(sensor.id)}/proxy/sites`,
    );
    // Synapse's /sites returns either `{ data: { sites: [...] } }` or
    // `{ data: [...] }` or a bare array — defensive unwrapping.
    const data = (response as { data?: unknown }).data ?? response;
    const sites: Array<Record<string, unknown>> = Array.isArray(data)
      ? (data as Array<Record<string, unknown>>)
      : Array.isArray((data as { sites?: unknown }).sites)
        ? ((data as { sites: Array<Record<string, unknown>> }).sites)
        : [];
    return sites.map((site) => normalise(sensor, site));
  } catch {
    // Offline sensors / permission errors should not crash the page.
    // Return an empty list and let the caller show the sensor as
    // "unreachable" in the aggregated summary.
    return [];
  }
}

/**
 * Fleet-wide sites: one row per (sensor, hostname) pair.
 *
 * Aggregates client-side by fanning out `/sites` requests to every
 * connected sensor in parallel. For a fleet under ~50 sensors this is
 * fine; at larger scale a server-side aggregator service would be
 * better, but that's a heavier infrastructure investment deferred
 * until a second caller justifies it.
 */
export function useFleetSites() {
  const { isEnabled: isDemoMode } = useDemoMode();

  return useQuery({
    queryKey: ['fleet', 'sites', isDemoMode ? 'demo' : 'live'],
    queryFn: async (): Promise<FleetSite[]> => {
      const sensors = await fetchSensors();
      const perSensor = await Promise.all(sensors.map(fetchSitesForSensor));
      return perSensor.flat();
    },
    refetchInterval: isDemoMode ? false : 15000,
    staleTime: isDemoMode ? Infinity : 10000,
  });
}
