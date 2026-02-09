import type { SensorConfig } from '../schemas/sensorConfig.js';

export function applyUpstreamsToAllSites(
  config: SensorConfig,
  upstream: { host: string; port: number },
  options: { defaultHostname?: string } = {}
): SensorConfig {
  const upstreams = [{ host: upstream.host, port: upstream.port, weight: 1 }];

  if (Array.isArray(config.sites) && config.sites.length > 0) {
    return {
      ...config,
      sites: config.sites.map((site) => ({
        ...site,
        upstreams,
      })),
    };
  }

  return {
    ...config,
    sites: [
      {
        hostname: options.defaultHostname ?? upstream.host,
        upstreams,
      },
    ],
  };
}

export function applyApparatusEchoUpstreamPreset(
  config: SensorConfig,
  upstream: { host: string; port: number }
): SensorConfig {
  // When no sites exist, we still want a predictable hostname for demo UX.
  return applyUpstreamsToAllSites(config, upstream, { defaultHostname: 'demo.site' });
}

