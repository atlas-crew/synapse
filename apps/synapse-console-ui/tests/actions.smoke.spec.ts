import { expect, test } from '@playwright/test';

test('renders the actions surface and runs the legacy operator flows', async ({ page }) => {
  let currentConfig = {
    server: {
      http_addr: '0.0.0.0:80',
      https_addr: '0.0.0.0:443',
      workers: 0,
      shutdown_timeout_secs: 30,
      waf_threshold: 70,
      waf_enabled: true,
      log_level: 'info',
      waf_regex_timeout_ms: 100,
    },
    sites: [
      {
        hostname: 'example.com',
        upstreams: [{ host: 'origin.internal', port: 8080 }],
        tls: {
          cert_path: '/etc/ssl/original.crt',
          key_path: '/etc/ssl/original.key',
          min_version: '1.2',
        },
        waf: { enabled: true, rule_overrides: { sqli: 'block' } },
        headers: { add: { 'x-test': '1' } },
      },
    ],
    rate_limit: { enabled: true, rps: 1000 },
    profiler: { enabled: true, max_profiles: 1000 },
  };

  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const { pathname } = url;

    if (pathname.endsWith('/health')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ healthy: true, status: 'ok' }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/status')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ running: true, blocked_requests: 4, mode: 'proxy' }),
      });
      return;
    }

    if (pathname.endsWith('/config') && request.method() === 'GET') {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ETag: '"config-v1"' },
        body: JSON.stringify({
          success: true,
          data: currentConfig,
        }),
      });
      return;
    }

    if (pathname.endsWith('/config') && request.method() === 'POST') {
      currentConfig = request.postDataJSON() as typeof currentConfig;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            applied: true,
            persisted: true,
            rebuild_required: true,
            warnings: [],
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            sites: [
              {
                hostname: 'example.com',
                upstreams: ['origin.internal:8080'],
                tls_enabled: true,
                waf_enabled: true,
              },
            ],
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config/integrations')) {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ETag: '"integrations-v1"' },
        body: JSON.stringify({
          success: true,
          data: {
            access_mode: 'remote_management',
            sensor_api_key_set: true,
            horizon_hub_url: 'wss://horizon.example.com/ws/sensors',
            horizon_api_key_set: true,
            tunnel_url: 'wss://horizon.example.com/ws/tunnel/sensor',
            tunnel_api_key_set: true,
            apparatus_url: 'https://apparatus.example.com',
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config/export')) {
      await route.fulfill({
        status: 200,
        headers: {
          'Content-Type': 'application/x-yaml',
          'Content-Disposition': 'attachment; filename="sensor-config.yaml"',
        },
        body: ['server:', '  http_addr: 0.0.0.0:80', 'sites: []', ''].join('\n'),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config/import')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          message: 'Configuration imported and applied successfully.',
          applied: true,
          persisted: true,
          rebuild_required: true,
          warnings: [],
        }),
      });
      return;
    }

    if (pathname.endsWith('/restart')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            success: true,
            message:
              'Restart requested. Synapse WAF will restart using /usr/local/bin/synapse-waf.',
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/shutdown')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            success: true,
            message: 'Shutdown requested. Synapse WAF is draining existing connections.',
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/reload')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            success: true,
            message: 'Configuration reloaded successfully.',
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/test')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            success: true,
            message: 'Configuration syntax OK',
          },
        }),
      });
      return;
    }

    await route.continue();
  });

  await page.goto('/live/');
  await expect(page.getByRole('link', { name: 'Open legacy console' })).toHaveCount(0);
  await expect(page.getByText('Console Next')).toHaveCount(0);
  await expect(page.getByText('Synapse Operator UI')).toHaveCount(0);
  await expect(page.getByText('Operator surface is live')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Actions' }).click();

  await expect(page.getByRole('heading', { name: 'Operator actions' })).toBeVisible();
  await page.getByRole('button', { name: 'Export config' }).click();
  await expect(page.getByLabel('Export preview')).toContainText('server:');

  await page.getByLabel('Import config payload').fill('server:\n  http_addr: 127.0.0.1:8080\n');
  await page.getByRole('button', { name: 'Import config' }).click();
  await expect(
    page.getByText(
      'Configuration imported and applied successfully. Applied=true persisted=true rebuild_required=true.',
    ),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Restart service' }).click();
  await expect(
    page.getByText(
      'Restart requested. Synapse WAF will restart using /usr/local/bin/synapse-waf.',
    ),
  ).toBeVisible();
});

test('edits per-site tls controls from the Sites tab', async ({ page }) => {
  let lastPostedConfig: Record<string, unknown> | null = null;
  let currentConfig = {
    server: {
      http_addr: '0.0.0.0:80',
      https_addr: '0.0.0.0:443',
      workers: 0,
      shutdown_timeout_secs: 30,
      waf_threshold: 70,
      waf_enabled: true,
      log_level: 'info',
      waf_regex_timeout_ms: 100,
    },
    sites: [
      {
        hostname: 'example.com',
        upstreams: [{ host: 'origin.internal', port: 8080 }],
        tls: {
          cert_path: '/etc/ssl/original.crt',
          key_path: '/etc/ssl/original.key',
          min_version: '1.2',
        },
        waf: { enabled: true, rule_overrides: { sqli: 'block' } },
        headers: { add: { 'x-test': '1' } },
      },
    ],
    rate_limit: { enabled: true, rps: 1000 },
    profiler: { enabled: true, max_profiles: 1000 },
  };

  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const { pathname } = url;

    if (pathname.endsWith('/health')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ healthy: true, status: 'ok' }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/status')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ running: true, blocked_requests: 4, mode: 'proxy' }),
      });
      return;
    }

    if (pathname.endsWith('/config') && request.method() === 'GET') {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ETag: '"config-v1"' },
        body: JSON.stringify({ success: true, data: currentConfig }),
      });
      return;
    }

    if (pathname.endsWith('/config') && request.method() === 'POST') {
      lastPostedConfig = request.postDataJSON() as Record<string, unknown>;
      currentConfig = lastPostedConfig as typeof currentConfig;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            applied: true,
            persisted: true,
            rebuild_required: true,
            warnings: [],
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          data: {
            sites: [
              {
                hostname: 'example.com',
                upstreams: ['origin.internal:8080'],
                tls_enabled: true,
                waf_enabled: true,
              },
            ],
          },
        }),
      });
      return;
    }

    if (pathname.endsWith('/_sensor/config/integrations')) {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ETag: '"integrations-v1"' },
        body: JSON.stringify({
          success: true,
          data: {
            access_mode: 'remote_management',
            sensor_api_key_set: true,
            horizon_hub_url: 'wss://horizon.example.com/ws/sensors',
            horizon_api_key_set: true,
            tunnel_url: 'wss://horizon.example.com/ws/tunnel/sensor',
            tunnel_api_key_set: true,
            apparatus_url: 'https://apparatus.example.com',
          },
        }),
      });
      return;
    }

    await route.continue();
  });

  await page.goto('/live/');
  await page.getByRole('tab', { name: 'Sites' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();

  await expect(page.getByLabel('Site TLS enabled')).toBeChecked();
  await page.getByLabel('TLS certificate path').fill('/etc/ssl/updated.crt');
  await page.getByLabel('TLS key path').fill('/etc/ssl/updated.key');
  await page.getByLabel('Minimum TLS version').selectOption('1.3');
  await page.getByRole('button', { name: 'Save site' }).click();

  await expect.poll(() => lastPostedConfig).not.toBeNull();
  expect(lastPostedConfig).toBeTruthy();
  const postedSites = (lastPostedConfig as { sites: Array<Record<string, unknown>> }).sites;
  expect(postedSites[0]?.tls).toEqual({
    cert_path: '/etc/ssl/updated.crt',
    key_path: '/etc/ssl/updated.key',
    min_version: '1.3',
  });
});
