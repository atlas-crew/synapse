const { execSync } = require('child_process');
const http = require('http');

/**
 * Health check utility for Edge Protection services.
 * Checks for process availability and HTTP health endpoints.
 */
async function checkUrl(url, name) {
  return new Promise((resolve) => {
    http.get(url, (res) => {
      if (res.statusCode === 200) {
        console.log(`✅ ${name} (HTTP ${url}): UP`);
        resolve(true);
      } else {
        console.log(`❌ ${name} (HTTP ${url}): DOWN (Status: ${res.statusCode})`);
        resolve(false);
      }
    }).on('error', () => {
      console.log(`❌ ${name} (HTTP ${url}): DOWN (Connection Refused)`);
      resolve(false);
    });
  });
}

function checkProcess(pattern, name) {
  try {
    execSync(`pgrep -f "${pattern}"`, { stdio: 'ignore' });
    console.log(`✅ ${name} (Process): RUNNING`);
    return true;
  } catch (e) {
    console.log(`❌ ${name} (Process): NOT RUNNING`);
    return false;
  }
}

async function main() {
  console.log('🛡️ Edge Protection - Service Health Check');
  console.log('----------------------------------------');

  const services = [
    { name: 'Horizon API', url: 'http://localhost:3100/health', pattern: 'signal-horizon-api' },
    { name: 'Horizon UI', url: 'http://localhost:5180', pattern: 'signal-horizon-ui' },
    { name: 'Synapse Admin', url: 'http://localhost:6191/health', pattern: 'synapse-waf' },
    { name: 'Apparatus', url: 'http://localhost:8090', pattern: 'apparatus' },
    { name: 'Chimera', url: 'http://localhost:8880', pattern: 'chimera' }
  ];

  for (const service of services) {
    checkProcess(service.pattern, service.name);
    await checkUrl(service.url, service.name);
  }
}

main();
