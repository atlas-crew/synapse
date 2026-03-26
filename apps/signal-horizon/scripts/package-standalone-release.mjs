#!/usr/bin/env node

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, '..');
const repoRoot = path.resolve(appRoot, '..', '..');
const outRoot = path.join(appRoot, 'out');
const releaseRoot = path.join(outRoot, 'signal-horizon-standalone');
const tarballPath = path.join(outRoot, 'signal-horizon-standalone.tar.gz');
const deployExamplesRoot = path.join(appRoot, 'deploy', 'standalone');
const stagingParent = await fs.mkdtemp(path.join(os.tmpdir(), 'signal-horizon-release-'));
const stagingRoot = path.join(stagingParent, 'signal-horizon-standalone');

function readGitRevision(args) {
  const result = spawnSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8' });
  if (result.status !== 0) {
    return 'unknown';
  }
  const value = result.stdout.trim();
  return value.length > 0 ? value : 'unknown';
}

const gitSha = readGitRevision(['rev-parse', 'HEAD']);
const gitShortSha = readGitRevision(['rev-parse', '--short', 'HEAD']);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: 'inherit',
    ...options,
  });

  if (result.status !== 0) {
    throw new Error(`Command failed: ${command} ${args.join(' ')}`);
  }
}

async function ensureFile(filePath) {
  await fs.access(filePath).catch(() => {
    throw new Error(`Expected file not found: ${filePath}`);
  });
}

async function removeIfExists(targetPath) {
  await fs.rm(targetPath, { force: true, recursive: true });
}

async function copyIntoRelease(relativeSource, relativeDestination) {
  const sourcePath = path.join(appRoot, relativeSource);
  const destinationPath = path.join(stagingRoot, relativeDestination);
  await fs.mkdir(path.dirname(destinationPath), { recursive: true });
  await fs.cp(sourcePath, destinationPath, { force: true, recursive: true });
}

async function copyDeployExample(relativeSource, relativeDestination) {
  const sourcePath = path.join(deployExamplesRoot, relativeSource);
  const destinationPath = path.join(stagingRoot, relativeDestination);
  await fs.mkdir(path.dirname(destinationPath), { recursive: true });
  await fs.cp(sourcePath, destinationPath, { force: true });
}

async function pruneReleaseBundle() {
  const pathsToRemove = [
    '.env',
    '.env.render.example',
    'TEST-GAP-REPORT.md',
    'apps',
    'docs',
    'eslint.config.mjs',
    'project.json',
    'src',
    'tsconfig.json',
    'vitest.config.ts',
    'prisma/dev.db',
  ];

  await Promise.all(pathsToRemove.map((relativePath) => removeIfExists(path.join(stagingRoot, relativePath))));
}

const generatedAt = new Date().toISOString();

try {
  await fs.mkdir(outRoot, { recursive: true });
  await fs.mkdir(stagingRoot, { recursive: true });

  run('pnpm', ['signal-horizon:standalone']);
  run('pnpm', ['--filter', '@atlascrew/signal-horizon-api', 'deploy', '--legacy', stagingRoot], {
    cwd: repoRoot,
  });

  await pruneReleaseBundle();

  await copyIntoRelease('api/.env.example', '.env.example');
  await copyIntoRelease('site/guides/self-hosted-standalone.md', 'README.md');
  await copyIntoRelease('site/deployment.md', path.join('docs', 'deployment.md'));
  await copyIntoRelease('site/guides/self-hosted-standalone.md', path.join('docs', 'self-hosted-standalone.md'));
  await copyIntoRelease('../../LICENSE', 'LICENSE');
  await copyDeployExample(path.join('bin', 'start.sh'), path.join('bin', 'start.sh'));
  await copyDeployExample(path.join('bin', 'migrate.sh'), path.join('bin', 'migrate.sh'));
  await copyDeployExample(path.join('systemd', 'signal-horizon.service'), path.join('config', 'systemd', 'signal-horizon.service'));
  await copyDeployExample(path.join('nginx', 'signal-horizon.conf'), path.join('config', 'nginx', 'signal-horizon.conf'));
  await copyDeployExample(path.join('caddy', 'Caddyfile'), path.join('config', 'caddy', 'Caddyfile'));

  await fs.writeFile(
    path.join(stagingRoot, 'RELEASE.txt'),
    [
      'Signal Horizon standalone release bundle',
      `Generated: ${generatedAt}`,
      `Revision: ${gitSha}`,
      `Revision Short: ${gitShortSha}`,
      '',
      'Primary commands:',
      '  ./bin/migrate.sh',
      '  ./bin/start.sh',
      '',
      'Docs:',
      '  README.md',
      '  docs/self-hosted-standalone.md',
      '  docs/deployment.md',
      '',
    ].join('\n'),
    'utf8',
  );

  await Promise.all([
    ensureFile(path.join(stagingRoot, 'dist', 'index.js')),
    ensureFile(path.join(stagingRoot, 'dist', 'public', 'index.html')),
    ensureFile(path.join(stagingRoot, 'node_modules', '.bin', 'prisma')),
    ensureFile(path.join(stagingRoot, 'README.md')),
    ensureFile(path.join(stagingRoot, 'bin', 'start.sh')),
  ]);

  await removeIfExists(releaseRoot);
  // Preserve the deployed symlink layout under node_modules/.bin when materializing the final bundle.
  run('sh', ['-c', 'tar -cf - -C "$1" "$2" | tar -xf - -C "$3"', 'sh', stagingParent, path.basename(stagingRoot), outRoot]);
  await removeIfExists(tarballPath);
  run('tar', ['-czf', tarballPath, '-C', outRoot, path.basename(releaseRoot)]);

  process.stdout.write(`Standalone release bundle ready at ${tarballPath}\n`);
} finally {
  await removeIfExists(stagingParent);
}
