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
// Customer-facing standalone builds publish under the external npm scope used
// for deployable products. Renamed from @atlascrew/horizon per ADR-0003 (clean
// cutover at major version bump; no dual-publish).
const standalonePackageName = '@atlascrew/synapse-fleet';
const sourcePackageJsonPath = path.join(appRoot, 'api', 'package.json');

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
const sourcePackage = JSON.parse(await fs.readFile(sourcePackageJsonPath, 'utf8'));
const prismaVersion = sourcePackage.devDependencies?.prisma;
if (!prismaVersion) {
  throw new Error('prisma not found in apps/signal-horizon/api/package.json devDependencies');
}

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

async function ensureExecutableScript(filePath) {
  const contents = await fs.readFile(filePath, 'utf8');
  if (!contents.startsWith('#!/usr/bin/env bash')) {
    throw new Error(`Expected bash shebang in ${filePath}`);
  }

  const stats = await fs.stat(filePath);
  if ((stats.mode & 0o111) === 0) {
    throw new Error(`Expected executable permissions on ${filePath}`);
  }
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

async function writeStandalonePackageManifest() {
  const stagedPackagePath = path.join(stagingRoot, 'package.json');
  const stagedPackage = JSON.parse(await fs.readFile(stagedPackagePath, 'utf8'));
  const dependencies = {
    ...stagedPackage.dependencies,
    prisma: prismaVersion,
  };
  delete dependencies['@signal-horizon/shared'];

  const standalonePackage = {
    name: standalonePackageName,
    version: sourcePackage.version,
    description: 'Synapse Fleet — standalone UI and API runtime for customer-managed deployments',
    author: 'Nicholas Crew Ferguson <nick@atlascrew.dev> (https://atlascrew.dev)',
    keywords: ['synapse-fleet', 'synapse', 'security', 'soc', 'fleet', 'hunting', 'dashboard'],
    repository: {
      type: 'git',
      url: 'https://github.com/atlas-crew/horizon-security-platform',
      directory: 'apps/signal-horizon',
    },
    homepage: 'https://horizon.atlascrew.dev/signal-horizon',
    bugs: 'https://github.com/atlas-crew/horizon-security-platform/issues',
    license: sourcePackage.license,
    type: sourcePackage.type,
    main: 'dist/index.js',
    types: 'dist/index.d.ts',
    bin: {
      'synapse-fleet': 'bin/start.sh',
      'synapse-fleet-migrate': 'bin/migrate.sh',
    },
    files: ['dist', 'prisma', 'bin', 'config', 'docs', 'README.md', 'LICENSE', 'RELEASE.txt', '.env.example'],
    scripts: {
      postinstall: 'prisma generate',
      start: 'node dist/index.js',
      'db:generate': 'prisma generate',
      'db:migrate:prod': 'prisma migrate deploy',
      'db:studio': 'prisma studio',
    },
    engines: sourcePackage.engines,
    publishConfig: {
      access: 'public',
    },
    dependencies,
  };

  await fs.writeFile(stagedPackagePath, `${JSON.stringify(standalonePackage, null, 2)}\n`, 'utf8');
}

async function removeSourceMaps(targetPath) {
  const entries = await fs.readdir(targetPath, { withFileTypes: true }).catch((error) => {
    if (error?.code === 'ENOENT') {
      return [];
    }

    throw error;
  });
  await Promise.all(
    entries.map(async (entry) => {
      const entryPath = path.join(targetPath, entry.name);
      if (entry.isDirectory()) {
        await removeSourceMaps(entryPath);
        return;
      }

      if (entry.isFile() && entry.name.endsWith('.map')) {
        await fs.rm(entryPath, { force: true });
      }
    })
  );
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
  await writeStandalonePackageManifest();
  await removeSourceMaps(path.join(stagingRoot, 'dist'));

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
    ensureExecutableScript(path.join(stagingRoot, 'bin', 'start.sh')),
    ensureExecutableScript(path.join(stagingRoot, 'bin', 'migrate.sh')),
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
