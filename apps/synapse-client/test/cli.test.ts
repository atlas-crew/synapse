import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync, spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const CLI_PATH = resolve(__dirname, '../dist/cli.js');

// Helper to run CLI
function runCli(args: string[], env: Record<string, string> = {}): { stdout: string; stderr: string; status: number } {
  const result = spawnSync('node', [CLI_PATH, ...args], {
    encoding: 'utf-8',
    env: { ...process.env, ...env },
  });
  return {
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    status: result.status ?? 1,
  };
}

describe('CLI', () => {
  describe('--version', () => {
    it('should show version', () => {
      const result = runCli(['--version']);
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
      expect(result.status).toBe(0);
    });

    it('should show version with -v', () => {
      const result = runCli(['-v']);
      expect(result.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
      expect(result.status).toBe(0);
    });
  });

  describe('--help', () => {
    it('should show help', () => {
      const result = runCli(['--help']);
      expect(result.stdout).toContain('Synapse CLI');
      expect(result.stdout).toContain('USAGE:');
      expect(result.stdout).toContain('COMMANDS:');
      expect(result.stdout).toContain('EXAMPLES:');
      expect(result.status).toBe(0);
    });

    it('should show help with -h', () => {
      const result = runCli(['-h']);
      expect(result.stdout).toContain('Synapse CLI');
      expect(result.status).toBe(0);
    });

    it('should show help when no command provided', () => {
      const result = runCli([]);
      expect(result.stdout).toContain('Synapse CLI');
      expect(result.status).toBe(1); // Exit 1 when no command
    });
  });

  describe('argument parsing', () => {
    it('should require --url or SYNAPSE_URL', () => {
      const result = runCli(['status']);
      expect(result.stderr).toContain('--url or SYNAPSE_URL is required');
      expect(result.status).toBe(1);
    });

    it('should accept --url flag', () => {
      // This will fail to connect, but should parse args correctly
      const result = runCli(['--url', 'http://localhost:9999', 'health']);
      // Should attempt to connect (will fail)
      expect(result.stderr).toContain('Error:');
      expect(result.status).toBe(2); // Runtime error
    });

    it('should accept SYNAPSE_URL environment variable', () => {
      const result = runCli(['health'], { SYNAPSE_URL: 'http://localhost:9999' });
      expect(result.stderr).toContain('Error:');
      expect(result.status).toBe(2);
    });

    it('should require value for --url', () => {
      const result = runCli(['--url']);
      expect(result.stderr).toContain('--url requires a value');
      expect(result.status).toBe(1);
    });

    it('should require value for --timeout', () => {
      const result = runCli(['--timeout']);
      expect(result.stderr).toContain('--timeout requires a value');
      expect(result.status).toBe(1);
    });

    it('should reject non-numeric timeout', () => {
      const result = runCli(['--timeout', 'abc', '--url', 'http://localhost:3000', 'status']);
      expect(result.stderr).toContain('--timeout must be a number');
      expect(result.status).toBe(1);
    });
  });

  describe('command validation', () => {
    it('should reject unknown commands', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'unknown-command']);
      expect(result.stderr).toContain('Unknown command');
      expect(result.status).toBe(1);
    });

    it('should require entityId for release command', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'release']);
      expect(result.stderr).toContain('release requires entityId or IP');
      expect(result.status).toBe(1);
    });

    it('should require arguments for config-set', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'config-set']);
      expect(result.stderr).toContain('config-set requires key=value');
      expect(result.status).toBe(1);
    });

    it('should require JSON for rule-add', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'rule-add']);
      expect(result.stderr).toContain('rule-add requires JSON');
      expect(result.status).toBe(1);
    });

    it('should reject invalid JSON for rule-add', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'rule-add', 'not-json']);
      expect(result.stderr).toContain('Invalid JSON');
      expect(result.status).toBe(1);
    });

    it('should require rule ID for rule-remove', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'rule-remove']);
      expect(result.stderr).toContain('rule-remove requires rule ID');
      expect(result.status).toBe(1);
    });

    it('should require numeric rule ID for rule-remove', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'rule-remove', 'abc']);
      expect(result.stderr).toContain('numeric rule ID');
      expect(result.status).toBe(1);
    });

    it('should require method and URL for evaluate', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'evaluate']);
      expect(result.stderr).toContain('evaluate requires method and URL');
      expect(result.status).toBe(1);
    });
  });

  describe('environment variables', () => {
    it('should support SYNAPSE_JSON for JSON output', () => {
      // Can't easily test output format without a real server
      // Just verify the flag is accepted
      const result = runCli(['health'], { SYNAPSE_URL: 'http://localhost:9999', SYNAPSE_JSON: '1' });
      expect(result.status).toBe(2); // Runtime error (can't connect)
    });

    it('should support SYNAPSE_DEBUG for debug output', () => {
      const result = runCli(['health'], { SYNAPSE_URL: 'http://localhost:9999', SYNAPSE_DEBUG: '1' });
      // Debug output goes to stderr
      expect(result.stderr).toContain('[synapse]');
      expect(result.status).toBe(2);
    });

    it('should support SYNAPSE_TIMEOUT', () => {
      const result = runCli(['health'], { SYNAPSE_URL: 'http://localhost:9999', SYNAPSE_TIMEOUT: '1000' });
      expect(result.status).toBe(2);
    });
  });

  describe('exit codes', () => {
    it('should exit 0 for --help', () => {
      const result = runCli(['--help']);
      expect(result.status).toBe(0);
    });

    it('should exit 0 for --version', () => {
      const result = runCli(['--version']);
      expect(result.status).toBe(0);
    });

    it('should exit 1 for usage errors', () => {
      const result = runCli(['--url', 'http://localhost:3000', 'unknown']);
      expect(result.status).toBe(1);
    });

    it('should exit 2 for runtime errors', () => {
      const result = runCli(['--url', 'http://localhost:9999', 'health']);
      expect(result.status).toBe(2);
    });
  });
});
