import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { CommandSender, DEFAULT_CONFIG } from '../command-sender.js';
import type { Command, CommandSenderConfig } from '../command-sender.js';
import type WebSocket from 'ws';

// Mock WebSocket
const createMockWs = (readyState = 1): WebSocket => ({
  readyState,
  send: vi.fn(),
} as unknown as WebSocket);

describe('CommandSender', () => {
  let sender: CommandSender;

  beforeEach(() => {
    sender = new CommandSender();
  });

  afterEach(() => {
    sender.stop();
    sender.clear();
  });

  describe('constructor', () => {
    it('uses default config when no config provided', () => {
      const config = sender.getConfig();
      expect(config).toEqual(DEFAULT_CONFIG);
    });

    it('merges custom config with defaults', () => {
      const custom = new CommandSender({ maxQueueSize: 500 });
      const config = custom.getConfig();
      expect(config.maxQueueSize).toBe(500);
      expect(config.maxPerSensorQueueSize).toBe(DEFAULT_CONFIG.maxPerSensorQueueSize);
      custom.stop();
    });
  });

  describe('global queue limit', () => {
    it('enforces global queue size limit', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 3, maxPerSensorQueueSize: 100 });
      const dropped: unknown[] = [];
      limitedSender.on('command-dropped', (e) => dropped.push(e));

      // Add 3 commands (at capacity)
      const id1 = limitedSender.sendCommand('sensor-1', 'push_config', {});
      const id2 = limitedSender.sendCommand('sensor-2', 'push_config', {});
      const id3 = limitedSender.sendCommand('sensor-3', 'push_config', {});

      expect(id1).not.toBeNull();
      expect(id2).not.toBeNull();
      expect(id3).not.toBeNull();
      expect(limitedSender.getStats().total).toBe(3);

      // 4th command should trigger eviction of oldest pending
      const evicted: Command[] = [];
      limitedSender.on('command-evicted', (c) => evicted.push(c));

      const id4 = limitedSender.sendCommand('sensor-4', 'push_config', {});
      expect(id4).not.toBeNull();
      expect(evicted.length).toBe(1);
      expect(evicted[0].id).toBe(id1); // Oldest should be evicted
      expect(limitedSender.getStats().total).toBe(3); // Still at capacity
      expect(limitedSender.getStats().evicted).toBe(1);

      limitedSender.stop();
    });

    it('drops command when no pending commands to evict', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 2, maxPerSensorQueueSize: 100 });
      const dropped: unknown[] = [];
      limitedSender.on('command-dropped', (e) => dropped.push(e));

      // Register connections so commands get sent immediately
      limitedSender.registerConnection('sensor-1', createMockWs());
      limitedSender.registerConnection('sensor-2', createMockWs());

      // Commands are sent immediately when sensor is connected, status changes to 'sent'
      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.sendCommand('sensor-2', 'push_config', {});

      // No pending commands to evict, so third should be dropped
      const result = limitedSender.sendCommand('sensor-3', 'push_config', {});

      expect(result).toBeNull();
      expect(dropped.length).toBe(1);
      expect(dropped[0]).toMatchObject({ sensorId: 'sensor-3', reason: 'global_limit' });
      expect(limitedSender.getStats().dropped).toBe(1);

      limitedSender.stop();
    });
  });

  describe('per-sensor queue limit', () => {
    it('enforces per-sensor queue limit', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 100, maxPerSensorQueueSize: 2 });
      const evicted: Command[] = [];
      limitedSender.on('command-evicted', (c) => evicted.push(c));

      // Add 2 commands for same sensor (at per-sensor capacity)
      const id1 = limitedSender.sendCommand('sensor-1', 'push_config', { seq: 1 });
      const id2 = limitedSender.sendCommand('sensor-1', 'push_rules', { seq: 2 });

      expect(limitedSender.getSensorStats('sensor-1').pending).toBe(2);

      // 3rd command should evict oldest
      const id3 = limitedSender.sendCommand('sensor-1', 'restart', {});

      expect(id3).not.toBeNull();
      expect(evicted.length).toBe(1);
      expect(evicted[0].id).toBe(id1);
      expect(limitedSender.getSensorStats('sensor-1').pending).toBe(2);

      limitedSender.stop();
    });

    it('does not affect other sensors when per-sensor limit reached', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 100, maxPerSensorQueueSize: 2 });

      // Fill sensor-1 to capacity
      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.sendCommand('sensor-1', 'push_rules', {});

      // sensor-2 should still be able to queue
      const id = limitedSender.sendCommand('sensor-2', 'push_config', {});
      expect(id).not.toBeNull();
      expect(limitedSender.getSensorStats('sensor-2').pending).toBe(1);

      limitedSender.stop();
    });

    it('allows sending to connected sensor even when pending limit would block', () => {
      // Per-sensor limit only applies to pending commands (offline sensors)
      // When sensor is connected, commands are sent immediately and don't count against limit
      const limitedSender = new CommandSender({ maxQueueSize: 100, maxPerSensorQueueSize: 1 });

      // Register connection so commands go to 'sent' state
      limitedSender.registerConnection('sensor-1', createMockWs());

      const id1 = limitedSender.sendCommand('sensor-1', 'push_config', {});
      const id2 = limitedSender.sendCommand('sensor-1', 'push_rules', {});

      // Both should succeed because they're being sent, not queued
      expect(id1).not.toBeNull();
      expect(id2).not.toBeNull();
      expect(limitedSender.getSensorStats('sensor-1').pending).toBe(0);

      limitedSender.stop();
    });
  });

  describe('pending TTL eviction', () => {
    it('evicts pending commands after TTL expires', () => {
      vi.useFakeTimers();
      const limitedSender = new CommandSender({
        maxQueueSize: 100,
        maxPerSensorQueueSize: 100,
        pendingTTL: 1000 // 1 second for testing
      });
      const evicted: unknown[] = [];
      limitedSender.on('command-evicted', (e) => evicted.push(e));

      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.start();

      expect(limitedSender.getStats().pending).toBe(1);

      // Advance past TTL
      vi.advanceTimersByTime(2000);

      // Cleanup runs every 60 seconds, so advance to trigger it
      vi.advanceTimersByTime(60000);

      expect(limitedSender.getStats().pending).toBe(0);
      expect(evicted.length).toBe(1);

      limitedSender.stop();
      vi.useRealTimers();
    });
  });

  describe('stats', () => {
    it('tracks queue utilization', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 10, maxPerSensorQueueSize: 5 });

      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.sendCommand('sensor-1', 'push_rules', {});

      const stats = limitedSender.getStats();
      expect(stats.total).toBe(2);
      expect(stats.queueCapacity).toBe(10);
      expect(stats.queueUtilization).toBe(0.2);

      const sensorStats = limitedSender.getSensorStats('sensor-1');
      expect(sensorStats.pending).toBe(2);
      expect(sensorStats.capacity).toBe(5);
      expect(sensorStats.utilization).toBe(0.4);

      limitedSender.stop();
    });

    it('tracks dropped and evicted separately', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 2, maxPerSensorQueueSize: 100 });

      // Register connection so commands go to 'sent' (not evictable)
      limitedSender.registerConnection('sensor-1', createMockWs());

      // Fill with sent commands (not evictable)
      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.sendCommand('sensor-1', 'push_rules', {});

      // This should be dropped (can't evict sent commands)
      limitedSender.sendCommand('sensor-1', 'restart', {});

      const stats = limitedSender.getStats();
      expect(stats.dropped).toBe(1);
      expect(stats.evicted).toBe(0);

      limitedSender.stop();
    });

    it('resets stats on resetStats call', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 1, maxPerSensorQueueSize: 100 });

      limitedSender.sendCommand('sensor-1', 'push_config', {});
      limitedSender.sendCommand('sensor-1', 'push_rules', {}); // Evicts first

      expect(limitedSender.getStats().evicted).toBe(1);

      limitedSender.resetStats();

      expect(limitedSender.getStats().evicted).toBe(0);
      expect(limitedSender.getStats().dropped).toBe(0);

      limitedSender.stop();
    });
  });

  describe('sendCommand return value', () => {
    it('returns command ID on success', () => {
      const id = sender.sendCommand('sensor-1', 'push_config', {});
      expect(id).toMatch(/^cmd-/);
    });

    it('returns custom ID when provided', () => {
      const id = sender.sendCommand('sensor-1', 'push_config', {}, 'my-custom-id');
      expect(id).toBe('my-custom-id');
    });

    it('returns null when command is dropped', () => {
      const limitedSender = new CommandSender({ maxQueueSize: 1, maxPerSensorQueueSize: 1 });
      limitedSender.registerConnection('sensor-1', createMockWs());

      limitedSender.sendCommand('sensor-1', 'push_config', {});
      const result = limitedSender.sendCommand('sensor-1', 'push_rules', {});

      expect(result).toBeNull();
      limitedSender.stop();
    });
  });

  describe('existing functionality preserved', () => {
    it('sends command immediately when sensor connected', () => {
      const ws = createMockWs();
      sender.registerConnection('sensor-1', ws);

      const id = sender.sendCommand('sensor-1', 'push_config', { key: 'value' });

      expect(ws.send).toHaveBeenCalledTimes(1);
      const sent = JSON.parse((ws.send as ReturnType<typeof vi.fn>).mock.calls[0][0]);
      expect(sent).toMatchObject({
        type: 'push_config',
        commandId: id,
        payload: { key: 'value' },
      });
    });

    it('queues command when sensor offline', () => {
      const id = sender.sendCommand('sensor-1', 'push_config', {});

      expect(sender.getCommand(id!)?.status).toBe('pending');
      expect(sender.getPendingCommands('sensor-1').length).toBe(1);
    });

    it('flushes pending commands on reconnect', () => {
      sender.sendCommand('sensor-1', 'push_config', {});
      sender.sendCommand('sensor-1', 'push_rules', {});

      const ws = createMockWs();
      sender.registerConnection('sensor-1', ws);

      expect(ws.send).toHaveBeenCalledTimes(2);
      expect(sender.getPendingCommands('sensor-1').length).toBe(0);
    });

    it('handles command response correctly', () => {
      const completed: Command[] = [];
      sender.on('command-complete', (c) => completed.push(c));

      const id = sender.sendCommand('sensor-1', 'push_config', {});
      sender.handleResponse(id!, true);

      expect(completed.length).toBe(1);
      expect(completed[0].status).toBe('success');
    });

    it('cancels pending command', () => {
      const id = sender.sendCommand('sensor-1', 'push_config', {});
      const result = sender.cancelCommand(id!);

      expect(result).toBe(true);
      expect(sender.getCommand(id!)?.status).toBe('failed');
      expect(sender.getCommand(id!)?.error).toBe('Cancelled');
    });
  });
});
