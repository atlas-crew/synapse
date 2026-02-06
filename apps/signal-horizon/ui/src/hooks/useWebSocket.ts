/**
 * Signal Horizon WebSocket Hook
 * Manages connection to the dashboard gateway
 *
 * When demo mode is enabled, this hook populates the store with demo data
 * instead of connecting to the real WebSocket server.
 */

import { useCallback, useRef, useEffect, useState } from 'react';
import { z } from 'zod';
import { useHorizonStore } from '../stores/horizonStore';
import { useDemoMode } from '../stores/demoModeStore';
import { getDemoData } from '../lib/demoData';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:3100/ws/dashboard';
const API_KEY = import.meta.env.VITE_HORIZON_API_KEY || 'dev-dashboard-key';
const RECONNECT_DELAY = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;

// =============================================================================
// Zod Schemas for Message Validation
// =============================================================================

const CampaignSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().nullish().transform(val => val ?? undefined),
  status: z.enum(['ACTIVE', 'MONITORING', 'RESOLVED', 'FALSE_POSITIVE']),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  isCrossTenant: z.boolean(),
  tenantsAffected: z.number(),
  confidence: z.number(),
  firstSeenAt: z.string(),
  lastActivityAt: z.string(),
}).passthrough(); // Allow extra fields from database

const ThreatSchema = z.object({
  id: z.string(),
  threatType: z.string(),
  indicator: z.string(),
  riskScore: z.number(),
  fleetRiskScore: z.number().nullish().transform(val => val ?? undefined),
  hitCount: z.number(),
  tenantsAffected: z.number(),
  isFleetThreat: z.boolean(),
  firstSeenAt: z.string(),
  lastSeenAt: z.string(),
}).passthrough(); // Allow extra fields from database

const SnapshotDataSchema = z.object({
  activeCampaigns: z.array(CampaignSchema),
  recentThreats: z.array(ThreatSchema),
  sensorStats: z.record(z.string(), z.number()),
  apiStats: z.object({
    discoveryEvents: z.number(),
    schemaViolations: z.number(),
  }).optional().default({ discoveryEvents: 0, schemaViolations: 0 }),
});

const CampaignAlertSchema = z.object({
  campaign: z.object({
    id: z.string(),
    name: z.string(),
    severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
    isCrossTenant: z.boolean(),
    tenantsAffected: z.number(),
    confidence: z.number(),
  }),
});

const ThreatAlertSchema = z.object({
  threat: z.object({
    id: z.string(),
    threatType: z.string(),
    indicator: z.string(),
    riskScore: z.number(),
    isFleetThreat: z.boolean(),
  }),
});

const BlocklistUpdateSchema = z.object({
  updates: z.array(
    z.object({
      type: z.enum(['add', 'remove']),
      blockType: z.string(),
      indicator: z.string(),
    })
  ),
  campaign: z.string().optional(),
});

// Base message schema
const BaseMessageSchema = z.object({
  type: z.string(),
  timestamp: z.number().optional(),
  sequenceId: z.number().optional(),
});

// Type aliases are inferred at usage site via z.infer<typeof Schema>

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isCleaningUpRef = useRef(false);
  const lastLoadedScenarioRef = useRef<string | null>(null);
  const [reconnectAttempt, setReconnectAttempt] = useState(0);

  // Demo mode state
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  const {
    connectionState,
    setConnectionState,
    setSessionId,
    setSnapshot,
    addCampaign,
    addThreat,
    addAlert,
    clearAlerts,
  } = useHorizonStore();

  // Load demo data when demo mode is enabled or scenario changes
  useEffect(() => {
    if (isDemoMode) {
      // Only reload if scenario changed or not yet loaded
      if (lastLoadedScenarioRef.current !== scenario) {
        console.log('[WebSocket] Loading demo data for scenario:', scenario);

        // Load Signal Horizon demo data into the store
        const demoData = getDemoData(scenario);
        const { signalHorizon } = demoData;

        // Convert SensorStats to Record<string, number> format
        const sensorStatsRecord: Record<string, number> = {
          CONNECTED: signalHorizon.sensorStats.CONNECTED,
          DISCONNECTED: signalHorizon.sensorStats.DISCONNECTED,
          WARNING: signalHorizon.sensorStats.WARNING,
        };

        // Set snapshot with demo data
        setSnapshot({
          activeCampaigns: signalHorizon.campaigns,
          recentThreats: signalHorizon.threats,
          sensorStats: sensorStatsRecord,
          apiStats: { discoveryEvents: 0, schemaViolations: 0 },
        });

        // Clear existing alerts and add demo alerts
        clearAlerts();
        signalHorizon.alerts.forEach((alert) => {
          addAlert(alert);
        });

        // Mark scenario as loaded and set connected state
        lastLoadedScenarioRef.current = scenario;
        setConnectionState('connected');
        setSessionId('demo-session');

        console.log('[WebSocket] Demo mode loaded:', {
          campaigns: signalHorizon.campaigns.length,
          threats: signalHorizon.threats.length,
          alerts: signalHorizon.alerts.length,
          scenario,
        });
      }
    } else if (lastLoadedScenarioRef.current !== null) {
      // Demo mode was disabled - reset state
      lastLoadedScenarioRef.current = null;
      setConnectionState('disconnected');
      setSessionId(null);
      console.log('[WebSocket] Demo mode disabled');
    }
  }, [isDemoMode, scenario, setSnapshot, addAlert, clearAlerts, setConnectionState, setSessionId]);

  // Cleanup helper - clears timeout and closes websocket
  const cleanup = useCallback(() => {
    isCleaningUpRef.current = true;

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      // Remove event handlers before closing to prevent reconnect attempts
      wsRef.current.onopen = null;
      wsRef.current.onmessage = null;
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.close(1000, 'Cleanup');
      wsRef.current = null;
    }

    isCleaningUpRef.current = false;
  }, []);

  // Handle incoming messages with Zod validation
  const handleMessage = useCallback(
    (event: MessageEvent) => {
      let rawMessage: unknown;
      try {
        rawMessage = JSON.parse(event.data as string);
      } catch {
        console.error('[WebSocket] Failed to parse message as JSON');
        return;
      }

      // Validate base message structure
      const baseResult = BaseMessageSchema.safeParse(rawMessage);
      if (!baseResult.success) {
        console.error('[WebSocket] Invalid message format:', baseResult.error.format());
        return;
      }

      const message = rawMessage as {
        type: string;
        data?: unknown;
        timestamp?: number;
        sessionId?: string;
        tenantId?: string;
        isFleetAdmin?: boolean;
        topic?: string;
        error?: string;
      };

      switch (message.type) {
        case 'auth-required':
          // Server requests authentication - send API key
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ type: 'auth', payload: { apiKey: API_KEY } }));
          }
          break;

        case 'auth-success':
          // Authentication successful
          setSessionId(message.sessionId ?? null);
          console.log('[WebSocket] Authenticated:', {
            sessionId: message.sessionId,
            tenantId: message.tenantId,
            isFleetAdmin: message.isFleetAdmin,
          });
          break;

        case 'auth-failed':
          console.error('[WebSocket] Authentication failed:', message.error);
          setConnectionState('error');
          break;

        case 'snapshot': {
          const snapshotResult = SnapshotDataSchema.safeParse(message.data);
          if (snapshotResult.success) {
            setSnapshot(snapshotResult.data);
          } else {
            console.error('[WebSocket] Invalid snapshot data:', snapshotResult.error.format());
          }
          break;
        }

        case 'campaign-alert': {
          const alertResult = CampaignAlertSchema.safeParse(message.data);
          if (alertResult.success) {
            const alertData = alertResult.data;
            addCampaign({
              ...alertData.campaign,
              status: 'ACTIVE',
              firstSeenAt: new Date().toISOString(),
              lastActivityAt: new Date().toISOString(),
            });
            addAlert({
              id: `campaign-${alertData.campaign.id}-${message.timestamp}`,
              type: 'campaign',
              title: `Campaign Detected: ${alertData.campaign.name}`,
              description: `${alertData.campaign.tenantsAffected} tenants affected, ${Math.round(alertData.campaign.confidence * 100)}% confidence`,
              severity: alertData.campaign.severity,
              timestamp: message.timestamp ?? Date.now(),
            });
          }
          break;
        }

        case 'threat-alert': {
          const alertResult = ThreatAlertSchema.safeParse(message.data);
          if (alertResult.success) {
            const alertData = alertResult.data;
            addThreat({
              ...alertData.threat,
              hitCount: 1,
              tenantsAffected: alertData.threat.isFleetThreat ? 2 : 1,
              firstSeenAt: new Date().toISOString(),
              lastSeenAt: new Date().toISOString(),
            });
            addAlert({
              id: `threat-${alertData.threat.id}-${message.timestamp}`,
              type: 'threat',
              title: `Threat Detected: ${alertData.threat.indicator}`,
              description: `Risk score: ${alertData.threat.riskScore}, ${alertData.threat.isFleetThreat ? 'Fleet-wide' : 'Local'}`,
              severity:
                alertData.threat.riskScore >= 80
                  ? 'CRITICAL'
                  : alertData.threat.riskScore >= 60
                    ? 'HIGH'
                    : 'MEDIUM',
              timestamp: message.timestamp ?? Date.now(),
            });
          }
          break;
        }

        case 'blocklist-update': {
          const updateResult = BlocklistUpdateSchema.safeParse(message.data);
          if (updateResult.success) {
            const updateData = updateResult.data;
            addAlert({
              id: `blocklist-${message.timestamp}`,
              type: 'blocklist',
              title: 'Blocklist Updated',
              description: `${updateData.updates.length} indicators modified`,
              severity: 'MEDIUM',
              timestamp: message.timestamp ?? Date.now(),
            });
          }
          break;
        }

        case 'ping':
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ type: 'pong' }));
          }
          break;

        case 'subscribed':
        case 'unsubscribed':
          console.log(`[WebSocket] ${message.type}: ${message.topic}`);
          break;

        case 'error':
          console.error('[WebSocket] Server error:', message.error);
          break;

        default:
          console.log('[WebSocket] Unknown message type:', message.type);
      }
    },
    [setSessionId, setConnectionState, setSnapshot, addCampaign, addThreat, addAlert]
  );

  // Schedule reconnection with exponential backoff
  const scheduleReconnect = useCallback(() => {
    if (isCleaningUpRef.current) {
      return;
    }

    if (reconnectAttemptsRef.current >= MAX_RECONNECT_ATTEMPTS) {
      console.log('[WebSocket] Max reconnect attempts reached');
      setReconnectAttempt(reconnectAttemptsRef.current);
      return;
    }

    reconnectAttemptsRef.current += 1;
    setReconnectAttempt(reconnectAttemptsRef.current);
    const delay = RECONNECT_DELAY * reconnectAttemptsRef.current;

    console.log(
      `[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttemptsRef.current})`
    );

    reconnectTimeoutRef.current = setTimeout(() => {
      // Will be connected by the effect that watches for reconnect
      setConnectionState('connecting');
    }, delay);
  }, [setConnectionState]);

  // Connect to WebSocket
  const connect = useCallback(() => {
    // Skip actual WebSocket connection when demo mode is enabled
    if (isDemoMode) {
      console.log('[WebSocket] Demo mode active - skipping real connection');
      return;
    }

    const existing = wsRef.current;
    if (
      existing &&
      (existing.readyState === WebSocket.OPEN || existing.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    // Clean up any existing connection first
    cleanup();

    setConnectionState('connecting');

    try {
      const ws = new WebSocket(`${WS_URL}?apiKey=${API_KEY}`);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[WebSocket] Connected to Signal Horizon Hub');
        setConnectionState('connected');
        reconnectAttemptsRef.current = 0;
        setReconnectAttempt(0);
      };

      ws.onmessage = handleMessage;

      ws.onclose = (event) => {
        console.log('[WebSocket] Disconnected:', event.code, event.reason);
        wsRef.current = null;
        setConnectionState('disconnected');
        setSessionId(null);

        // Only reconnect if not intentionally cleaning up
        if (!isCleaningUpRef.current) {
          scheduleReconnect();
        }
      };

      ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
        setConnectionState('error');
      };
    } catch (error) {
      console.error('[WebSocket] Failed to connect:', error);
      setConnectionState('error');
      scheduleReconnect();
    }
  }, [cleanup, handleMessage, scheduleReconnect, setConnectionState, setSessionId, isDemoMode]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    cleanup();
    setConnectionState('disconnected');
    setSessionId(null);
    reconnectAttemptsRef.current = 0;
    setReconnectAttempt(0);
  }, [cleanup, setConnectionState, setSessionId]);

  // Send message helper
  const send = useCallback((message: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(message));
    } else {
      console.warn('[WebSocket] Cannot send - not connected');
    }
  }, []);

  const subscribe = useCallback(
    (topic: string) => {
      send({ type: 'subscribe', payload: { topic } });
    },
    [send]
  );

  const unsubscribe = useCallback(
    (topic: string) => {
      send({ type: 'unsubscribe', payload: { topic } });
    },
    [send]
  );

  const requestSnapshot = useCallback(() => {
    send({ type: 'request-snapshot' });
  }, [send]);

  // Trigger connection when state becomes 'connecting' (e.g. from reconnect scheduler)
  useEffect(() => {
    if (connectionState === 'connecting' && !isDemoMode) {
      connect();
    }
  }, [connectionState, connect, isDemoMode]);

  // Cleanup on unmount - disconnect and clear all timers
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    connect,
    disconnect,
    send,
    subscribe,
    unsubscribe,
    requestSnapshot,
    isConnected: connectionState === 'connected',
    connectionState,
    isDemoMode,
    reconnectAttempt,
    maxReconnectAttempts: MAX_RECONNECT_ATTEMPTS,
  };
}
