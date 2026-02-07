import { config } from '../../config.js';

export type FleetCommandFeatures = {
  toggleChaos: boolean;
  toggleMtd: boolean;
};

// Runtime feature flags (in-memory).
// Initialized from env-backed config at boot, but can be modified at runtime via admin routes.
export const fleetCommandFeatures: FleetCommandFeatures = {
  toggleChaos: config.fleetCommands.enableToggleChaos,
  toggleMtd: config.fleetCommands.enableToggleMtd,
};

export function updateFleetCommandFeatures(update: Partial<FleetCommandFeatures>): FleetCommandFeatures {
  if (typeof update.toggleChaos === 'boolean') fleetCommandFeatures.toggleChaos = update.toggleChaos;
  if (typeof update.toggleMtd === 'boolean') fleetCommandFeatures.toggleMtd = update.toggleMtd;
  return fleetCommandFeatures;
}

export function getFleetCommandFeaturesForConfig(): { enableToggleChaos: boolean; enableToggleMtd: boolean } {
  return {
    enableToggleChaos: fleetCommandFeatures.toggleChaos,
    enableToggleMtd: fleetCommandFeatures.toggleMtd,
  };
}

