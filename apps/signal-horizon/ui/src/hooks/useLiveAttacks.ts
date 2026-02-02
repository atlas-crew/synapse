import { useState, useEffect, useRef } from 'react';

export interface Attack {
  id: string;
  sourceIp: string;
  sourceLat: number;
  sourceLon: number;
  targetLat: number;
  targetLon: number;
  color: [number, number, number];
  timestamp: number;
}

export interface SensorLocation {
  id: string;
  name: string;
  lat: number;
  lon: number;
  status: 'online' | 'offline' | 'warning';
}

const SENSORS: SensorLocation[] = [
  { id: 's1', name: 'US-East-1', lat: 37.7749, lon: -122.4194, status: 'online' }, // SF
  { id: 's2', name: 'EU-West-1', lat: 51.5074, lon: -0.1278, status: 'online' },   // London
  { id: 's3', name: 'AP-South-1', lat: 1.3521, lon: 103.8198, status: 'warning' }, // Singapore
  { id: 's4', name: 'SA-East-1', lat: -23.5505, lon: -46.6333, status: 'online' }, // Sao Paulo
  { id: 's5', name: 'US-Central', lat: 41.8781, lon: -87.6298, status: 'online' }, // Chicago
];

const COLORS: [number, number, number][] = [
  [255, 0, 0],    // Critical (Red)
  [255, 165, 0],  // High (Orange)
  [255, 255, 0],  // Medium (Yellow)
];

export function useLiveAttacks() {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const attacksRef = useRef<Attack[]>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      
      // Clean up old attacks (> 5 seconds)
      const activeAttacks = attacksRef.current.filter(a => now - a.timestamp < 5000);
      
      // Generate 1-3 new attacks
      const newAttacks: Attack[] = [];
      const count = Math.floor(Math.random() * 3) + 1;
      
      for (let i = 0; i < count; i++) {
        const target = SENSORS[Math.floor(Math.random() * SENSORS.length)];
        
        // Random source roughly mapped to population centers
        const sourceLat = (Math.random() * 160) - 80;
        const sourceLon = (Math.random() * 360) - 180;
        
        newAttacks.push({
          id: Math.random().toString(36).substr(2, 9),
          sourceIp: `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
          sourceLat,
          sourceLon,
          targetLat: target.lat,
          targetLon: target.lon,
          color: COLORS[Math.floor(Math.random() * COLORS.length)],
          timestamp: now,
        });
      }
      
      attacksRef.current = [...activeAttacks, ...newAttacks];
      setAttacks([...attacksRef.current]);
      
    }, 800);

    return () => clearInterval(interval);
  }, []);

  return { attacks, sensors: SENSORS };
}
