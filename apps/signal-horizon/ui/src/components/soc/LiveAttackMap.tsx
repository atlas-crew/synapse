import { useState, useEffect, useMemo, Component, type ReactNode } from 'react';
import { Globe2 } from 'lucide-react';
import DeckGL from '@deck.gl/react';
import { GeoJsonLayer, ArcLayer, ScatterplotLayer } from '@deck.gl/layers';
import type { PickingInfo } from '@deck.gl/core';
import { feature } from 'topojson-client';
import type { Topology, GeometryCollection } from 'topojson-specification';
import { useLiveAttacks, type Attack, type SensorLocation } from '../../hooks/useLiveAttacks';

// Hide shader debug text that luma.gl injects into the DOM
function hideShaderDebugText() {
  if (typeof document === 'undefined') return;
  const styleId = 'luma-shader-hide';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      body > *:not(#root):not(script):not(link):not(style):not(noscript):not(meta) {
        display: none !important;
        visibility: hidden !important;
      }
    `;
    document.head.appendChild(style);
  }
}

if (typeof window !== 'undefined') {
  hideShaderDebugText();
}

// Error boundary for deck.gl WebGL failures
interface DeckErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class DeckErrorBoundary extends Component<{ children: ReactNode; fallback: ReactNode }, DeckErrorBoundaryState> {
  state: DeckErrorBoundaryState = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.warn('DeckGL WebGL error caught:', error.message);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback;
    }
    return this.props.children;
  }
}

const INITIAL_VIEW_STATE = {
  latitude: 20,
  longitude: 0,
  zoom: 1.5,
  pitch: 40,
  bearing: 0,
};

const WORLD_ATLAS_URL = 'https://unpkg.com/world-atlas@2.0.2/countries-110m.json';

// Detect Firefox - deck.gl v9 has shader issues with Firefox
function isFirefox(): boolean {
  if (typeof navigator === 'undefined') return false;
  return navigator.userAgent.toLowerCase().includes('firefox');
}

interface LiveAttackMapProps {
  /** Show a "DEMO" badge when using simulated data. Defaults to true. */
  isDemo?: boolean;
}

export function LiveAttackMap({ isDemo = true }: LiveAttackMapProps) {
  const { attacks, sensors } = useLiveAttacks();
  const [countries, setCountries] = useState<any>(null);
  const [tooltip, setTooltip] = useState<{x: number, y: number, content: string} | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // deck.gl v9 has shader compilation bugs with Firefox - use fallback
  const [webglFailed] = useState(() => {
    if (isFirefox()) {
      console.warn('Firefox detected - deck.gl v9 has known shader issues, using fallback');
      return true;
    }
    return false;
  });

  useEffect(() => {
    fetch(WORLD_ATLAS_URL)
      .then(resp => resp.json())
      .then((worldData: Topology<{ countries: GeometryCollection }>) => {
        const countriesGeoJson = feature(worldData, worldData.objects.countries);
        setCountries(countriesGeoJson);
        setIsLoading(false);
      })
      .catch(err => {
        console.error('Failed to load world map:', err);
        setError('Failed to load map');
        setIsLoading(false);
      });
  }, []);

  const layers = useMemo(() => {
    const result = [];

    // 1. World Map Base Layer (Only render if data loaded)
    if (countries) {
      result.push(new GeoJsonLayer({
        id: 'base-map',
        data: countries,
        stroked: true,
        filled: true,
        lineWidthMinPixels: 1,
        getLineColor: [60, 60, 60],
        getFillColor: [30, 30, 30],
        opacity: 0.4,
      }));
    }

    // 2. Sensor Locations (Targets)
    result.push(new ScatterplotLayer<SensorLocation>({
      id: 'sensors',
      data: sensors,
      getPosition: d => [d.lon, d.lat],
      getFillColor: d => d.status === 'warning' ? [255, 165, 0] : [0, 255, 0],
      getRadius: 500000,
      radiusMinPixels: 5,
      radiusMaxPixels: 15,
      pickable: true,
      onHover: (info: PickingInfo) => {
        if (info.object) {
          setTooltip({
            x: info.x,
            y: info.y,
            content: `${info.object.name} (${info.object.status})`
          });
        } else {
          setTooltip(null);
        }
      }
    }));

    // 3. Attack Arcs
    result.push(new ArcLayer<Attack>({
      id: 'attacks',
      data: attacks,
      getSourcePosition: d => [d.sourceLon, d.sourceLat],
      getTargetPosition: d => [d.targetLon, d.targetLat],
      getSourceColor: d => d.color,
      getTargetColor: d => [d.color[0], d.color[1], d.color[2], 80],
      getWidth: 2,
      getHeight: 0.5,
    }));

    // 4. Source Impacts (Pulse effect at source)
    result.push(new ScatterplotLayer<Attack>({
      id: 'attack-sources',
      data: attacks,
      getPosition: d => [d.sourceLon, d.sourceLat],
      getFillColor: d => d.color,
      getRadius: 200000,
      radiusMinPixels: 2,
      opacity: 0.8,
    }));

    return result;
  }, [countries, sensors, attacks]);

  if (error) {
    return (
      <div className="relative w-full h-[600px] bg-surface-inset overflow-hidden border border-border-subtle flex items-center justify-center">
        <p className="text-ink-secondary">{error}</p>
      </div>
    );
  }

  // Fallback visualization when WebGL fails
  const FallbackMap = () => (
    <div className="w-full h-full bg-gradient-to-br from-[#0a1628] to-[#1a2840] flex flex-col items-center justify-center p-8">
      <div className="text-center mb-8">
        <Globe2 className="h-12 w-12 text-ac-blue mb-4" />
        <h3 className="text-lg font-medium text-ink-primary mb-2">WebGL Map Unavailable</h3>
        <p className="text-sm text-ink-secondary max-w-md">
          The interactive globe requires WebGL which isn't available in this browser.
          Attack data is still being collected and displayed below.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-4 w-full max-w-lg">
        <div className="bg-surface-card/50 p-4 border border-border-subtle">
          <div className="text-3xl font-light text-ac-red">{attacks.length}</div>
          <div className="text-xs text-ink-secondary">Active Attacks</div>
        </div>
        <div className="bg-surface-card/50 p-4 border border-border-subtle">
          <div className="text-3xl font-light text-ac-green">{sensors.length}</div>
          <div className="text-xs text-ink-secondary">Sensors Online</div>
        </div>
      </div>
      {attacks.length > 0 && (
        <div className="mt-6 w-full max-w-lg">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2">Recent Attacks</h4>
          <div className="space-y-1 max-h-32 overflow-auto">
            {attacks.slice(0, 5).map((attack, i) => (
              <div key={i} className="text-xs text-ink-secondary flex justify-between bg-surface-inset/50 px-2 py-1">
                <span>{attack.sourceIp}</span>
                <span className="text-ink-muted">→</span>
                <span>Sensor</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="relative w-full h-[600px] bg-[#111] overflow-hidden border border-border-subtle" role="img" aria-label="Live attack map showing global threat activity with attack arcs and sensor locations">
      {isLoading ? (
        <div className="w-full h-full flex items-center justify-center">
          <div className="animate-spin h-8 w-8 border-b-2 border-ac-blue" />
        </div>
      ) : webglFailed ? (
        <FallbackMap />
      ) : (
        <DeckErrorBoundary fallback={<FallbackMap />}>
          <div className="deck-container w-full h-full">
            <DeckGL
              initialViewState={INITIAL_VIEW_STATE}
              controller={true}
              layers={layers}
              getTooltip={({object}) => object && `${object.name || object.sourceIp}`}
              onError={(error) => {
                console.warn('DeckGL error:', error);
              }}
            />
          </div>
        </DeckErrorBoundary>
      )}

      {/* Demo Data Badge */}
      {isDemo && (
        <div className="absolute top-3 right-3 z-10 pointer-events-none">
          <span className="inline-flex items-center px-2.5 py-1 text-xs font-semibold uppercase tracking-wider bg-ac-orange/90 text-white">
            Demo Data
          </span>
        </div>
      )}

      {/* Overlay Stats */}
      <div className="absolute top-4 left-4 p-4 bg-surface-base/80 backdrop-blur-sm border border-border-subtle pointer-events-none">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2">Live Activity</h3>
        <div className="flex items-center gap-3">
          <div className="flex flex-col">
            <span className="text-2xl font-light text-ink-primary">{attacks.length}</span>
            <span className="text-xs text-ink-secondary">Active Threats</span>
          </div>
          <div className="h-8 w-px bg-border-subtle" />
          <div className="flex flex-col">
            <span className="text-2xl font-light text-ink-primary">{sensors.length}</span>
            <span className="text-xs text-ink-secondary">Sensors Online</span>
          </div>
        </div>
      </div>

      {tooltip && (
        <div
          className="absolute z-50 px-2 py-1 bg-black text-white text-xs pointer-events-none transform -translate-x-1/2 -translate-y-full"
          style={{ left: tooltip.x, top: tooltip.y - 10 }}
        >
          {tooltip.content}
        </div>
      )}
    </div>
  );
}
