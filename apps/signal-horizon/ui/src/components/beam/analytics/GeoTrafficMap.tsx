import { useEffect, useState, useMemo } from 'react';
import DeckGL from '@deck.gl/react';
import { GeoJsonLayer } from '@deck.gl/layers';
import { scaleThreshold } from 'd3-scale';
import { feature } from 'topojson-client';
import { Spinner, colors } from '@/ui';

// Aggressively suppress luma.gl/deck.gl debug output
if (typeof window !== 'undefined') {
  (window as any).luma = (window as any).luma || {};
  (window as any).luma.log = { level: 0, enable: () => {}, disable: () => {}, log: () => {}, warn: () => {}, error: () => {} };

  // Suppress shader debug log
  // @ts-expect-error - deck.gl internal
  if (!window.__LUMA_SUPPRESS_APPLIED__) {
    // @ts-expect-error - deck.gl internal
    window.__LUMA_SUPPRESS_APPLIED__ = true;
    const originalCreateElement = document.createElement.bind(document);
    document.createElement = function(tagName: string, options?: ElementCreationOptions) {
      const el = originalCreateElement(tagName, options);
      // Intercept pre elements that might contain shader code
      if (tagName.toLowerCase() === 'pre') {
        const observer = new MutationObserver(() => {
          if (el.textContent?.includes('#define') || el.textContent?.includes('LUMA')) {
            el.style.display = 'none';
          }
        });
        observer.observe(el, { childList: true, characterData: true, subtree: true });
      }
      return el;
    };
  }
}

const WORLD_ATLAS_URL = 'https://unpkg.com/world-atlas@2.0.2/countries-110m.json';

// Demo Traffic Data by Country (ISO 3166-1 numeric or name)
const COUNTRY_TRAFFIC: Record<string, number> = {
  '840': 150000, // USA
  '826': 45000,  // GBR
  '276': 32000,  // DEU
  '250': 28000,  // FRA
  '392': 21000,  // JPN
  '036': 18000,  // AUS
  '124': 15000,  // CAN
  '076': 12000,  // BRA
  '356': 9000,   // IND
  '643': 5000,   // RUS
};

const COLOR_SCALE = scaleThreshold()
  .domain([1000, 5000, 10000, 50000, 100000])
  .range([
    [82, 158, 236],  // Sky Blue (#529EEC)
    [0, 87, 183],    // Atlas Crew Blue (#0057B7)
    [0, 65, 137],    // Atlas Crew Blue-Dark (#004189)
    [0, 30, 98],     // Navy (#001E62)
    [0, 16, 68],     // Navy-Darker
    [191, 58, 48]    // Atlas Crew Red (#BF3A30) - extreme traffic alert
  ]);

const INITIAL_VIEW_STATE = {
  latitude: 20,
  longitude: 0,
  zoom: 0.8,
  pitch: 0,
  bearing: 0,
};

export function GeoTrafficMap() {
  const [countries, setCountries] = useState<any>(null);
  const [hoverInfo, setHoverInfo] = useState<{x: number, y: number, object: any} | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(WORLD_ATLAS_URL)
      .then(resp => resp.json())
      .then(worldData => {
        const countriesGeoJson = feature(worldData as any, worldData.objects.countries as any);
        setCountries(countriesGeoJson);
        setIsLoading(false);
      })
      .catch(err => {
        console.error('Failed to load map data:', err);
        setError('Failed to load map');
        setIsLoading(false);
      });
  }, []);

  const layers = useMemo(() => {
    if (!countries) return [];
    return [
      new GeoJsonLayer({
        id: 'geo-traffic',
        data: countries,
        stroked: true,
        filled: true,
        lineWidthMinPixels: 1,
        getLineColor: [200, 200, 200],
        getFillColor: (d: any) => {
          const traffic = COUNTRY_TRAFFIC[d.id] || 0;
          if (traffic === 0) return [240, 244, 248];
          const color = COLOR_SCALE(traffic);
          return [color[0], color[1], color[2]];
        },
        pickable: true,
        onHover: info => setHoverInfo(info.object ? { x: info.x, y: info.y, object: info.object } : null),
        updateTriggers: {
          getFillColor: [COUNTRY_TRAFFIC]
        }
      })
    ];
  }, [countries]);

  if (error) {
    return (
      <div className="bg-surface-card border border-border-subtle p-0 h-[400px] relative overflow-hidden flex items-center justify-center">
        <p className="text-ink-secondary">{error}</p>
      </div>
    );
  }

  return (
    <div className="bg-surface-card border border-border-subtle p-0 h-[400px] relative overflow-hidden" role="img" aria-label="Geographic traffic map showing global request distribution by country">
      <div className="absolute top-4 left-4 z-10 pointer-events-none">
        <h3 className="text-lg font-semibold text-ink-primary">Global Traffic Distribution</h3>
        <p className="text-sm text-ink-secondary">Requests by Origin Country</p>
      </div>

      {isLoading ? (
        <div className="w-full h-full flex items-center justify-center">
          <Spinner size={32} color={colors.blue} />
        </div>
      ) : (
        <div
          className="deck-container w-full h-full"
          style={{
            fontSize: 0,
            lineHeight: 0,
            color: 'transparent',
            overflow: 'hidden'
          }}
        >
          <DeckGL
            initialViewState={INITIAL_VIEW_STATE}
            controller={true}
            layers={layers}
            style={{ background: 'transparent' }}
          />
        </div>
      )}

      {hoverInfo && (
        <div
          className="absolute z-50 px-3 py-2 bg-ac-navy text-white text-xs shadow-lg pointer-events-none transform -translate-x-1/2 -translate-y-full"
          style={{ left: hoverInfo.x, top: hoverInfo.y - 10 }}
        >
          <div className="font-bold">{hoverInfo.object.properties.name}</div>
          <div>{COUNTRY_TRAFFIC[hoverInfo.object.id]?.toLocaleString() || 0} Requests</div>
        </div>
      )}
    </div>
  );
}
