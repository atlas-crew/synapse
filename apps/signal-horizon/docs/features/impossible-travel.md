# Feature: Impossible Travel Detection

Impossible Travel detection identifies account compromise by analyzing geographic distance and time elapsed between consecutive logins.

## How it Works

The `ImpossibleTravelService` monitors authentication-related signals (e.g., `CREDENTIAL_STUFFING` or `LOGIN` signals if provided by sensors). When a login event occurs, the service:

1. Retrieves the last known location for that user.
2. Calculates the **Haversine distance** between the previous and current location.
3. Calculates the **required speed** to travel that distance in the time elapsed.
4. If the required speed exceeds a threshold (e.g., 1000 km/h), it flags the event as "Impossible Travel".

## Thresholds & Severity

| Required Speed | Severity | Description |
|----------------|----------|-------------|
| 500 - 1000 km/h | LOW | Suspicious, possible via commercial flight. |
| 1000 - 2000 km/h | MEDIUM | Very unlikely (faster than commercial air). |
| 2000 - 5000 km/h | HIGH | Physically impossible (Supersonic/Mach speed). |
| > 5000 km/h | CRITICAL | Teleportation (different continents in minutes). |

## Implementation Details

- **Location Source**: Enriched from IP metadata (GeoIP) at the sensor or aggregator level.
- **Signal Type**: Creates a new `Signal` of type `IMPOSSIBLE_TRAVEL`.
- **Confidence Scoring**: Confidence is adjusted based on:
  - Distance (higher distance = higher confidence).
  - Time gap (very small gaps = higher confidence).
  - Device consistency (same device ID across locations reduces confidence, suggesting VPN use).

## Configuration

In `api/src/config.ts`:
```typescript
impossibleTravel: {
  maxSpeedKmh: 1000,
  minDistanceKm: 50,
  enabled: true,
}
```

## User Feedback & False Positives

Detection can be sensitive to users on VPNs or corporate proxies. 
- **VPN Detection**: If an IP is flagged as a known VPN provider, the confidence score is automatically lowered.
- **Dismissals**: Analysts can mark `IMPOSSIBLE_TRAVEL` signals as `FALSE_POSITIVE` in the dashboard, which is tracked for that user.
