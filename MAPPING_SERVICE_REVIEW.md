<!-- Copyright (c) 2026 Frank Currie (frank@sfle.ca) -->
# Mapping Service Review - UTBA SwarmMap

## Current Implementation

The mapping solution for UTBA SwarmMap has been migrated to a modern, high-performance stack:

- **Mapping Library:** [Mapbox GL JS v3](https://docs.mapbox.com/mapbox-gl-js/) (High-performance vector tiles)
- **Tile Provider:** [Mapbox](https://www.mapbox.com/) (Standard and Satellite styles)
- **Reverse Geocoding:** [Mapbox Geocoding API](https://docs.mapbox.com/api/search/geocoding/) with [Nominatim (OSM)](https://nominatim.openstreetmap.org/) fallback.
- **Clustering:** Native Mapbox GL JS clustering for optimal performance and aesthetics.

### Pros

- **Performance:** Native vector tile rendering provides smooth zooming and rotation.
- **Aesthetics:** Modern, customizable styles that align with the application's visual design.
- **Reliability:** Mapbox Geocoding is highly robust; Nominatim provides a resilient fallback for intersection lookups.
- **UX:** Integrated popups and native clustering provide a superior user experience compared to raster-based solutions.

### Cons

- **Vendor Dependency:** Mapbox GL JS v2+ uses a proprietary license.
- **Cost:** Free up to 50,000 monthly loads; requires monitoring as traffic grows.

---

## Google Maps Migration Evaluation (April 2026)

### Cost Comparison

| Service | Mapbox (Current) | Google Maps Platform |
| :--- | :--- | :--- |
| **Free Tier (Loads)** | **50,000** loads/mo | **~28,500** loads/mo (via $200 credit) |
| **Price per 1k loads** | $5.00 | $7.00 |
| **Geocoding (Free)** | **100,000** requests/mo | **40,000** requests/mo (via $200 credit) |
| **Geocoding (Paid)** | $0.75 / 1k | $5.00 / 1k |

**Finding:** Mapbox offers a significantly more generous free tier for both map loads (nearly 2x) and geocoding (2.5x). For the current usage profile of SwarmMap, Mapbox remains the more cost-effective solution.

### Integration Effort

- **Frontend:** Requires a complete rewrite of the map initialization and interaction logic. Google Maps uses a different API for clustering (external library required) and marker/popup management.
- **Backend:** Requires implementing a new `GoogleMapsLocationService` and updating the factory logic in `main.go`.
- **Infrastructure:** Requires new Secret Manager entries for Google Maps API keys and updating CSP headers in the middleware.
- **Testing:** Requires updating both unit tests for geocoding and E2E tests (Playwright) which currently rely on Mapbox-specific DOM classes.

**Finding:** Migration effort is estimated as **Medium-High**.

### Feature Parity

- **Clustering:** Supported by both, but Mapbox's native vector-based clustering is more performant and easier to style than Google's library-based approach.
- **Styling:** Mapbox GL JS provides superior control over vector tile styling via Mapbox Studio.
- **Popups:** Equivalent functionality.
- **Geocoding:** Google Maps is more accurate for obscure addresses, but Mapbox + Nominatim fallback is more than sufficient for swarm reporting.

---

## Final Recommendation

**Proceed with Migration? NO**

**Rationale:**
Mapbox GL JS v3 is already implemented and provides superior performance and aesthetics at a lower cost than Google Maps. The 50,000 free monthly loads provide significant headroom for growth. The integration effort to move to Google Maps is high and would result in higher operational costs once the free tier is exceeded, without offering significant functional improvements for this specific use case (unless Street View becomes mandatory).

---

Review performed by Overseer (powered by gemini-3-flash-preview) - April 2026
