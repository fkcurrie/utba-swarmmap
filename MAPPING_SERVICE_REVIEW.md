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

## Alternatives Review

### 1. MapLibre GL JS + Vector Tile Provider (e.g., Maptiler)

MapLibre is an open-source fork of Mapbox GL JS v1.

- **Pros:** Open-source (BSD), same performance as Mapbox GL JS.
- **Cons:** Slightly more complex initial setup.

### 2. Google Maps Platform

- **Pros:** Best address data and Street View.
- **Cons:** Most expensive; complex pricing.

---

## Comparison Summary

| Feature | Legacy (OSM/Leaflet) | Mapbox (Current) | MapLibre + Maptiler | Google Maps |
| :--- | :--- | :--- | :--- | :--- |
| **Performance** | Raster (Average) | Vector (Excellent) | Vector (Excellent) | Vector (Excellent) |
| **Geocoding** | Nominatim (Limited) | Robust + Fallback | Robust | Best |
| **Customization** | Low | High | High | Medium |
| **Open Source** | Yes | No (since v2) | Yes | No |

---

## Recommendations

1. **Short Term (Completed):** Mapbox GL JS v3 has been fully implemented as the primary mapping service. Leaflet and its associated plugins have been removed to reduce bundle size and maintenance overhead.
2. **Medium Term (Monitor):** Monitor Mapbox usage to stay within the 50,000 free monthly loads. If costs become an issue, evaluate a move to MapLibre GL JS + Maptiler for a similar experience at lower cost.
3. **Long Term (Enterprise):** Evaluate Google Maps only if Street View becomes a requirement for swarm validation.

**Current Status:** Mapbox migration is complete. The application now uses high-performance vector tiles and robust geocoding with a Nominatim fallback for resilience.

---

Review performed by Overseer (powered by gemini-3-flash-preview) - April 2026
