# Mapping Service Review - UTBA SwarmMap

## Current Implementation

The current mapping solution for UTBA SwarmMap utilizes the following components:

- **Mapping Library:** [Leaflet](https://leafletjs.com/) (Open-source, free)
- **Tile Provider:** [OpenStreetMap (OSM)](https://www.openstreetmap.org/) (Free, requires attribution)
- **Reverse Geocoding:** [Nominatim (OSM)](https://nominatim.openstreetmap.org/) (Free, but has strict usage limits)
- **Clustering:** [Leaflet.markercluster](https://github.com/Leaflet/Leaflet.markercluster) (Open-source, free)

### Pros:
- **Cost:** Completely free.
- **Open Source:** No vendor lock-in for the library.
- **Simplicity:** Easy to implement and well-documented.

### Cons:
- **Performance:** Uses raster tiles, which are slower and less smooth than vector tiles.
- **Geocoding Reliability:** Nominatim has strict [Usage Policies](https://operations.osmfoundation.org/policies/nominatim/) (max 1 request per second). If the site scales or experiences high concurrent traffic, it may be blocked.
- **Aesthetics:** The default OSM style is functional but looks somewhat dated compared to modern alternatives.
- **Features:** Limited built-in features for things like advanced search or street view.

---

## Alternatives Review

### 1. Mapbox (Mapbox GL JS)
Mapbox is a popular choice for high-performance, beautiful maps using vector tiles.

- **Cost:**
    - **Map Loads:** Free up to 50,000 loads per month. $5.00 per 1,000 loads thereafter.
    - **Geocoding:** 100,000 requests per month free. $0.75 per 1,000 requests thereafter.
- **Pros:**
    - Extremely high performance (vector tiles).
    - Highly customizable styles (can match branding).
    - Excellent documentation and community support.
    - Robust geocoding API.
- **Cons:**
    - Proprietary license (since GL JS v2).
    - Can become expensive at very high scale.

### 2. Google Maps Platform
The industry standard with the most comprehensive data.

- **Cost:**
    - $200 free credit monthly (shared across all Maps products).
    - **Dynamic Maps:** $7.00 per 1,000 loads.
    - **Reverse Geocoding:** $5.00 per 1,000 requests.
- **Pros:**
    - Most accurate and comprehensive data (POIs, addresses).
    - Street View integration.
    - Familiar interface for users.
- **Cons:**
    - Most expensive option once the free credit is exceeded.
    - Requires a credit card for billing setup even for the free tier.
    - Complex pricing structure.

### 3. Stadia Maps
A developer-friendly alternative that focuses on privacy and performance.

- **Cost:**
    - **Free Tier:** Limited for non-commercial or small projects (up to 200,000 tile requests per month).
    - **Hobbyist:** ~$20/month for higher limits.
- **Pros:**
    - Clean, modern map styles.
    - Vector tile support.
    - Good balance between cost and performance.
- **Cons:**
    - Smaller community than Google/Mapbox.

### 4. MapLibre GL JS + Vector Tile Provider (e.g., Maptiler)
MapLibre is an open-source fork of Mapbox GL JS v1.

- **Cost:**
    - **Library:** Free (BSD 3-Clause).
    - **Maptiler Tile Service:** Free tier up to 100,000 requests per month.
- **Pros:**
    - Open-source and free library.
    - Performance of vector tiles without Mapbox's newer proprietary license.
- **Cons:**
    - Slightly more complex setup (choosing a separate tile provider).

---

## Comparison Summary

| Feature | Current (OSM/Leaflet) | Mapbox | Google Maps | MapLibre + Maptiler |
| :--- | :--- | :--- | :--- | :--- |
| **Cost (Low Volume)** | Free | Free | Free ($200 credit) | Free |
| **Cost (High Volume)**| Free | Moderate | High | Moderate |
| **Performance** | Raster (Average) | Vector (Excellent) | Vector (Excellent) | Vector (Excellent) |
| **Geocoding** | Nominatim (Limited) | Robust | Best | Robust |
| **Customization** | Low | High | Medium | High |

---

## Recommendations

1. **Short Term (Maintenance):** Continue using the current Leaflet/OSM solution but monitor Nominatim usage. Consider adding a fallback or a more robust geocoding provider like **LocationIQ** (5,000 requests/day free) if Nominatim limits are hit.
2. **Medium Term (Upgrade):** Migrate to **Mapbox GL JS** or **MapLibre GL JS**. This will significantly improve the user experience with smoother interactions and more professional-looking maps. Mapbox's free tier is likely sufficient for UTBA SwarmMap's current scale.
3. **Long Term (Enterprise):** If the project requires the highest data accuracy or Street View integration, **Google Maps** would be the choice, though it comes with higher cost risks.

**Recommended Action:** Implement **Mapbox** as the primary mapping service. It offers a generous free tier, superior performance, and much better aesthetics than the current solution.

---
*Review performed by Overseer (powered by gemini-3-flash-preview) - April 2026*
