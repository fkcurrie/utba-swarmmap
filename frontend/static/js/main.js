// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

document.addEventListener('DOMContentLoaded', function () {
  const mapElement = document.getElementById('map');
  const reportSwarmBtn = document.getElementById('reportSwarmBtn');
  const reportSwarmForm = document.getElementById('reportSwarmForm');
  const galleryInput = document.getElementById('gallery-input');
  const cameraInput = document.getElementById('camera-input');
  const videoInput = document.getElementById('video-input');
  const selectedFilesList = document.getElementById('selectedFilesList');
  const fileManagementArea = document.getElementById('fileManagementArea');
  const totalFileCount = document.getElementById('totalFileCount');
  const clearAllFilesBtn = document.getElementById('clearAllFilesBtn');

  let map;
  let selectedFiles = [];
  let userMarker;

  // Caching configuration
  const CACHE_KEY_BASE = 'utba_swarms_cache';
  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  if (mapElement) {
    if (window.MAPBOX_TOKEN && window.MAPBOX_TOKEN !== '') {
      if (typeof mapboxgl === 'undefined') {
        console.warn(
          'Mapbox GL JS is not loaded. Check script include in footer.html.',
        );
        mapElement.innerHTML =
          '<div class="alert alert-danger m-3">Mapbox library failed to load.</div>';
        return;
      }

      mapboxgl.accessToken = window.MAPBOX_TOKEN;

      try {
        map = new mapboxgl.Map({
          container: 'map',
          style: 'mapbox://styles/mapbox/streets-v12',
          center: [-79.3832, 43.6532],
          zoom: 11,
        });
      } catch (e) {
        console.warn('Failed to initialize Mapbox map:', e);
        mapElement.innerHTML = `<div class="alert alert-danger m-3">Map initialization error: ${e.message}</div>`;
        return;
      }

      map.addControl(new mapboxgl.NavigationControl());

      map.on('load', () => {
        // Initialize sources and layers
        map.addSource('swarms', {
          type: 'geojson',
          data: { type: 'FeatureCollection', features: [] },
          cluster: true,
          clusterMaxZoom: 14,
          clusterRadius: 50,
        });

        // Cluster layers
        map.addLayer({
          id: 'clusters',
          type: 'circle',
          source: 'swarms',
          filter: ['has', 'point_count'],
          paint: {
            'circle-color': [
              'step',
              ['get', 'point_count'],
              '#51bbd6',
              10,
              '#f1f075',
              30,
              '#f28cb1',
            ],
            'circle-radius': [
              'step',
              ['get', 'point_count'],
              20,
              10,
              30,
              30,
              40,
            ],
            'circle-stroke-width': 2,
            'circle-stroke-color': '#fff',
          },
        });

        map.addLayer({
          id: 'cluster-count',
          type: 'symbol',
          source: 'swarms',
          filter: ['has', 'point_count'],
          layout: {
            'text-field': '{point_count_abbreviated}',
            'text-font': ['DIN Offc Pro Medium', 'Arial Unicode MS Bold'],
            'text-size': 12,
          },
        });

        // Unclustered points
        map.addLayer({
          id: 'unclustered-point',
          type: 'circle',
          source: 'swarms',
          filter: ['!', ['has', 'point_count']],
          paint: {
            'circle-color': [
              'match',
              ['get', 'displayStatus'],
              'Verified',
              '#fbc531',
              'Claimed',
              '#ff8c00',
              'Captured',
              '#4cd137',
              'Archived',
              '#487eb0',
              '#e84118', // Default Red-Orange for Reported
            ],
            'circle-radius': 10,
            'circle-stroke-width': 2,
            'circle-stroke-color': '#fff',
          },
        });

        // Click on cluster to zoom in
        map.on('click', 'clusters', (e) => {
          const features = map.queryRenderedFeatures(e.point, {
            layers: ['clusters'],
          });
          const clusterId = features[0].properties.cluster_id;
          map
            .getSource('swarms')
            .getClusterExpansionZoom(clusterId, (err, zoom) => {
              if (err) return;
              map.easeTo({
                center: features[0].geometry.coordinates,
                zoom: zoom,
              });
            });
        });

        // Click on unclustered point to show popup
        map.on('click', 'unclustered-point', (e) => {
          const coordinates = e.features[0].geometry.coordinates.slice();
          const swarm = e.features[0].properties;

          // Ensure that if the map is zoomed out such that multiple
          // copies of the feature are visible, the popup appears
          // over the copy being pointed to.
          while (Math.abs(e.lngLat.lng - coordinates[0]) > 180) {
            coordinates[0] += e.lngLat.lng > coordinates[0] ? 360 : -360;
          }

          // Helper to parse potential stringified JSON from Mapbox properties
          const parseProp = (prop) => {
            if (typeof prop === 'string') {
              try {
                return JSON.parse(prop);
              } catch {
                return [];
              }
            }
            return prop || [];
          };

          const allMedia = [
            ...parseProp(swarm.reportedMediaURLs),
            ...parseProp(swarm.capturedMediaURLs),
            ...parseProp(swarm.mediaURLs),
          ];

          let popupContent = `
              <div class="swarm-popup">
                <h6 class="mb-1"><strong>${swarm.displayStatus}</strong></h6>
                <p class="mb-1 text-muted small"><i class="fa-solid fa-location-dot me-1"></i> ${swarm.nearestIntersection}</p>
                <p class="mb-2 small"><i class="fa-regular fa-clock me-1"></i> ${new Date(swarm.reportedTimestamp).toLocaleString()}</p>
                <div class="p-2 bg-light rounded small mb-2">${swarm.description}</div>
            `;

          if (allMedia.length > 0) {
            popupContent += `
                <div class="d-grid">
                    <button class="btn btn-sm btn-primary view-media-btn" data-media-urls='${JSON.stringify(allMedia)}'>
                        <i class="fa-solid fa-images me-1"></i> View ${allMedia.length} Photo/Video
                    </button>
                </div>
            `;
          }

          if (
            swarm.reporterName ||
            swarm.reporterPhone ||
            swarm.reporterEmail
          ) {
            popupContent +=
              '<hr class="my-2"><small><strong>Reporter Contact:</strong><br>';
            if (swarm.reporterName)
              popupContent += `Name: ${swarm.reporterName}<br>`;
            if (swarm.reporterPhone)
              popupContent += `Phone: ${swarm.reporterPhone}<br>`;
            if (swarm.reporterEmail)
              popupContent += `Email: ${swarm.reporterEmail}<br>`;
            popupContent += '</small>';
          }
          if (
            window.USER_ROLE &&
            ['collector', 'collector_admin', 'site_admin'].includes(
              window.USER_ROLE,
            ) &&
            ['Reported', 'Verified'].includes(swarm.status) &&
            !swarm.assignedCollectorID
          ) {
            popupContent += `
                <div class="d-grid mt-2 pt-2 border-top">
                    <form action="/claim_swarm" method="POST">
                        <input type="hidden" name="swarmID" value="${swarm.id}">
                        <input type="hidden" name="csrf_token" value="${window.CSRF_TOKEN}">
                        <button type="submit" class="btn btn-sm btn-success w-100">
                            <i class="fa-solid fa-hand-holding-heart me-1"></i> Claim Swarm
                        </button>
                    </form>
                </div>
            `;
          }
          popupContent += '</div>';

          new mapboxgl.Popup()
            .setLngLat(coordinates)
            .setHTML(popupContent)
            .addTo(map);
        });

        map.on('mouseenter', 'clusters', () => {
          map.getCanvas().style.cursor = 'pointer';
        });
        map.on('mouseleave', 'clusters', () => {
          map.getCanvas().style.cursor = '';
        });
        map.on('mouseenter', 'unclustered-point', () => {
          map.getCanvas().style.cursor = 'pointer';
        });
        map.on('mouseleave', 'unclustered-point', () => {
          map.getCanvas().style.cursor = '';
        });

        fetchSwarms();
      });

      // Map click for reporting
      map.on('click', async (e) => {
        // Don't trigger if clicking on a cluster or point
        const features = map.queryRenderedFeatures(e.point, {
          layers: ['clusters', 'unclustered-point'],
        });
        if (features.length > 0) return;

        const { lng, lat } = e.lngLat;
        const latInput = document.getElementById('latitude');
        const lngInput = document.getElementById('longitude');
        if (latInput) latInput.value = lat;
        if (lngInput) lngInput.value = lng;

        const intersectionInput = document.getElementById('intersection');
        if (intersectionInput) {
          const originalPlaceholder = intersectionInput.placeholder;
          intersectionInput.value = '';
          intersectionInput.placeholder = 'Fetching nearest intersection...';

          const intersection = await getNearestIntersection(lat, lng);
          intersectionInput.value = intersection;
          intersectionInput.placeholder = originalPlaceholder;
        }

        const reportModalEl = document.getElementById('reportSwarmModal');
        if (reportModalEl) {
          const reportModal =
            bootstrap.Modal.getOrCreateInstance(reportModalEl);
          reportModal.show();
        }
      });
    } else {
      console.error('Mapbox token is missing. Map will not be initialized.');
      mapElement.innerHTML =
        '<div class="alert alert-warning m-3">Mapbox token is missing. Please configure MAPBOX_ACCESS_TOKEN.</div>';
    }
  }

  // Render swarms on map and list
  const renderSwarms = (swarms) => {
    const debugSwarms = document.getElementById('debugSwarms');

    if (debugSwarms) debugSwarms.innerHTML = '';

    if (!Array.isArray(swarms)) {
      console.warn('Swarms data is not an array:', swarms);
      return;
    }

    // Update Mapbox source
    if (map && map.getSource('swarms')) {
      const geojson = {
        type: 'FeatureCollection',
        features: swarms.map((swarm) => ({
          type: 'Feature',
          geometry: {
            type: 'Point',
            coordinates: [swarm.longitude, swarm.latitude],
          },
          properties: {
            ...swarm,
            // Convert arrays to strings for Mapbox properties to avoid issues
            reportedMediaURLs: JSON.stringify(swarm.reportedMediaURLs || []),
            capturedMediaURLs: JSON.stringify(swarm.capturedMediaURLs || []),
            mediaURLs: JSON.stringify(swarm.mediaURLs || []),
          },
        })),
      };
      map.getSource('swarms').setData(geojson);
    }

    if (swarms.length === 0) {
      if (debugSwarms) {
        debugSwarms.innerHTML =
          '<div class="text-center p-3 text-muted">No swarms reported yet.</div>';
      }
      return;
    }

    if (debugSwarms) {
      swarms.forEach((swarm) => {
        const swarmDiv = document.createElement('div');
        swarmDiv.className = 'border-bottom mb-1 pb-1 hover-bg-light';
        swarmDiv.style.cursor = 'pointer';
        swarmDiv.innerHTML = `
                <div class="d-flex justify-content-between">
                    <strong>${swarm.displayStatus}</strong>
                    <small class="text-muted">${new Date(swarm.reportedTimestamp).toLocaleTimeString()}</small>
                </div>
                <div class="text-truncate small">${swarm.nearestIntersection}</div>
            `;
        swarmDiv.onclick = () => {
          if (map) {
            map.flyTo({
              center: [swarm.longitude, swarm.latitude],
              zoom: 16,
            });
          }
        };
        debugSwarms.appendChild(swarmDiv);
      });
    }
  };

  // Fetch and display swarms with caching
  const fetchSwarms = async (forceRefresh = false) => {
    const debugSwarms = document.getElementById('debugSwarms');
    const cacheKey = debugSwarms
      ? `${CACHE_KEY_BASE}_collector`
      : CACHE_KEY_BASE;

    if (!forceRefresh) {
      const cached = sessionStorage.getItem(cacheKey);
      if (cached) {
        try {
          const { timestamp, data } = JSON.parse(cached);
          if (Date.now() - timestamp < CACHE_TTL) {
            console.log('Using cached swarm data');
            renderSwarms(data);
            return;
          }
        } catch (e) {
          console.error('Cache parse error', e);
        }
      }
    }

    try {
      if (debugSwarms) {
        debugSwarms.innerHTML =
          '<div class="text-center p-2"><div class="spinner-border spinner-border-sm text-primary" role="status"></div> Loading...</div>';
      }

      const visitorId = localStorage.getItem('utba_visitor_id');
      const url =
        visitorId && !debugSwarms
          ? `/get_swarms?sessionId=${visitorId}`
          : '/get_swarms';
      const response = await fetch(url);
      if (!response.ok) throw new Error('Failed to fetch swarms');
      const swarms = await response.json();

      sessionStorage.setItem(
        cacheKey,
        JSON.stringify({
          timestamp: Date.now(),
          data: swarms,
        }),
      );

      renderSwarms(swarms);
    } catch (error) {
      console.warn('Error fetching swarms:', error);
      if (debugSwarms)
        debugSwarms.innerHTML =
          '<div class="alert alert-danger p-2 small">Error loading swarms.</div>';
    }
  };

  // Hook up refresh button if it exists
  const refreshMapBtn = document.getElementById('refreshMapBtn');
  if (refreshMapBtn) {
    refreshMapBtn.addEventListener('click', () => {
      fetchSwarms(true);
    });
  }

  const locateUser = (doPan = false) => {
    if (doPan) {
      const reportBtn = document.getElementById('reportSwarmBtn');
      if (reportBtn) {
        reportBtn.disabled = true;
        reportBtn.innerHTML =
          '<span class="spinner-border spinner-border-sm me-2"></span> Finding location...';
      }

      // Show modal immediately so user (and E2E tests) sees it's working
      const reportModalEl = document.getElementById('reportSwarmModal');
      const reportModal = bootstrap.Modal.getOrCreateInstance(reportModalEl);
      reportModal.show();
    }

    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const { latitude, longitude } = position.coords;

          const reportBtn = document.getElementById('reportSwarmBtn');
          if (reportBtn) {
            reportBtn.disabled = false;
            reportBtn.innerHTML =
              '<i class="fa-solid fa-location-dot me-2"></i> Report a Swarm at Your Location';
          }

          if (doPan && map) {
            map.flyTo({ center: [longitude, latitude], zoom: 15 });

            if (userMarker) userMarker.remove();
            userMarker = new mapboxgl.Marker({ color: '#ff0000' })
              .setLngLat([longitude, latitude])
              .setPopup(new mapboxgl.Popup().setHTML('<h6>Your Location</h6>'))
              .addTo(map)
              .togglePopup();

            const latInput = document.getElementById('latitude');
            const lngInput = document.getElementById('longitude');
            if (latInput) latInput.value = latitude;
            if (lngInput) lngInput.value = longitude;

            const intersectionInput = document.getElementById('intersection');
            if (intersectionInput) {
              const originalPlaceholder = intersectionInput.placeholder;
              intersectionInput.value = '';
              intersectionInput.placeholder = 'Fetching...';
              const intersection = await getNearestIntersection(
                latitude,
                longitude,
              );
              intersectionInput.value = intersection;
              intersectionInput.placeholder = originalPlaceholder;
            }
          }
        },
        (error) => {
          const reportBtn = document.getElementById('reportSwarmBtn');
          if (reportBtn) {
            reportBtn.disabled = false;
            reportBtn.innerHTML =
              '<i class="fa-solid fa-location-dot me-2"></i> Report a Swarm at Your Location';
          }
          console.warn('Could not get your location:', error.message);
        },
        { timeout: 10000, enableHighAccuracy: true },
      );
    } else {
      console.warn('Geolocation is not supported by this browser.');
    }
  };

  if (reportSwarmBtn) {
    reportSwarmBtn.addEventListener('click', () => locateUser(true));
  }

  // File Management
  const updateFileList = () => {
    if (selectedFiles.length > 0) {
      fileManagementArea.style.display = 'block';
      selectedFilesList.innerHTML = '';
      selectedFiles.forEach((file, index) => {
        const fileItem = document.createElement('div');
        fileItem.className =
          'd-flex justify-content-between align-items-center mb-2 p-2 border-bottom';
        fileItem.innerHTML = `
                    <div class="text-truncate me-2" style="max-width: 150px;">
                        <i class="${file.type.startsWith('image/') ? 'fa-solid fa-image text-primary' : 'fa-solid fa-video text-info'} me-2"></i>
                        ${file.name} <small class="text-muted">(${(file.size / (1024 * 1024)).toFixed(2)} MB)</small>
                    </div>
                    <div>
                        <button type="button" class="btn btn-sm btn-outline-primary preview-file-btn me-1" data-index="${index}" title="Preview file">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-danger remove-file-btn" data-index="${index}" aria-label="Remove file">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                `;
        selectedFilesList.appendChild(fileItem);
      });
      totalFileCount.textContent = selectedFiles.length + ' file(s) ready';

      document.querySelectorAll('.remove-file-btn').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          const index = parseInt(e.currentTarget.getAttribute('data-index'));
          selectedFiles.splice(index, 1);
          updateFileList();
        });
      });

      document.querySelectorAll('.preview-file-btn').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          const index = parseInt(e.currentTarget.getAttribute('data-index'));
          const previewURLs = selectedFiles.map(
            (file) =>
              URL.createObjectURL(file) +
              (file.type.startsWith('video/') ? '#video' : '#image'),
          );
          openMediaViewer(previewURLs, index);
        });
      });
    } else {
      fileManagementArea.style.display = 'none';
    }
  };

  if (galleryInput) {
    galleryInput.addEventListener('change', (e) => {
      for (let i = 0; i < e.target.files.length; i++) {
        const file = e.target.files[i];
        if (file.size > 50 * 1024 * 1024) {
          alert(`File ${file.name} is too large (max 50MB)`);
          continue;
        }
        selectedFiles.push(file);
      }
      updateFileList();
      galleryInput.value = '';
    });
  }

  if (cameraInput) {
    cameraInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        if (file.size > 50 * 1024 * 1024) {
          alert('File is too large (max 50MB)');
        } else {
          selectedFiles.push(file);
          updateFileList();
        }
      }
      cameraInput.value = '';
    });
  }

  if (videoInput) {
    videoInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        const file = e.target.files[0];
        if (file.size > 50 * 1024 * 1024) {
          alert('Video file is too large (max 50MB)');
        } else {
          selectedFiles.push(file);
          updateFileList();
        }
      }
      videoInput.value = '';
    });
  }

  if (clearAllFilesBtn) {
    clearAllFilesBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to clear all selected files?')) {
        selectedFiles = [];
        updateFileList();
      }
    });
  }

  if (reportSwarmForm) {
    reportSwarmForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      const submitBtn = reportSwarmForm.querySelector('button[type="submit"]');
      const originalBtnText = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Submitting...';

      try {
        const formData = new FormData(reportSwarmForm);
        formData.delete('media');
        selectedFiles.forEach((file) => {
          formData.append('media', file);
        });

        const prepareResponse = await fetch('/prepare_swarm', {
          method: 'POST',
          body: formData,
        });
        if (!prepareResponse.ok) {
          const errorText = await prepareResponse.text();
          throw new Error(errorText || 'Failed to prepare report');
        }
        const prepareData = await prepareResponse.json();

        const confirmFormData = new URLSearchParams();
        confirmFormData.append('referenceID', prepareData.referenceID);
        confirmFormData.append('description', prepareData.description);
        confirmFormData.append('latitude', prepareData.latitude);
        confirmFormData.append('longitude', prepareData.longitude);
        confirmFormData.append('intersection', prepareData.nearestIntersection);
        confirmFormData.append(
          'reporterName',
          document.getElementById('reporterName').value,
        );
        confirmFormData.append(
          'reporterEmail',
          document.getElementById('reporterEmail').value,
        );
        confirmFormData.append(
          'reporterPhone',
          document.getElementById('reporterPhone').value,
        );
        confirmFormData.append(
          'reporterSessionId',
          localStorage.getItem('utba_visitor_id'),
        );

        if (prepareData.mediaURLs) {
          prepareData.mediaURLs.forEach((url) => {
            confirmFormData.append('mediaURLs', url);
          });
        }

        const confirmResponse = await fetch('/confirm_swarm', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: confirmFormData,
        });

        if (!confirmResponse.ok) {
          const errorText = await confirmResponse.text();
          throw new Error(errorText || 'Failed to confirm report');
        }

        sessionStorage.removeItem(CACHE_KEY_BASE);
        sessionStorage.removeItem(`${CACHE_KEY_BASE}_collector`);

        alert('Swarm report submitted successfully!');
        reportSwarmForm.reset();
        selectedFiles = [];
        updateFileList();

        const reportModalEl = document.getElementById('reportSwarmModal');
        const reportModal = bootstrap.Modal.getInstance(reportModalEl);
        if (reportModal) reportModal.hide();

        window.location.reload();
      } catch (error) {
        console.error('Error submitting report:', error);
        alert('Error: ' + error.message);
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnText;
      }
    });
  }

  // Media Viewer
  let currentMediaIndex = 0;
  let mediaURLs = [];

  const updateMediaViewer = () => {
    const imgViewer = document.getElementById('media-viewer');
    const videoViewer = document.getElementById('video-viewer');
    const counter = document.getElementById('media-counter');
    const url = mediaURLs[currentMediaIndex];

    imgViewer.style.display = 'none';
    videoViewer.style.display = 'none';
    if (videoViewer.pause) videoViewer.pause();

    const isVideo =
      url
        .toLowerCase()
        .match(/\.(mp4|webm|mov|avi|3gp|mpeg|ogv|ts|mkv|m4v)$/) ||
      url.includes('video');

    if (isVideo) {
      videoViewer.src = url;
      videoViewer.style.display = 'block';
    } else {
      imgViewer.src = url;
      imgViewer.style.display = 'block';
    }

    counter.textContent = `${currentMediaIndex + 1} of ${mediaURLs.length}`;
    document
      .querySelectorAll('.media-nav')
      .forEach(
        (btn) => (btn.style.display = mediaURLs.length > 1 ? 'block' : 'none'),
      );
  };

  const navigateMedia = (step) => {
    currentMediaIndex =
      (currentMediaIndex + step + mediaURLs.length) % mediaURLs.length;
    updateMediaViewer();
  };

  const openMediaViewer = (urls, startIndex = 0) => {
    mediaURLs = urls;
    currentMediaIndex = startIndex;
    updateMediaViewer();
    const mediaModal = bootstrap.Modal.getOrCreateInstance(
      document.getElementById('media-viewer-modal'),
    );
    mediaModal.show();
  };

  document
    .querySelectorAll('.media-nav.prev')
    .forEach((btn) => btn.addEventListener('click', () => navigateMedia(-1)));
  document
    .querySelectorAll('.media-nav.next')
    .forEach((btn) => btn.addEventListener('click', () => navigateMedia(1)));

  document.addEventListener('click', function (e) {
    const btn = e.target.closest('.view-media-btn');
    if (btn) {
      try {
        const urls = JSON.parse(btn.getAttribute('data-media-urls'));
        openMediaViewer(urls);
      } catch (err) {
        console.error('Error parsing media URLs:', err);
      }
    }
  });

  locateUser(false);

  (function trackVisit() {
    let visitorId = localStorage.getItem('utba_visitor_id');
    if (!visitorId) {
      visitorId =
        Math.random().toString(36).substring(2, 15) +
        Math.random().toString(36).substring(2, 15);
      localStorage.setItem('utba_visitor_id', visitorId);
    }
    fetch('/api/track_visit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ visitorId: visitorId }),
    }).catch((err) => console.warn('Failed to track visit:', err));
  })();
});

async function getNearestIntersection(lat, lng) {
  if (window.MAPBOX_TOKEN && window.MAPBOX_TOKEN !== '') {
    try {
      const response = await fetch(
        `https://api.mapbox.com/geocoding/v5/mapbox.places/${lng},${lat}.json?access_token=${window.MAPBOX_TOKEN}&types=address,neighborhood,locality`,
      );
      if (!response.ok) throw new Error('Mapbox Geocoding error');
      const data = await response.json();
      if (data.features && data.features.length > 0)
        return data.features[0].place_name;
    } catch (error) {
      console.warn('Error getting intersection from Mapbox:', error);
    }
  }

  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`,
      {
        headers: {
          'User-Agent': 'utba-swarmmap (fkcurrie/utba-swarmmap)',
        },
      },
    );
    if (!response.ok) throw new Error('Nominatim error');
    const data = await response.json();
    return data.display_name || 'Unknown location';
  } catch (error) {
    console.warn('Error getting intersection:', error);
    return 'Could not fetch location';
  }
}
