// Copyright (c) 2026 Frank Currie (frank@sfle.ca)

document.addEventListener('DOMContentLoaded', function () {
  const mapElement = document.getElementById('map');
  const reportSwarmBtn = document.getElementById('reportSwarmBtn');
  const reportSwarmForm = document.getElementById('reportSwarmForm');
  const galleryInput = document.getElementById('gallery-input');
  const cameraInput = document.getElementById('camera-input');
  const selectedFilesList = document.getElementById('selectedFilesList');
  const fileManagementArea = document.getElementById('fileManagementArea');
  const totalFileCount = document.getElementById('totalFileCount');
  const clearAllFilesBtn = document.getElementById('clearAllFilesBtn');

  let map;
  let selectedFiles = [];
  let swarmLayerGroup;

  // Caching configuration
  const CACHE_KEY_BASE = 'utba_swarms_cache';
  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  if (mapElement) {
    // Use setTimeout to ensure the map container is fully rendered
    setTimeout(() => {
      map = L.map('map').setView([43.6532, -79.3832], 12);

      let tileLayer;
      if (window.MAPBOX_TOKEN && window.MAPBOX_TOKEN !== '') {
        tileLayer = L.tileLayer(
          'https://api.mapbox.com/styles/v1/mapbox/streets-v12/tiles/{z}/{x}/{y}?access_token=' +
            window.MAPBOX_TOKEN,
          {
            attribution:
              '© <a href="https://www.mapbox.com/about/maps/">Mapbox</a> © <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a> <strong><a href="https://www.mapbox.com/map-feedback/" target="_blank">Improve this map</a></strong>',
            tileSize: 512,
            zoomOffset: -1,
          },
        );
      } else {
        tileLayer = L.tileLayer(
          'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
          {
            attribution:
              '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
          },
        );
      }
      tileLayer.addTo(map);

      // Initialize Marker Cluster Group
      swarmLayerGroup = L.markerClusterGroup({
        showCoverageOnHover: false,
        zoomToBoundsOnClick: true,
        spiderfyOnMaxZoom: true,
      }).addTo(map);

      map.on('click', async function (e) {
        document.getElementById('latitude').value = e.latlng.lat;
        document.getElementById('longitude').value = e.latlng.lng;

        const intersectionInput = document.getElementById('intersection');
        const originalPlaceholder = intersectionInput.placeholder;
        intersectionInput.value = '';
        intersectionInput.placeholder = 'Fetching nearest intersection...';

        const intersection = await getNearestIntersection(
          e.latlng.lat,
          e.latlng.lng,
        );
        intersectionInput.value = intersection;
        intersectionInput.placeholder = originalPlaceholder;

        const reportModal = new bootstrap.Modal(
          document.getElementById('reportSwarmModal'),
        );
        reportModal.show();
      });

      // Render swarms on map
      const renderSwarms = (swarms) => {
        const debugSwarms = document.getElementById('debugSwarms');

        if (!swarmLayerGroup) return;
        swarmLayerGroup.clearLayers();
        if (debugSwarms) debugSwarms.innerHTML = '';

        if (!Array.isArray(swarms)) {
          console.warn('Swarms data is not an array:', swarms);
          return;
        }

        if (swarms.length === 0) {
          if (debugSwarms) {
            debugSwarms.innerHTML =
              '<div class="text-center p-3 text-muted">No swarms reported yet.</div>';
          }
          return;
        }

        swarms.forEach((swarm) => {
          let color = '#ff0000'; // Default Red for Reported
          if (swarm.displayStatus === 'Verified') color = '#ff69b4'; // Pink
          if (swarm.displayStatus === 'Captured') color = '#00ff00'; // Green
          if (swarm.displayStatus === 'Archived') color = '#0000ff'; // Blue

          const marker = L.circleMarker([swarm.latitude, swarm.longitude], {
            radius: 10,
            fillColor: color,
            color: '#fff',
            weight: 2,
            opacity: 1,
            fillOpacity: 0.8,
          });

          let popupContent = `
              <div class="swarm-popup">
                <h6 class="mb-1"><strong>${swarm.displayStatus}</strong></h6>
                <p class="mb-1 text-muted small"><i class="fa-solid fa-location-dot me-1"></i> ${swarm.nearestIntersection}</p>
                <p class="mb-2 small"><i class="fa-regular fa-clock me-1"></i> ${new Date(swarm.reportedTimestamp).toLocaleString()}</p>
                <div class="p-2 bg-light rounded small mb-2">${swarm.description}</div>
            `;

          // Combine media URLs from all possible fields
          const allMedia = [
            ...(swarm.reportedMediaURLs || []),
            ...(swarm.capturedMediaURLs || []),
            ...(swarm.mediaURLs || []), // For compatibility with older data or PrepareSwarm
          ];

          // Add media button if URLs exist
          if (allMedia.length > 0) {
            popupContent += `
                <div class="d-grid">
                    <button class="btn btn-sm btn-primary view-media-btn" data-media-urls='${JSON.stringify(allMedia)}'>
                        <i class="fa-solid fa-images me-1"></i> View ${allMedia.length} Photo/Video
                    </button>
                </div>
            `;
          }

          // Add contact info for collectors if available
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

          popupContent += '</div>';

          marker.bindPopup(popupContent);
          swarmLayerGroup.addLayer(marker);

          if (debugSwarms) {
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
              map.setView([swarm.latitude, swarm.longitude], 16);
              marker.openPopup();
            };
            debugSwarms.appendChild(swarmDiv);
          }
        });
      };

      // Fetch and display swarms with caching
      const fetchSwarms = async (forceRefresh = false) => {
        const debugSwarms = document.getElementById('debugSwarms');
        const cacheKey = debugSwarms
          ? `${CACHE_KEY_BASE}_collector`
          : CACHE_KEY_BASE;

        // Check cache
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
          // Show loading state
          if (debugSwarms) {
            debugSwarms.innerHTML =
              '<div class="text-center p-2"><div class="spinner-border spinner-border-sm text-primary" role="status"></div> Loading...</div>';
          }

          const response = await fetch('/get_swarms');
          if (!response.ok) throw new Error('Failed to fetch swarms');
          const swarms = await response.json();

          // Update cache
          sessionStorage.setItem(
            cacheKey,
            JSON.stringify({
              timestamp: Date.now(),
              data: swarms,
            }),
          );

          renderSwarms(swarms);
        } catch (error) {
          console.error('Error fetching swarms:', error);
          if (debugSwarms)
            debugSwarms.innerHTML =
              '<div class="alert alert-danger p-2 small">Error loading swarms.</div>';
        }
      };

      fetchSwarms();

      // Hook up refresh button if it exists
      const refreshMapBtn = document.getElementById('refreshMapBtn');
      if (refreshMapBtn) {
        refreshMapBtn.addEventListener('click', () => {
          fetchSwarms(true);
        });
      }
    }, 0);
  }

  const locateUser = (doPan = false) => {
    if (navigator.geolocation) {
      if (doPan) {
        reportSwarmBtn.disabled = true;
        reportSwarmBtn.innerHTML =
          '<span class="spinner-border spinner-border-sm me-2"></span> Finding location...';
      }

      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const userLatLng = [
            position.coords.latitude,
            position.coords.longitude,
          ];

          if (reportSwarmBtn) {
            reportSwarmBtn.disabled = false;
            reportSwarmBtn.innerHTML =
              '<i class="fa-solid fa-location-dot me-2"></i> Report a Swarm at Your Location';
          }

          if (doPan && map) {
            map.setView(userLatLng, 15);
            L.marker(userLatLng)
              .addTo(map)
              .bindPopup('Your Location')
              .openPopup();
            document.getElementById('latitude').value = userLatLng[0];
            document.getElementById('longitude').value = userLatLng[1];

            const intersectionInput = document.getElementById('intersection');
            intersectionInput.value = 'Fetching...';
            const intersection = await getNearestIntersection(
              userLatLng[0],
              userLatLng[1],
            );
            intersectionInput.value = intersection;

            const reportModal = new bootstrap.Modal(
              document.getElementById('reportSwarmModal'),
            );
            reportModal.show();
          }
        },
        (error) => {
          if (reportSwarmBtn) {
            reportSwarmBtn.disabled = false;
            reportSwarmBtn.innerHTML =
              '<i class="fa-solid fa-location-dot me-2"></i> Report a Swarm at Your Location';
          }
          if (doPan)
            alert('Could not get your location. Error: ' + error.message);
        },
        { timeout: 20000, enableHighAccuracy: true },
      );
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
                    <div class="text-truncate me-2" style="max-width: 200px;">
                        <i class="${file.type.startsWith('image/') ? 'fa-solid fa-image text-primary' : 'fa-solid fa-video text-info'} me-2"></i>
                        ${file.name} <small class="text-muted">(${(file.size / (1024 * 1024)).toFixed(2)} MB)</small>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-danger remove-file-btn" data-index="${index}" aria-label="Remove file">
                        <i class="fa-solid fa-xmark"></i>
                    </button>
                `;
        selectedFilesList.appendChild(fileItem);
      });
      totalFileCount.textContent = selectedFiles.length;

      document.querySelectorAll('.remove-file-btn').forEach((btn) => {
        btn.addEventListener('click', (e) => {
          const index = parseInt(e.currentTarget.getAttribute('data-index'));
          selectedFiles.splice(index, 1);
          updateFileList();
        });
      });
    } else {
      fileManagementArea.style.display = 'none';
    }
  };

  if (galleryInput) {
    galleryInput.addEventListener('change', (e) => {
      for (let i = 0; i < e.target.files.length; i++) {
        selectedFiles.push(e.target.files[i]);
      }
      updateFileList();
      galleryInput.value = ''; // Reset for next selection
    });
  }

  if (cameraInput) {
    cameraInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        selectedFiles.push(e.target.files[0]);
        updateFileList();
      }
      cameraInput.value = ''; // Reset
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
        // 1. Prepare Swarm (Upload Files)
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

        // 2. Confirm Swarm
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
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: confirmFormData,
        });

        if (!confirmResponse.ok) {
          const errorText = await confirmResponse.text();
          throw new Error(errorText || 'Failed to confirm report');
        }

        // Clear caches since new swarm is added
        sessionStorage.removeItem(CACHE_KEY_BASE);
        sessionStorage.removeItem(`${CACHE_KEY_BASE}_collector`);

        alert('Swarm report submitted successfully!');
        reportSwarmForm.reset();
        selectedFiles = [];
        updateFileList();

        const reportModalEl = document.getElementById('reportSwarmModal');
        const reportModal = bootstrap.Modal.getInstance(reportModalEl);
        if (reportModal) reportModal.hide();

        // Refresh page or update map
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

  // Media Viewer Functionality
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

    const navButtons = document.querySelectorAll('.media-nav');
    navButtons.forEach(
      (btn) => (btn.style.display = mediaURLs.length > 1 ? 'block' : 'none'),
    );
  };

  const navigateMedia = (step) => {
    currentMediaIndex =
      (currentMediaIndex + step + mediaURLs.length) % mediaURLs.length;
    updateMediaViewer();
  };

  const openMediaViewer = (urls) => {
    mediaURLs = urls;
    currentMediaIndex = 0;
    updateMediaViewer();
    const mediaModal = new bootstrap.Modal(
      document.getElementById('media-viewer-modal'),
    );
    mediaModal.show();
  };

  document.querySelectorAll('.media-nav.prev').forEach((btn) => {
    btn.addEventListener('click', () => navigateMedia(-1));
  });
  document.querySelectorAll('.media-nav.next').forEach((btn) => {
    btn.addEventListener('click', () => navigateMedia(1));
  });

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

  // Visit tracking
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
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ visitorId: visitorId }),
    }).catch((err) => console.error('Failed to track visit:', err));
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
      if (data.features && data.features.length > 0) {
        return data.features[0].place_name;
      }
    } catch (error) {
      console.error('Error getting intersection from Mapbox:', error);
      // Fallback to Nominatim below
    }
  }

  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`,
    );
    if (!response.ok) throw new Error('Nominatim error');
    const data = await response.json();
    return data.display_name || 'Unknown location';
  } catch (error) {
    console.error('Error getting intersection:', error);
    return 'Could not fetch location';
  }
}
