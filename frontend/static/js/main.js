document.addEventListener('DOMContentLoaded', function () {
  const mapElement = document.getElementById('map');
  const reportSwarmBtn = document.getElementById('reportSwarmBtn');
  let map;

  if (mapElement) {
    // Use setTimeout to ensure the map container is fully rendered
    setTimeout(() => {
      map = L.map('map').setView([43.6532, -79.3832], 12);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution:
          '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      }).addTo(map);

      map.on('click', async function (e) {
        document.getElementById('latitude').value = e.latlng.lat;
        document.getElementById('longitude').value = e.latlng.lng;

        const intersectionInput = document.getElementById('intersection');
        intersectionInput.value = 'Fetching...';
        const intersection = await getNearestIntersection(
          e.latlng.lat,
          e.latlng.lng,
        );
        intersectionInput.value = intersection;

        const reportModal = new bootstrap.Modal(
          document.getElementById('reportSwarmModal'),
        );
        reportModal.show();
      });

      // Fetch and display swarms
      const fetchSwarms = async () => {
        try {
          const response = await fetch('/get_swarms');
          const swarms = await response.json();

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
            }).addTo(map);

            marker.bindPopup(`
              <strong>${swarm.displayStatus}</strong><br>
              ${swarm.nearestIntersection}<br>
              <small>${new Date(swarm.reportedTimestamp).toLocaleString()}</small><br>
              <p>${swarm.description}</p>
            `);
          });
        } catch (error) {
          console.error('Error fetching swarms:', error);
        }
      };

      fetchSwarms();
    }, 0);
  }

  const locateUser = (doPan = false) => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          const userLatLng = [
            position.coords.latitude,
            position.coords.longitude,
          ];
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

  // Form submission and file management
  const reportSwarmForm = document.getElementById('reportSwarmForm');
  const galleryInput = document.getElementById('gallery-input');
  const cameraInput = document.getElementById('camera-input');
  const selectedFilesList = document.getElementById('selectedFilesList');
  const fileManagementArea = document.getElementById('fileManagementArea');
  const totalFileCount = document.getElementById('totalFileCount');
  const clearAllFilesBtn = document.getElementById('clearAllFilesBtn');

  let selectedFiles = [];

  const updateFileList = () => {
    selectedFilesList.innerHTML = '';
    if (selectedFiles.length === 0) {
      fileManagementArea.style.display = 'none';
      return;
    }

    fileManagementArea.style.display = 'block';
    totalFileCount.textContent = selectedFiles.length;

    selectedFiles.forEach((file, index) => {
      const div = document.createElement('div');
      div.className =
        'd-flex justify-content-between align-items-center mb-1 p-1 border-bottom';
      div.innerHTML = `
        <small class="text-truncate" style="max-width: 200px;">${file.name}</small>
        <button type="button" class="btn btn-sm btn-link text-danger remove-file-btn" data-index="${index}">
          <i class="fas fa-times"></i>
        </button>
      `;
      selectedFilesList.appendChild(div);
    });

    document.querySelectorAll('.remove-file-btn').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.currentTarget.dataset.index);
        selectedFiles.splice(index, 1);
        updateFileList();
      });
    });
  };

  if (galleryInput) {
    galleryInput.addEventListener('change', (e) => {
      selectedFiles = [...selectedFiles, ...Array.from(e.target.files)];
      updateFileList();
    });
  }

  if (cameraInput) {
    cameraInput.addEventListener('change', (e) => {
      selectedFiles = [...selectedFiles, ...Array.from(e.target.files)];
      updateFileList();
    });
  }

  if (clearAllFilesBtn) {
    clearAllFilesBtn.addEventListener('click', () => {
      selectedFiles = [];
      updateFileList();
    });
  }

  if (reportSwarmForm) {
    reportSwarmForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = reportSwarmForm.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Submitting...';

      const formData = new FormData(reportSwarmForm);
      // Add a unique reference ID
      formData.append(
        'referenceID',
        Math.random().toString(36).substring(2, 15) +
          Math.random().toString(36).substring(2, 15),
      );

      // Add files
      selectedFiles.forEach((file) => {
        formData.append('media', file);
      });

      // Add session ID for tracking
      formData.append(
        'reporterSessionId',
        localStorage.getItem('utba_visitor_id'),
      );

      try {
        const response = await fetch('/confirm_swarm', {
          method: 'POST',
          body: formData,
        });

        if (response.ok) {
          alert('Swarm report submitted successfully!');
          location.reload();
        } else {
          const errorText = await response.text();
          alert('Failed to submit report: ' + errorText);
        }
      } catch (error) {
        console.error('Error submitting report:', error);
        alert('An error occurred while submitting the report.');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Submit Report';
      }
    });
  }

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
  try {
    const response = await fetch(
      `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`,
    );
    const data = await response.json();
    return data.display_name || 'Unknown location';
  } catch (error) {
    console.error('Error getting intersection:', error);
    return 'Could not fetch location';
  }
}
