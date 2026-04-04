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

// File Management
    const updateFileList = () => {
        if (selectedFiles.length > 0) {
            fileManagementArea.style.display = 'block';
            selectedFilesList.innerHTML = '';
            selectedFiles.forEach((file, index) => {
                const fileItem = document.createElement('div');
                fileItem.className = 'd-flex justify-content-between align-items-center mb-2 p-2 border-bottom';
                fileItem.innerHTML = `
                    <div class="text-truncate mr-2" style="max-width: 200px;">
                        <i class="${file.type.startsWith('image/') ? 'fas fa-image' : 'fas fa-video'} mr-2"></i>
                        ${file.name} <small class="text-muted">(${(file.size / (1024 * 1024)).toFixed(2)} MB)</small>
                    </div>
                    <button type="button" class="btn btn-sm btn-outline-danger remove-file-btn" data-index="${index}">
                        <i class="fas fa-times"></i>
                    </button>
                `;
                selectedFilesList.appendChild(fileItem);
            });
            totalFileCount.textContent = selectedFiles.length;
            
            document.querySelectorAll('.remove-file-btn').forEach(btn => {
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
            selectedFiles = [];
            updateFileList();
        });
    }

    // Form Submission
    if (reportSwarmForm) {
        reportSwarmForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const submitBtn = reportSwarmForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.textContent;
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Processing...';

            try {
                // 1. Prepare Swarm (Upload Files)
                const formData = new FormData(reportSwarmForm);
                // Remove existing media fields from formData if any (though there shouldn't be since they are not in the form)
                formData.delete('media');
                selectedFiles.forEach(file => {
                    formData.append('media', file);
                });

                const prepareResponse = await fetch('/prepare_swarm', {
                    method: 'POST',
                    body: formData
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
                confirmFormData.append('reporterName', document.getElementById('reporterName').value);
                confirmFormData.append('reporterEmail', document.getElementById('reporterEmail').value);
                confirmFormData.append('reporterPhone', document.getElementById('reporterPhone').value);
                
                // Add media URLs
                if (prepareData.mediaURLs) {
                    prepareData.mediaURLs.forEach(url => {
                        confirmFormData.append('mediaURLs', url);
                    });
                }

                const confirmResponse = await fetch('/confirm_swarm', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: confirmFormData
                });

                if (!confirmResponse.ok) {
                    const errorText = await confirmResponse.text();
                    throw new Error(errorText || 'Failed to confirm report');
                }

                alert('Swarm report submitted successfully!');
                reportSwarmForm.reset();
                selectedFiles = [];
                updateFileList();
                const reportModal = bootstrap.Modal.getInstance(document.getElementById('reportSwarmModal'));
                reportModal.hide();
                
                // Refresh page or update map (optional)
                window.location.reload();

            } catch (error) {
                console.error('Error submitting report:', error);
                alert('Error: ' + error.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = originalBtnText;
            }
        });
    }

    locateUser(false);
});

// Media Viewer Functionality
let currentMediaIndex = 0;
let mediaURLs = [];

function openMediaViewer(urls) {
    mediaURLs = urls;
    currentMediaIndex = 0;
    updateMediaViewer();
    const mediaModal = new bootstrap.Modal(document.getElementById('mediaViewerModal'));
    mediaModal.show();
}

function updateMediaViewer() {
    const imgViewer = document.getElementById('mediaViewer');
    const videoViewer = document.getElementById('videoViewer');
    const counter = document.getElementById('mediaCounter');
    const url = mediaURLs[currentMediaIndex];
    
    imgViewer.style.display = 'none';
    videoViewer.style.display = 'none';
    videoViewer.pause();
    
    const isVideo = url.toLowerCase().match(/\.(mp4|webm|mov|avi|3gp|mpeg|ogv|ts|mkv|m4v)$/) || 
                   url.includes('video'); // Basic check

    if (isVideo) {
        videoViewer.src = url;
        videoViewer.style.display = 'block';
    } else {
        imgViewer.src = url;
        imgViewer.style.display = 'block';
    }
    
    counter.textContent = `${currentMediaIndex + 1} of ${mediaURLs.length}`;
    
    // Hide nav buttons if only one item
    const navButtons = document.querySelectorAll('.media-nav');
    navButtons.forEach(btn => btn.style.display = mediaURLs.length > 1 ? 'block' : 'none');
}

function navigateMedia(step) {
    currentMediaIndex = (currentMediaIndex + step + mediaURLs.length) % mediaURLs.length;
    updateMediaViewer();
}

// Event delegation for dynamically (or statically) rendered view-media-btns
document.addEventListener('click', function(e) {
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
