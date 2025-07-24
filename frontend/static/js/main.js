document.addEventListener('DOMContentLoaded', function() {
    const mapElement = document.getElementById('map');
    const reportSwarmBtn = document.getElementById('reportSwarmBtn');
    let map;

    if (mapElement) {
        // Use setTimeout to ensure the map container is fully rendered
        setTimeout(() => {
            map = L.map('map').setView([43.6532, -79.3832], 12);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            }).addTo(map);

            map.on('click', async function(e) {
                document.getElementById('latitude').value = e.latlng.lat;
                document.getElementById('longitude').value = e.latlng.lng;
                
                const intersectionInput = document.getElementById('intersection');
                intersectionInput.value = "Fetching...";
                const intersection = await getNearestIntersection(e.latlng.lat, e.latlng.lng);
                intersectionInput.value = intersection;

                const reportModal = new bootstrap.Modal(document.getElementById('reportSwarmModal'));
                reportModal.show();
            });
        }, 0);
    }

    const locateUser = (doPan = false) => {
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(async position => {
                const userLatLng = [position.coords.latitude, position.coords.longitude];
                if (doPan && map) {
                    map.setView(userLatLng, 15);
                    L.marker(userLatLng).addTo(map).bindPopup("Your Location").openPopup();
                    document.getElementById('latitude').value = userLatLng[0];
                    document.getElementById('longitude').value = userLatLng[1];
                    
                    const intersectionInput = document.getElementById('intersection');
                    intersectionInput.value = "Fetching...";
                    const intersection = await getNearestIntersection(userLatLng[0], userLatLng[1]);
                    intersectionInput.value = intersection;

                    const reportModal = new bootstrap.Modal(document.getElementById('reportSwarmModal'));
                    reportModal.show();
                }
            }, error => {
                if (doPan) alert("Could not get your location. Error: " + error.message);
            }, { timeout: 20000, enableHighAccuracy: true });
        }
    };

    if (reportSwarmBtn) {
        reportSwarmBtn.addEventListener('click', () => locateUser(true));
    }

    locateUser(false);
});

async function getNearestIntersection(lat, lng) {
    try {
        const response = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}`);
        const data = await response.json();
        return data.display_name || "Unknown location";
    } catch (error) {
        console.error('Error getting intersection:', error);
        return "Could not fetch location";
    }
}
