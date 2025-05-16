# UTBA Swarm Map

A web application for tracking and managing bee swarms in the Greater Toronto Area. This application allows members of the public to report bee swarms and enables UTBA (Urban Toronto Beekeepers Association) members to manage and respond to swarm reports.

## Live Demo

[UTBA Swarm Map on Cloud Run](https://utba-swarmmap-rcemytjnza-pd.a.run.app)

> **Note:** This is a very early prototype. Features, functionality, and design are subject to rapid change and may be incomplete or unstable.

## Features

- Interactive map showing reported bee swarms
- Public swarm reporting with photo/video upload
- Swarm status tracking (Reported, Verified, Captured, Archived)
- Detailed swarm information including location and description
- Media upload support for photos and videos
- Nearest intersection detection
- Mobile-friendly interface

## Technical Stack

- Backend: Go (Golang)
- Frontend: HTML, CSS, JavaScript
- Database: Google Cloud Firestore
- Storage: Google Cloud Storage
- Hosting: Google Cloud Run
- Maps: OpenStreetMap with Leaflet.js

## Setup

1. Clone the repository:
```bash
git clone https://github.com/fkcurrie/utba-swarmmap.git
cd utba-swarmmap
```

2. Install Go dependencies:
```bash
go mod download
```

3. Set up Google Cloud:
   - Create a new project
   - Enable Firestore
   - Create a Cloud Storage bucket
   - Set up Cloud Run

4. Configure environment variables:
   - Set up Google Cloud credentials
   - Configure project ID and bucket name

5. Build and deploy:
```bash
gcloud builds submit --tag gcr.io/[PROJECT_ID]/utba-swarmmap
gcloud run deploy utba-swarmmap --image gcr.io/[PROJECT_ID]/utba-swarmmap --platform managed
```

## Known Issues

1. Map Display Issues
   - Not all swarm pins are visible on the map
   - Need to investigate marker clustering for better visualization

2. Media Upload
   - Multiple photo/video upload functionality needs fixing
   - File size limits and format validation need review

3. Authentication
   - Currently no authentication system
   - Need to implement Google/Apple sign-in
   - Need to add username/password authentication

4. Admin Features
   - Need to create an administrator dashboard
   - Add role-based access control
   - Implement swarm catcher specific features

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- UTBA (Urban Toronto Beekeepers Association)
- OpenStreetMap contributors
- Leaflet.js team 