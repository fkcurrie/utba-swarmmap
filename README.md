<!-- Copyright (c) 2026 Frank Currie (frank@sfle.ca) -->
# UTBA Swarm Map

A web application for tracking and managing bee swarms. This application allows the public to report bee swarms and enables beekeepers to manage and respond to those reports.

## Project Structure

The application has been refactored into a modern, multi-service architecture to improve development velocity and scalability.

- **/backend**: A Go service that provides the main API, handles business logic, manages the database, and renders HTML templates.
- **/frontend**: A lightweight Go service whose sole responsibility is to serve static assets (CSS, JavaScript, images, vendor libraries) efficiently.
- **/node_modules**: Contains frontend development dependencies like Chart.js.

This separation allows the frontend (styling, UI logic) to be developed and deployed independently of the backend, which is ideal for rapid UI iteration.

## Features

- **Interactive Map**: Shows reported bee swarms using OpenStreetMap and Leaflet.js.
- **Public Swarm Reporting**: Anyone can report a swarm, optionally including photos and videos.
- **Camera & Gallery Upload**: On mobile, users can either take a new photo/video or upload an existing one from their gallery.
- **Admin Dashboard**: A comprehensive dashboard for administrators to manage users and swarms.
- **Interactive Site Traffic Chart**: The admin dashboard features a dynamic chart to visualize site visits over various time ranges (7 days, 30 days, etc.).
- **Role-Based Access Control**: Differentiates between regular users, collectors, and site administrators.

## Tech Stack

- **Backend**: Go
- **Frontend**: Go (for serving), HTML, CSS, vanilla JavaScript
- **UI Libraries**: Bootstrap, [Chart.js](https://www.chartjs.org/), Leaflet.js
- **Database**: Google Cloud Firestore
- **Storage**: Google Cloud Storage
- **Deployment**: Docker, Google Cloud Run

## Local Development & Deployment

The primary workflow is to build Docker images locally, push them to a container registry, and deploy to Cloud Run. This provides a fast feedback loop, especially for frontend changes.

### Prerequisites

- [Go](https://golang.org/) installed
- [Docker](https://www.docker.com/) installed and running
- [Google Cloud SDK](https://cloud.google.com/sdk) (`gcloud`) installed and authenticated
- A Google Cloud Project with the Cloud Run and Cloud Build APIs enabled.

### Running Locally (Coming Soon)

Instructions for running each service locally will be added in a future update.

### Automated Deployment (GitHub Actions)

This project includes a GitHub Actions workflow for automated validation and deployment to Google Cloud Run.

- **Workflow File**: `deployment/deploy.yml`
- **Action Required**: Due to repository permission restrictions for automated agents, the workflow file must be manually moved to `.github/workflows/deploy.yml` to trigger the automated CI/CD pipeline.
- **Trigger**: The workflow is configured to trigger on any tag matching `v*` (e.g., `v0.6`).
- **Secrets**: The following GitHub repository secrets must be configured:
  - `GCP_PROJECT_ID`: Your Google Cloud Project ID.
  - `GCP_SA_KEY`: A JSON key for a Service Account with permissions to build images and deploy to Cloud Run.

### Manual Deployment

Both the frontend and backend have their own `Dockerfile` and can be deployed independently.

**1. Deploy the Backend:**

```bash
# Navigate to the backend directory
cd backend

# Build the Docker image
docker build -t northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/backend:latest .

# Push the image to Google Artifact Registry
docker push northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/backend:latest

# Deploy to Cloud Run
gcloud run deploy utba-swarmmap-backend \
  --image northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/backend:latest \
  --platform managed \
  --region northamerica-northeast2 \
  --allow-unauthenticated \
  --port 8080
```

**2. Deploy the Frontend:**

After the initial backend deployment, get the backend service URL. You will need to provide this URL to the frontend service.

```bash
# Navigate to the frontend directory
cd frontend

# Build the Docker image
docker build -t northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/frontend:latest .

# Push the image to Google Artifact Registry
docker push northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/frontend:latest

# Deploy to Cloud Run
gcloud run deploy utba-swarmmap-frontend \
  --image northamerica-northeast2-docker.pkg.dev/[PROJECT_ID]/swarmmap-repo/frontend:latest \
  --platform managed \
  --region northamerica-northeast2 \
  --allow-unauthenticated
```

After the frontend is deployed, you must **re-deploy the backend** one more time, setting the `FRONTEND_ASSETS_URL` environment variable to the URL of your newly deployed frontend service. This allows the backend to load assets from the correct location.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
