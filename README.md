# Toronto Map Web Application

A simple web application that displays an interactive map of Toronto using OpenStreetMap and Folium.

## Local Development

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

The application will be available at http://localhost:8080

## Deployment

This application is configured to be deployed to Google Cloud Run using Cloud Build.

### Prerequisites

1. Google Cloud SDK installed
2. Docker installed
3. Access to Google Cloud Platform (GCP) project
4. Cloud Build API enabled
5. Container Registry API enabled
6. Cloud Run API enabled

### Deployment Steps

1. Initialize your GCP project:
```bash
gcloud config set project YOUR_PROJECT_ID
```

2. Enable required APIs:
```bash
gcloud services enable cloudbuild.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

3. Push your code to GitHub:
```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/fkcurrie/toronto-map.git
git push -u origin main
```

4. Connect your GitHub repository to Cloud Build:
   - Go to Cloud Build > Triggers in the GCP Console
   - Click "Connect Repository"
   - Select GitHub and authorize
   - Select your repository
   - Create a trigger that builds on push to main branch

The application will be automatically built and deployed when you push changes to the main branch.

## Accessing the Application

Once deployed, the application will be available at a URL provided by Cloud Run. You can find this URL in the Cloud Run console or by running:

```bash
gcloud run services describe toronto-map --platform managed --region us-central1 --format 'value(status.url)'
``` 