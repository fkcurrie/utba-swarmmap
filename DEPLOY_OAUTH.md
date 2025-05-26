# Google OAuth2 Deployment Guide

## Step 1: Set up Google OAuth2 Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Select your `utba-swarmmap` project
3. Navigate to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth 2.0 Client IDs**
5. Choose **Web application**
6. Set these **Authorized redirect URIs**:
   - `https://utba-swarmmap-18499119240.northamerica-northeast2.run.app/auth/google/callback`
   - `http://localhost:8080/auth/google/callback` (for local testing)
7. Save and copy the **Client ID** and **Client Secret**

## Step 2: Update Cloud Build Substitutions

Before deploying, update the substitutions in `cloudbuild.yaml`:

```yaml
substitutions:
  _GOOGLE_CLIENT_ID: 'your-actual-google-client-id'
  _GOOGLE_CLIENT_SECRET: 'your-actual-google-client-secret'  
  _GOOGLE_REDIRECT_URL: 'https://utba-swarmmap-18499119240.northamerica-northeast2.run.app/auth/google/callback'
```

## Step 3: Deploy the Application

```bash
gcloud builds submit --config cloudbuild.yaml .
```

## Step 4: Create Initial Admin User

1. Visit: `https://utba-swarmmap-18499119240.northamerica-northeast2.run.app/bootstrap`
2. Enter the email address you want to use as admin (must match the Google account you'll sign in with)
3. Enter the full name for the admin user
4. Click "Create Admin"

## Step 5: Test the Authentication

1. Visit: `https://utba-swarmmap-18499119240.northamerica-northeast2.run.app/login`
2. Click "Sign in with Google"
3. Use the same Google account email you set as admin
4. You should be redirected to the admin dashboard

## How It Works

### For Public Users
- Can report swarms without any authentication
- Main map remains completely open to the public

### For Swarm Collectors
- Must sign in with Google
- New users are automatically created with "pending" status
- Require admin approval before accessing the dashboard

### For Administrators
- Must sign in with Google  
- Can approve/reject pending users
- Can delete swarm reports
- Full access to all features

## Benefits of Google OAuth2

- **No password management**: Users sign in with their existing Google accounts
- **Better security**: Google handles all authentication security
- **Verified emails**: All users have verified email addresses
- **Familiar experience**: Users are comfortable with Google Sign-In
- **Easy user management**: Admins can approve users based on verified email addresses

## Environment Variables

The application needs these environment variables:
- `GOOGLE_CLIENT_ID`: Your Google OAuth2 client ID
- `GOOGLE_CLIENT_SECRET`: Your Google OAuth2 client secret  
- `GOOGLE_REDIRECT_URL`: The callback URL for OAuth2 flow 