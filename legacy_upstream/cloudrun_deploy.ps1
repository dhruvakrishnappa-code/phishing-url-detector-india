# Cloud Run deploy helper (PowerShell)
# Fill $PROJECT and $IMAGE variables and run from repo root.

$PROJECT = '<YOUR_GCP_PROJECT>'
$REGION = 'us-central1'
$IMAGE = "gcr.io/$PROJECT/phishing-detector:latest"

Write-Host "Building and submitting image to Cloud Build..."
gcloud builds submit --tag $IMAGE .

Write-Host "Deploying to Cloud Run..."
gcloud run deploy phishing-detector --image $IMAGE --platform managed --region $REGION --allow-unauthenticated --set-env-vars=USE_ENRICH=0

Write-Host "Done. Use 'gcloud run services describe phishing-detector --region $REGION' to get URL."