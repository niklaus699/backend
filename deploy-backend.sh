#!/bin/bash
# Sentinel Backend Deployment Script for Google Cloud Run
# Usage: ./deploy-backend.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Sentinel Backend Deployment Script       ║${NC}"
echo -e "${GREEN}║  Google Cloud Run + Neon + Upstash        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"

# Check prerequisites
echo -e "\n${YELLOW}Checking prerequisites...${NC}"

if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI not found. Install from: https://cloud.google.com/sdk${NC}"
    exit 1
fi

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found. Install from: https://www.docker.com/products/docker-desktop${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Prerequisites OK${NC}"

# Get configuration
echo -e "\n${YELLOW}Configuration:${NC}"
read -p "Enter GCP Project ID (e.g., sentinel-prod): " PROJECT_ID
read -p "Enter Cloud Run service name (e.g., sentinel-backend): " SERVICE_NAME
read -p "Enter region (e.g., us-central1): " REGION
read -p "Enter Docker image name (e.g., sentinel-backend): " IMAGE_NAME

echo -e "\n${YELLOW}Environment Variables (press Enter to skip optional):${NC}"
read -p "Enter DATABASE_URL: " DATABASE_URL
read -p "Enter REDIS_URL: " REDIS_URL
read -p "Enter SECRET_KEY: " SECRET_KEY
read -p "Enter ALLOWED_HOSTS (comma-separated): " ALLOWED_HOSTS
read -p "Enter CORS_ALLOWED_ORIGINS: " CORS_ALLOWED_ORIGINS
read -p "Enter SENTRY_DSN (optional): " SENTRY_DSN

# Set up GCP project
echo -e "\n${YELLOW}Setting up GCP project...${NC}"
gcloud config set project $PROJECT_ID
gcloud services enable run.googleapis.com container.googleapis.com cloudbuild.googleapis.com

# Create secrets
echo -e "\n${YELLOW}Creating Cloud secrets...${NC}"
echo -n "$SECRET_KEY" | gcloud secrets create django-secret-key --data-file=- 2>/dev/null || gcloud secrets versions add django-secret-key --data-file=-
echo -n "$DATABASE_URL" | gcloud secrets create database-url --data-file=- 2>/dev/null || gcloud secrets versions add database-url --data-file=-
echo -n "$REDIS_URL" | gcloud secrets create redis-url --data-file=- 2>/dev/null || gcloud secrets versions add redis-url --data-file=-

# Build Docker image
echo -e "\n${YELLOW}Building Docker image...${NC}"
gcloud builds submit --tag gcr.io/$PROJECT_ID/$IMAGE_NAME:latest

# Deploy to Cloud Run
echo -e "\n${YELLOW}Deploying to Cloud Run...${NC}"
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$IMAGE_NAME:latest \
  --platform managed \
  --region $REGION \
  --memory 512Mi \
  --cpu 1 \
  --timeout 3600 \
  --max-instances 2 \
  --set-env-vars "DJANGO_SETTINGS_MODULE=config.settings.production,ALLOWED_HOSTS=$ALLOWED_HOSTS,CORS_ALLOWED_ORIGINS=$CORS_ALLOWED_ORIGINS" \
  --set-secrets "SECRET_KEY=django-secret-key:latest,DATABASE_URL=database-url:latest,REDIS_URL=redis-url:latest" \
  --allow-unauthenticated

# Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME --region $REGION --format='value(status.url)')

echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Deployment Successful! ✅                 ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo -e "\n${YELLOW}Service URL:${NC} ${GREEN}$SERVICE_URL${NC}"
echo -e "\n${YELLOW}Next steps:${NC}"
echo "1. Update frontend VITE_API_URL to: $SERVICE_URL"
echo "2. Update frontend VITE_WS_URL to: ${SERVICE_URL/http/ws}"
echo "3. Deploy frontend to Vercel"
echo -e "\n${YELLOW}Test health check:${NC}"
echo "curl $SERVICE_URL/api/health/"
echo -e "\n${YELLOW}View logs:${NC}"
echo "gcloud run logs read $SERVICE_NAME --region $REGION --follow"
