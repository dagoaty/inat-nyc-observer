#!/bin/bash

# AWS Lambda deployment script using SAM
# Make sure you have AWS CLI and SAM CLI configured with appropriate permissions

set -e

echo "Deploying iNaturalist NYC Observer to AWS Lambda..."

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    echo "SAM CLI is not installed. Please install it first:"
    echo "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"
    exit 1
fi

# Check if AWS CLI is configured with mcp profile
if ! aws sts get-caller-identity --profile mcp &> /dev/null; then
    echo "AWS CLI mcp profile is not configured. Please configure it first."
    exit 1
fi

# Build the application
echo "Building SAM application..."
sam build

# Deploy the application
echo "Deploying to AWS..."
sam deploy --guided --stack-name inat-nyc-observer-stack --profile mcp

echo ""
echo "Deployment complete!"
echo "Your API endpoint URL will be shown in the CloudFormation outputs above."