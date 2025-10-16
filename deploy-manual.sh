#!/bin/bash

# Manual AWS Lambda deployment script (without SAM)
# Make sure you have AWS CLI configured with appropriate permissions

set -e

FUNCTION_NAME="inat-nyc-observer"
ROLE_NAME="inat-lambda-execution-role"

echo "Manual deployment of iNaturalist NYC Observer to AWS Lambda..."

# Check if AWS CLI is configured
if ! aws sts get-caller-identity --profile mcp &> /dev/null; then
    echo "AWS CLI mcp profile is not configured. Please configure it first."
    exit 1
fi

# Get account ID
ACCOUNT_ID=$(aws sts get-caller-identity --profile mcp --query Account --output text)
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

echo "Using AWS Account ID: $ACCOUNT_ID"

# Create IAM role if it doesn't exist
if ! aws iam get-role --role-name $ROLE_NAME --profile mcp &> /dev/null; then
    echo "Creating IAM role: $ROLE_NAME"
    
    # Create trust policy
    cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

    aws iam create-role \
        --role-name $ROLE_NAME \
        --assume-role-policy-document file://trust-policy.json \
        --profile mcp

    # Attach basic execution policy
    aws iam attach-role-policy \
        --role-name $ROLE_NAME \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
        --profile mcp

    rm trust-policy.json
    echo "Waiting for role to be ready..."
    sleep 10
else
    echo "IAM role $ROLE_NAME already exists"
fi

# Create deployment package
echo "Creating deployment package..."
rm -f lambda-deployment.zip
zip -r lambda-deployment.zip lambda_function.py src/

# Install dependencies to a temp directory and add to zip
echo "Installing dependencies..."
pip install -r requirements.txt -t ./temp-deps/
cd temp-deps && zip -r ../lambda-deployment.zip . && cd ..
rm -rf temp-deps

# Check if function exists
if aws lambda get-function --function-name $FUNCTION_NAME --profile mcp &> /dev/null; then
    echo "Updating existing function: $FUNCTION_NAME"
    aws lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://lambda-deployment.zip \
        --profile mcp
else
    echo "Creating new function: $FUNCTION_NAME"
    aws lambda create-function \
        --function-name $FUNCTION_NAME \
        --runtime python3.9 \
        --role $ROLE_ARN \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda-deployment.zip \
        --timeout 30 \
        --memory-size 128 \
        --profile mcp
fi

# Create or update function URL
echo "Creating function URL..."
FUNCTION_URL=$(aws lambda create-function-url-config \
    --function-name $FUNCTION_NAME \
    --auth-type NONE \
    --cors AllowCredentials=false,AllowHeaders="*",AllowMethods="GET,POST",AllowOrigins="*",MaxAge=86400 \
    --query FunctionUrl --output text \
    --profile mcp 2>/dev/null || \
    aws lambda get-function-url-config \
    --function-name $FUNCTION_NAME \
    --query FunctionUrl --output text \
    --profile mcp)

echo ""
echo "✅ Deployment complete!"
echo "📍 Function URL: $FUNCTION_URL"
echo ""
echo "Test your API:"
echo "curl $FUNCTION_URL"

# Cleanup
rm -f lambda-deployment.zip