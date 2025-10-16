# AWS Deployment Guide

## Prerequisites
- AWS CLI installed and configured (`aws configure`)
- Appropriate AWS permissions for Lambda, IAM, and CloudFormation

## Option 1: SAM Deployment (Recommended)
1. Install SAM CLI: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html
2. Run: `./deploy.sh`
3. Follow the guided prompts

## Option 2: Manual Deployment
1. Run: `./deploy-manual.sh`
2. Script will create IAM role, Lambda function, and Function URL automatically

## Testing
Once deployed, you'll get a Function URL. Test with:
```bash
curl https://YOUR-FUNCTION-URL.lambda-url.us-east-1.on.aws/
```

The API returns the exact same text output as running the script locally.

## Files
- `template.yaml` - SAM/CloudFormation template
- `lambda_function.py` - Lambda handler wrapper
- `deploy.sh` - SAM deployment script
- `deploy-manual.sh` - Manual AWS CLI deployment script