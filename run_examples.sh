#!/bin/bash

echo "=== OpenSearch Snapshot IAM Setup Examples ==="
echo ""

echo "This script creates IAM resources for OpenSearch manual snapshots using ARNs."
echo ""

echo "Required inputs:"
echo "1. Source OpenSearch domain ARN"
echo "2. Destination OpenSearch domain ARN"
echo "3. S3 bucket ARN (optional - will create new bucket if not provided)"
echo ""

echo "Usage examples:"
echo ""

echo "# Example 1: With existing S3 bucket"
echo 'python create_iam_resources.py \'
echo '  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \'
echo '  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \'
echo '  --s3-bucket "arn:aws:s3:::my-snapshots-bucket"'
echo ""

echo "# Example 2: Create new S3 bucket automatically"
echo 'python create_iam_resources.py \'
echo '  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \'
echo '  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain"'
echo ""

echo "# Example 3: Custom role and user names"
echo 'python create_iam_resources.py \'
echo '  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \'
echo '  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \'
echo '  --role-name "MySnapshotRole" \'
echo '  --user-name "MySnapshotUser"'
echo ""

echo "# Show help"
echo "python create_iam_resources.py --help"
echo ""

echo "Prerequisites:"
echo "1. Configure AWS credentials for both source and destination accounts"
echo "2. Install dependencies: pip install -r requirements.txt"
echo "3. Ensure you have permissions to create IAM roles/users in both accounts"
echo ""

echo "How to get ARNs:"
echo "1. OpenSearch domain ARN: AWS Console > OpenSearch > Domain > Overview"
echo "2. S3 bucket ARN: AWS Console > S3 > Bucket > Properties"
echo ""

echo "Output:"
echo "- iam_resources_output.json: Contains all created resources and credentials"
echo "- Access keys for both accounts (store securely!)"
echo ""

echo "Next steps after running:"
echo "1. Set up S3 bucket replication (if cross-region/cross-account)"
echo "2. Configure OpenSearch snapshot repositories using the created roles"
echo "3. Test snapshot creation and restoration"