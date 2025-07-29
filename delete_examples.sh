#!/bin/bash

echo "=== OpenSearch Snapshot IAM Resources Deletion Examples ==="
echo ""

echo "This script deletes all IAM resources created by create_iam_resources.py"
echo "It reads from the iam_resources_output.json file to know what to delete."
echo ""

echo "Usage examples:"
echo ""

echo "# Basic deletion (will prompt for confirmation)"
echo "python delete_iam_resources.py"
echo ""

echo "# Dry run - see what would be deleted without actually deleting"
echo "python delete_iam_resources.py --dry-run"
echo ""

echo "# Use custom config file"
echo "python delete_iam_resources.py --config-file my_custom_output.json"
echo ""

echo "# Skip S3 bucket deletion (keep bucket but delete IAM resources)"
echo "python delete_iam_resources.py --skip-s3"
echo ""

echo "# Dry run with custom config file"
echo "python delete_iam_resources.py --config-file my_config.json --dry-run"
echo ""

echo "# Show help"
echo "python delete_iam_resources.py --help"
echo ""

echo "Prerequisites:"
echo "1. Must have run create_iam_resources.py first"
echo "2. iam_resources_output.json file must exist"
echo "3. AWS credentials configured for both source and destination accounts"
echo "4. Same permissions as creation script"
echo ""

echo "Safety features:"
echo "- Confirmation prompt before deletion"
echo "- Dry run mode to preview changes"
echo "- Detailed logging of all operations"
echo "- Graceful handling of already-deleted resources"
echo ""

echo "What gets deleted:"
echo "- S3 bucket and all its contents (unless --skip-s3)"
echo "- IAM roles in both accounts"
echo "- IAM users in both accounts"
echo "- All attached policies"
echo "- All access keys"
echo "- Optionally the configuration file"