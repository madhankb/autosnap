# OpenSearch Manual Snapshot Automation

This project automates the creation of IAM resources required for OpenSearch manual snapshots across different domains, regions, and AWS accounts, as described in the [AWS blog post](https://aws.amazon.com/blogs/big-data/take-manual-snapshots-and-restore-in-a-different-domain-spanning-across-various-regions-and-accounts-in-amazon-opensearch-service/).

## Overview

The script creates all necessary IAM roles, users, policies, and S3 bucket resources to enable manual snapshots from a source OpenSearch domain and restoration to a destination OpenSearch domain, even across different AWS accounts and regions.

## Features

- ✅ **Cross-account support**: Works across different AWS accounts
- ✅ **Cross-region support**: Handles different AWS regions
- ✅ **Automatic S3 bucket creation**: Creates S3 bucket with proper policies if not provided
- ✅ **Secure IAM policies**: Implements least-privilege access with proper conditions
- ✅ **Differentiated resources**: Clear naming for source vs destination resources
- ✅ **Comprehensive logging**: Timestamped logs for audit trail
- ✅ **Error handling**: Graceful handling of existing resources and conflicts
- ✅ **Retry logic**: Automatic retry for S3 bucket name conflicts

## Prerequisites

1. **Python 3.7+** with pip
2. **AWS CLI configured** with credentials for both source and destination accounts
3. **Permissions** to create IAM roles, users, and S3 buckets in both accounts
4. **OpenSearch domain ARNs** for source and destination domains

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
# With existing S3 bucket
python create_iam_resources.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --s3-bucket "arn:aws:s3:::my-snapshots-bucket"

# Create new S3 bucket automatically
python create_iam_resources.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain"
```

### Advanced Usage

```bash
# Custom role and user names
python create_iam_resources.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --role-name "MySnapshotRole" \
  --user-name "MySnapshotUser"
```

### Command Line Options

| Option | Required | Description | Default |
|--------|----------|-------------|---------|
| `--src-domain` | Yes | Source OpenSearch domain ARN | - |
| `--dest-domain` | Yes | Destination OpenSearch domain ARN | - |
| `--s3-bucket` | No | S3 bucket ARN (creates new if not provided) | - |
| `--role-name` | No | IAM role name | `OpenSearchSnapshotRole` |
| `--user-name` | No | IAM user name | `OpenSearchSnapshotUser` |
| `--help` | No | Show help message | - |

## Resources Created

### S3 Bucket (if not provided)
- **Name**: `opensearch-snapshots-{8-char-uuid}`
- **Location**: Source account and region
- **Features**: Versioning enabled, OpenSearch service access policy

### Source Account Resources
- **IAM Role**: `{role-name}-src` (default: `OpenSearchSnapshotRole-src`)
- **IAM User**: `{user-name}-src` (default: `OpenSearchSnapshotUser-src`)
- **Policies**: 
  - S3 access policy for snapshot operations
  - AssumeRole policy for user
  - OpenSearch access policy (PassRole + ESHttpPut)

### Destination Account Resources
- **IAM Role**: `{role-name}-dest` (default: `OpenSearchSnapshotRole-dest`)
- **IAM User**: `{user-name}-dest` (default: `OpenSearchSnapshotUser-dest`)
- **Policies**:
  - S3 access policy for snapshot operations
  - AssumeRole policy for user

### Output File
- **File**: `iam_resources_output.json`
- **Contains**: All ARNs, credentials, and configuration details

## Security Features

### IAM Role Trust Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "account-id"
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:es:region:account-id:domain/domain-name"
        }
      }
    }
  ]
}
```

### S3 Permissions Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::bucket-name"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::bucket-name/*"
    }
  ]
}
```

## Example Output

```
2025-07-28 16:28:58 - INFO - === Starting OpenSearch Snapshot IAM Resources Creation ===
2025-07-28 16:28:58 - INFO - Source domain ARN: arn:aws:es:us-east-1:111111111111:domain/source-domain
2025-07-28 16:28:58 - INFO - Destination domain ARN: arn:aws:es:us-west-2:222222222222:domain/dest-domain
2025-07-28 16:28:58 - INFO - S3 bucket: Will create new bucket
2025-07-28 16:28:59 - INFO - Creating new S3 bucket
2025-07-28 16:28:59 - INFO - Attempt 1/5: Trying bucket name opensearch-snapshots-a1b2c3d4
2025-07-28 16:28:59 - INFO - Successfully created S3 bucket: opensearch-snapshots-a1b2c3d4
2025-07-28 16:29:00 - INFO - Processing SOURCE account resources
2025-07-28 16:29:00 - INFO - Creating IAM role: OpenSearchSnapshotRole-src
2025-07-28 16:29:01 - INFO - Successfully created role: OpenSearchSnapshotRole-src
2025-07-28 16:29:01 - INFO - Creating IAM user: OpenSearchSnapshotUser-src
2025-07-28 16:29:02 - INFO - Successfully created user: OpenSearchSnapshotUser-src
2025-07-28 16:29:02 - INFO - Processing DESTINATION account resources
2025-07-28 16:29:02 - INFO - Creating IAM role: OpenSearchSnapshotRole-dest
2025-07-28 16:29:03 - INFO - Successfully created role: OpenSearchSnapshotRole-dest
2025-07-28 16:29:03 - INFO - Creating IAM user: OpenSearchSnapshotUser-dest
2025-07-28 16:29:04 - INFO - Successfully created user: OpenSearchSnapshotUser-dest
2025-07-28 16:29:04 - INFO - IAM resources created successfully!
2025-07-28 16:29:04 - INFO - Complete configuration saved to: iam_resources_output.json
```

## How to Get ARNs

### OpenSearch Domain ARN
1. Go to AWS Console → OpenSearch Service
2. Select your domain
3. Copy the ARN from the domain overview

### S3 Bucket ARN (optional)
1. Go to AWS Console → S3
2. Select your bucket
3. Go to Properties tab
4. Copy the ARN

## Next Steps After Running

1. **Set up S3 bucket replication** (if cross-region/cross-account)
   ```bash
   # Configure replication from source bucket to destination region
   aws s3api put-bucket-replication --bucket source-bucket --replication-configuration file://replication.json
   ```

2. **Configure OpenSearch snapshot repositories**
   ```bash
   # Register snapshot repository in source domain
   curl -X PUT "https://source-domain-endpoint/_snapshot/my-repository" \
     -H "Content-Type: application/json" \
     -d '{
       "type": "s3",
       "settings": {
         "bucket": "opensearch-snapshots-a1b2c3d4",
         "region": "us-east-1",
         "role_arn": "arn:aws:iam::111111111111:role/OpenSearchSnapshotRole-src"
       }
     }'
   ```

3. **Test snapshot creation and restoration**
   ```bash
   # Create snapshot
   curl -X PUT "https://source-domain-endpoint/_snapshot/my-repository/snapshot-1"
   
   # Restore snapshot in destination domain
   curl -X POST "https://dest-domain-endpoint/_snapshot/my-repository/snapshot-1/_restore"
   ```

## Troubleshooting

### Common Issues

1. **Bucket name conflicts**: Script automatically retries with different names
2. **Existing resources**: Script handles existing IAM resources gracefully
3. **Permission errors**: Ensure your AWS credentials have sufficient permissions
4. **Cross-account access**: Verify trust relationships and bucket policies

### Log Analysis
- Check timestamps in logs for operation sequence
- Look for ERROR level messages for critical issues
- WARNING messages indicate non-critical issues (existing resources)

## Cleanup

### Deleting Resources

To clean up all resources created by the script, use the `delete_iam_resources.py` script:

```bash
# Delete all resources using default config file
python delete_iam_resources.py

# Use custom config file
python delete_iam_resources.py --config-file my_config.json

# Dry run to see what would be deleted
python delete_iam_resources.py --dry-run

# Skip S3 bucket deletion (if it contains other data)
python delete_iam_resources.py --skip-s3
```

### Delete Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config-file` | Configuration file with resource details | `iam_resources_output.json` |
| `--dry-run` | Show what would be deleted without actually deleting | False |
| `--skip-s3` | Skip S3 bucket deletion | False |

### What Gets Deleted

The delete script removes all resources created by `create_iam_resources.py`:

1. **S3 Bucket** (unless `--skip-s3` is used)
   - All objects and versions in the bucket
   - The bucket itself

2. **Source Account Resources**
   - IAM User and all access keys
   - IAM Role and all attached policies
   - All inline policies

3. **Destination Account Resources**
   - IAM User and all access keys
   - IAM Role and all attached policies
   - All inline policies

### Safety Features

- **Confirmation prompt**: Asks for confirmation before deleting (unless dry-run)
- **Dry run mode**: Shows what would be deleted without making changes
- **Graceful handling**: Continues if resources don't exist
- **Detailed logging**: Shows exactly what's being deleted
- **Config file cleanup**: Optionally removes the configuration file after successful deletion

### Example Delete Output

```
2025-07-28 16:35:00 - INFO - === Starting OpenSearch Snapshot IAM Resources Deletion ===
2025-07-28 16:35:00 - INFO - Loading configuration from: iam_resources_output.json
2025-07-28 16:35:00 - INFO - Resources to be deleted:
2025-07-28 16:35:00 - INFO -   S3 Bucket: opensearch-snapshots-a1b2c3d4
2025-07-28 16:35:00 - INFO -   Source IAM Role: OpenSearchSnapshotRole-src
2025-07-28 16:35:00 - INFO -   Source IAM User: OpenSearchSnapshotUser-src
2025-07-28 16:35:00 - INFO -   Destination IAM Role: OpenSearchSnapshotRole-dest
2025-07-28 16:35:00 - INFO -   Destination IAM User: OpenSearchSnapshotUser-dest

Are you sure you want to delete these resources? (yes/no): yes

2025-07-28 16:35:05 - INFO - Deleting S3 bucket resources
2025-07-28 16:35:05 - INFO - Deleting S3 bucket: opensearch-snapshots-a1b2c3d4
2025-07-28 16:35:06 - INFO - Successfully deleted S3 bucket: opensearch-snapshots-a1b2c3d4
2025-07-28 16:35:06 - INFO - Deleting SOURCE account resources
2025-07-28 16:35:06 - INFO - Deleting IAM user: OpenSearchSnapshotUser-src
2025-07-28 16:35:07 - INFO - Successfully deleted IAM user: OpenSearchSnapshotUser-src
2025-07-28 16:35:07 - INFO - Deleting IAM role: OpenSearchSnapshotRole-src
2025-07-28 16:35:08 - INFO - Successfully deleted IAM role: OpenSearchSnapshotRole-src
2025-07-28 16:35:08 - INFO - Deletion completed: 5/5 resources processed successfully
2025-07-28 16:35:08 - INFO - All resources deleted successfully!
```

## File Structure

```
├── create_iam_resources.py    # Main creation script
├── delete_iam_resources.py    # Cleanup script
├── requirements.txt           # Python dependencies
├── run_examples.sh           # Usage examples
├── delete_examples.sh        # Delete examples
├── README.md                 # This file
└── iam_resources_output.json # Generated output (after running create script)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [AWS Blog: Take manual snapshots and restore in a different domain](https://aws.amazon.com/blogs/big-data/take-manual-snapshots-and-restore-in-a-different-domain-spanning-across-various-regions-and-accounts-in-amazon-opensearch-service/)
- [OpenSearch Snapshot and Restore Documentation](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-snapshots.html)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)