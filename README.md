# OpenSearch Snapshot Setup Automation

This project provides a unified script that automates the complete setup for OpenSearch manual snapshots across different domains, regions, and AWS accounts. It creates IAM resources, configures OpenSearch security, and optionally registers snapshot repositories, as described in the [AWS blog post](https://aws.amazon.com/blogs/big-data/take-manual-snapshots-and-restore-in-a-different-domain-spanning-across-various-regions-and-accounts-in-amazon-opensearch-service/).

## Overview

The unified `opensearch_snapshot_setup.py` script handles the complete end-to-end setup:
1. **IAM Resources**: Creates roles, users, and policies for both source and destination accounts
2. **S3 Bucket Management**: Smart bucket reuse (empty buckets only) or creates new buckets
3. **OpenSearch Security**: Configures role mappings for snapshot operations
4. **Repository Registration**: Automatically registers the snapshot repository (can be skipped)

## Features

- ✅ **Unified Setup**: Single script handles IAM, security, and repository setup
- ✅ **Cross-account support**: Works across different AWS accounts
- ✅ **Cross-region support**: Handles different AWS regions
- ✅ **Smart S3 bucket management**: Reuses empty buckets or creates new ones
- ✅ **OpenSearch security configuration**: Automatically configures role mappings
- ✅ **Repository registration**: Automatically registers snapshot repositories
- ✅ **Secure IAM policies**: Implements least-privilege access with proper conditions
- ✅ **Comprehensive logging**: Clean output with optional debug mode
- ✅ **Dry-run mode**: Preview what will be created without making changes
- ✅ **Force new bucket**: Option to create new bucket every run
- ✅ **Error handling**: Graceful handling of existing resources and conflicts

## Prerequisites

1. **Python 3.7+** with pip
2. **AWS CLI configured** with credentials for both source and destination accounts
3. **Permissions** to create IAM roles, users, and S3 buckets in both accounts
4. **OpenSearch domain ARNs** for source and destination domains
5. **OpenSearch admin credentials** (for security configuration and repository registration)

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install boto3 requests urllib3
   ```

## Usage

### Basic Usage

```bash
# Complete setup (IAM + Security + Repository) with automatic S3 bucket management
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword

# With existing S3 bucket
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --s3-bucket "arn:aws:s3:::my-snapshots-bucket" \
  --username admin --password mypassword

# Using --s3 alias for S3 bucket
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --s3 "arn:aws:s3:::my-snapshots-bucket" \
  --username admin --password mypassword
```

### Advanced Usage

```bash
# Skip repository registration (IAM and security only)
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --skip-repository

# Force new bucket creation every run
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --force-new-bucket

# Dry run to see what would be created
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --dry-run

# Debug mode for detailed logging
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --debug

# IAM resources only (skip OpenSearch security and repository)
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --skip-security

# Skip only repository registration (do IAM and security)
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --skip-repository
```

### Command Line Options

| Option | Required | Description | Default |
|--------|----------|-------------|---------|
| `--src-domain` | Yes | Source OpenSearch domain ARN | - |
| `--dest-domain` | Yes | Destination OpenSearch domain ARN | - |
| `--username` | No* | OpenSearch admin username | - |
| `--password` | No* | OpenSearch admin password | - |
| `--s3-bucket` | No | S3 bucket ARN (creates/reuses if not provided) | - |
| `--s3` | No | Alias for --s3-bucket | - |
| `--role-name` | No | IAM role name prefix | `OpenSearchSnapshotRole` |
| `--user-name` | No | IAM user name prefix | `OpenSearchSnapshotUser` |
| `--force-new-bucket` | No | Force creation of new S3 bucket | `False` |
| `--skip-security` | No | Skip OpenSearch security configuration | `False` |
| `--skip-repository` | No | Skip snapshot repository registration | `False` |
| `--dry-run` | No | Show what would be done without making changes | `False` |
| `--debug` | No | Enable detailed debug logging | `False` |
| `--help` | No | Show help message | - |

*Required for OpenSearch security configuration and repository registration

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
- **File**: `opensearch_snapshot_config.json`
- **Contains**: All ARNs, credentials, and configuration details for both accounts

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
2025-07-29 19:24:38 - INFO - === Starting OpenSearch Snapshot Setup ===
------------------------------------------------------------
2025-07-29 19:24:38 - INFO - Source: version-check-211 (ap-south-1)
2025-07-29 19:24:38 - INFO - Destination: test (us-east-1)
------------------------------------------------------------
2025-07-29 19:24:38 - INFO - Managing S3 bucket automatically
2025-07-29 19:24:38 - INFO - Checking for existing empty snapshot buckets...
2025-07-29 19:24:41 - INFO - Using S3 bucket: opensearch-snapshots-8cc57667
------------------------------------------------------------
2025-07-29 19:24:41 - INFO - === Processing SOURCE account ===
2025-07-29 19:24:42 - INFO - Successfully updated role: OpenSearchSnapshotRole-src
2025-07-29 19:24:42 - INFO - Updating policy: OpenSearchSnapshotUser-srcAssumeRolePolicy
2025-07-29 19:24:42 - INFO - Successfully updated user: OpenSearchSnapshotUser-src
2025-07-29 19:24:42 - INFO - Added OpenSearch policy to user: OpenSearchSnapshotUser-src
------------------------------------------------------------
2025-07-29 19:24:42 - INFO - === Processing DESTINATION account ===
2025-07-29 19:24:43 - INFO - Successfully updated role: OpenSearchSnapshotRole-dest
2025-07-29 19:24:43 - INFO - Updating policy: OpenSearchSnapshotUser-destAssumeRolePolicy
2025-07-29 19:24:43 - INFO - Successfully updated user: OpenSearchSnapshotUser-dest
------------------------------------------------------------
2025-07-29 19:24:43 - INFO - === Configuring OpenSearch Security ===
2025-07-29 19:24:44 - INFO - Source domain endpoint: https://search-version-check-211-hlbfai2wqjuptyrbhegjttvk4m.ap-south-1.es.amazonaws.com
2025-07-29 19:24:46 - INFO - Current AWS user ARN: arn:aws:iam::765423874566:user/admin
2025-07-29 19:24:47 - INFO - Configured all_access role mapping
2025-07-29 19:24:48 - INFO - Configured manage_snapshots role mapping
------------------------------------------------------------
2025-07-29 19:24:48 - INFO - === Registering Snapshot Repository ===
2025-07-29 19:24:49 - INFO - Successfully registered snapshot repository: automated-snapshots
------------------------------------------------------------
2025-07-29 19:24:48 - INFO - === Setup Summary ===
2025-07-29 19:24:48 - INFO - S3 bucket: opensearch-snapshots-8cc57667
2025-07-29 19:24:48 - INFO - Source role: OpenSearchSnapshotRole-src
2025-07-29 19:24:48 - INFO - Source user: OpenSearchSnapshotUser-src
2025-07-29 19:24:48 - INFO - Destination role: OpenSearchSnapshotRole-dest
2025-07-29 19:24:48 - INFO - Destination user: OpenSearchSnapshotUser-dest
------------------------------------------------------------
2025-07-29 19:24:48 - INFO - Setup completed successfully!
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

### Default Behavior (Repository Registered)
The script automatically registers the snapshot repository by default, so you can proceed directly to testing:

```bash
# Create snapshot
curl -X PUT "https://source-domain-endpoint/_snapshot/automated-snapshots/snapshot-1" \
  -H "Content-Type: application/json" \
  -d '{"indices": "*", "ignore_unavailable": true, "include_global_state": false}'

# Check snapshot status
curl -X GET "https://source-domain-endpoint/_snapshot/automated-snapshots/snapshot-1"

# Restore snapshot in destination domain (register repository first in destination)
curl -X POST "https://dest-domain-endpoint/_snapshot/automated-snapshots/snapshot-1/_restore" \
  -H "Content-Type: application/json" \
  -d '{"indices": "*", "ignore_unavailable": true, "include_global_state": false}'
```

### If you used `--skip-repository`
You need to manually register the snapshot repository:

```bash
# Register repository in source domain
curl -X PUT "https://source-domain-endpoint/_snapshot/automated-snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "s3",
    "settings": {
      "bucket": "opensearch-snapshots-8cc57667",
      "region": "ap-south-1",
      "role_arn": "arn:aws:iam::111111111111:role/OpenSearchSnapshotRole-src"
    }
  }'

# Register repository in destination domain
curl -X PUT "https://dest-domain-endpoint/_snapshot/automated-snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "s3",
    "settings": {
      "bucket": "opensearch-snapshots-8cc57667",
      "region": "ap-south-1",
      "role_arn": "arn:aws:iam::222222222222:role/OpenSearchSnapshotRole-dest"
    }
  }'
```

### Additional Setup (if needed)

1. **Set up S3 bucket replication** (if cross-region/cross-account)
   ```bash
   # Configure replication from source bucket to destination region
   aws s3api put-bucket-replication --bucket opensearch-snapshots-8cc57667 --replication-configuration file://replication.json
   ```

## Troubleshooting

### Common Issues

1. **Bucket name conflicts**: Script automatically retries with different names
2. **Existing resources**: Script handles existing IAM resources gracefully
3. **Permission errors**: Ensure your AWS credentials have sufficient permissions
4. **Cross-account access**: Verify trust relationships and bucket policies
5. **OpenSearch connection issues**: Verify username/password and domain accessibility
6. **Partial cleanup**: Use `--debug` mode to see detailed cleanup progress

### Log Analysis
- Check timestamps in logs for operation sequence
- Look for ERROR level messages for critical issues
- WARNING messages indicate non-critical issues (existing resources)
- DEBUG messages show detailed ARN cleanup operations

### Cleanup Scenarios

#### Scenario 1: Normal Cleanup
```bash
# Complete cleanup with all resources existing
python delete_all.py --username admin --password mypassword
```

#### Scenario 2: IAM Resources Already Deleted
```bash
# OpenSearch cleanup still works using ARNs from config
python delete_all.py --username admin --password mypassword
# Script will clean up OpenSearch mappings even if IAM resources don't exist
```

#### Scenario 3: Partial Cleanup
```bash
# Skip S3 if it contains other data
python delete_all.py --username admin --password mypassword --skip-s3

# Skip OpenSearch if you want to keep security mappings
python delete_all.py --skip-opensearch
```

#### Scenario 4: Troubleshooting
```bash
# Use debug mode to see detailed cleanup operations
python delete_all.py --username admin --password mypassword --debug

# Dry run to see what would be cleaned up
python delete_all.py --username admin --password mypassword --dry-run
```

## Dry Run Mode

Use `--dry-run` to see exactly what the script would create without making any actual changes:

```bash
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --dry-run
```

### Dry Run Output Example
```
2025-07-29 19:24:38 - INFO - === DRY RUN MODE - No changes will be made ===
------------------------------------------------------------
2025-07-29 19:24:38 - INFO - Source: source-domain (us-east-1)
2025-07-29 19:24:38 - INFO - Destination: dest-domain (us-west-2)
------------------------------------------------------------
2025-07-29 19:24:38 - INFO - [DRY RUN] Would create bucket: opensearch-snapshots-a1b2c3d4
------------------------------------------------------------
2025-07-29 19:24:41 - INFO - === Processing SOURCE account ===
2025-07-29 19:24:42 - INFO - [DRY RUN] Would create/update role: OpenSearchSnapshotRole-src
2025-07-29 19:24:42 - INFO - [DRY RUN] Would create/update user: OpenSearchSnapshotUser-src
2025-07-29 19:24:42 - INFO - [DRY RUN] Would add OpenSearch policy to user: OpenSearchSnapshotUser-src
------------------------------------------------------------
2025-07-29 19:24:42 - INFO - === Processing DESTINATION account ===
2025-07-29 19:24:43 - INFO - [DRY RUN] Would create/update role: OpenSearchSnapshotRole-dest
2025-07-29 19:24:43 - INFO - [DRY RUN] Would create/update user: OpenSearchSnapshotUser-dest
------------------------------------------------------------
2025-07-29 19:24:43 - INFO - === Configuring OpenSearch Security ===
2025-07-29 19:24:44 - INFO - [DRY RUN] Would configure security for: source-domain
2025-07-29 19:24:46 - INFO - [DRY RUN] Would map current user to all_access role
2025-07-29 19:24:47 - INFO - [DRY RUN] Would map IAM role/user to manage_snapshots role
------------------------------------------------------------
2025-07-29 19:24:48 - INFO - DRY RUN COMPLETE - No actual changes were made
```

## Debug Mode

Use `--debug` for detailed logging including policies, API calls, and troubleshooting information:

```bash
python opensearch_snapshot_setup.py \
  --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \
  --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \
  --username admin --password mypassword \
  --debug
```

Debug mode includes:
- JSON-formatted policy documents
- AWS API call details
- Step-by-step process information
- Exception stack traces
- S3 bucket operation details

## Cleanup

### Deleting All Resources

To clean up all resources created by the script, use the `delete_all.py` script:

```bash
# Complete cleanup (IAM + S3 + OpenSearch security + repository)
python delete_all.py --username admin --password mypassword

# Dry run to see what would be deleted
python delete_all.py --username admin --password mypassword --dry-run

# Skip S3 bucket deletion (if it contains other data)
python delete_all.py --username admin --password mypassword --skip-s3

# Skip OpenSearch operations (keep security mappings and repository)
python delete_all.py --skip-opensearch

# Use custom config file
python delete_all.py --config-file my_config.json --username admin --password mypassword

# Debug mode for detailed logging
python delete_all.py --username admin --password mypassword --debug
```

### Delete Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `--config-file` | Configuration file with resource details | `opensearch_snapshot_config.json` |
| `--username` | OpenSearch admin username (for security/repository cleanup) | - |
| `--password` | OpenSearch admin password (for security/repository cleanup) | - |
| `--dry-run` | Show what would be deleted without actually deleting | `False` |
| `--skip-s3` | Skip S3 bucket deletion | `False` |
| `--skip-opensearch` | Skip OpenSearch operations (security + repository) | `False` |
| `--debug` | Enable detailed debug logging | `False` |

### What Gets Deleted

The delete script removes all resources created by `opensearch_snapshot_setup.py`:

1. **OpenSearch Resources** (unless `--skip-opensearch` is used)
   - Snapshot repository (`automated-snapshots`)
   - Security role mappings (removes current user from `all_access`, removes all IAM role/user ARNs from `manage_snapshots`)
   - **Works even if IAM resources are already deleted** - uses ARNs from config file

2. **S3 Bucket** (unless `--skip-s3` is used)
   - All objects and versions in the bucket
   - The bucket itself

3. **Source Account Resources**
   - IAM User and all access keys
   - IAM Role and all attached policies
   - All inline policies (including OpenSearch policies)

4. **Destination Account Resources**
   - IAM User and all access keys
   - IAM Role and all attached policies
   - All inline policies

### Safety Features

- **Confirmation prompt**: Asks for confirmation before deleting (unless dry-run)
- **Dry run mode**: Shows what would be deleted without making changes
- **Graceful handling**: Continues if resources don't exist
- **Independent cleanup**: OpenSearch security cleanup works even if IAM resources are already deleted
- **Comprehensive mapping cleanup**: Removes all related ARNs from OpenSearch role mappings
- **Detailed logging**: Shows exactly what's being deleted with separators
- **Debug mode**: Comprehensive logging for troubleshooting
- **Selective deletion**: Skip S3 or OpenSearch operations if needed
- **Config file cleanup**: Optionally removes the configuration file after successful deletion

### Example Delete Output

```
2025-07-29 20:15:00 - INFO - === Starting OpenSearch Snapshot Resources Deletion ===
------------------------------------------------------------
2025-07-29 20:15:00 - INFO - Loading configuration from: opensearch_snapshot_config.json
2025-07-29 20:15:00 - INFO - Resources to be deleted:
2025-07-29 20:15:00 - INFO -   S3 Bucket: opensearch-snapshots-8cc57667
2025-07-29 20:15:00 - INFO -   Source IAM Role: OpenSearchSnapshotRole-src
2025-07-29 20:15:00 - INFO -   Source IAM User: OpenSearchSnapshotUser-src
2025-07-29 20:15:00 - INFO -   Destination IAM Role: OpenSearchSnapshotRole-dest
2025-07-29 20:15:00 - INFO -   Destination IAM User: OpenSearchSnapshotUser-dest
2025-07-29 20:15:00 - INFO -   OpenSearch Security Mappings (all_access, manage_snapshots)
2025-07-29 20:15:00 - INFO -   Snapshot Repository: automated-snapshots
------------------------------------------------------------

Are you sure you want to delete these resources? (yes/no): yes

------------------------------------------------------------
2025-07-29 20:15:05 - INFO - === Deleting Snapshot Repository ===
2025-07-29 20:15:06 - INFO - Successfully deleted snapshot repository: automated-snapshots
------------------------------------------------------------
2025-07-29 20:15:06 - INFO - === Reverting OpenSearch Security Mappings ===
2025-07-29 20:15:07 - INFO - Cleaned up all_access role mapping
2025-07-29 20:15:08 - INFO - Cleaned up manage_snapshots role mapping
------------------------------------------------------------
2025-07-29 20:15:08 - INFO - === Deleting S3 Bucket ===
2025-07-29 20:15:09 - INFO - Successfully deleted S3 bucket: opensearch-snapshots-8cc57667
------------------------------------------------------------
2025-07-29 20:15:09 - INFO - === Deleting SOURCE Account Resources ===
2025-07-29 20:15:10 - INFO - Successfully deleted IAM user: OpenSearchSnapshotUser-src
2025-07-29 20:15:11 - INFO - Successfully deleted IAM role: OpenSearchSnapshotRole-src
------------------------------------------------------------
2025-07-29 20:15:11 - INFO - === Deleting DESTINATION Account Resources ===
2025-07-29 20:15:12 - INFO - Successfully deleted IAM user: OpenSearchSnapshotUser-dest
2025-07-29 20:15:13 - INFO - Successfully deleted IAM role: OpenSearchSnapshotRole-dest
------------------------------------------------------------
2025-07-29 20:15:13 - INFO - === Deletion Summary ===
2025-07-29 20:15:13 - INFO - Deletion completed: 6/6 resources processed successfully
2025-07-29 20:15:13 - INFO - All resources deleted successfully!
```

## Enhanced Cleanup Features

### Robust OpenSearch Security Cleanup

The delete script includes advanced OpenSearch security cleanup that:

- **Works independently of IAM resource state**: Cleans up OpenSearch role mappings even if IAM roles/users are already deleted
- **Uses config file ARNs**: References ARNs from the configuration file rather than querying IAM
- **Comprehensive mapping cleanup**: Removes all related ARNs from both `users` and `backend_roles` arrays
- **Cross-account aware**: Handles both source and destination account ARNs automatically
- **Graceful error handling**: Continues cleanup even if some mappings don't exist

### Cleanup Process Order

1. **OpenSearch Resources First**: Repository and security mappings are cleaned up first
2. **S3 Bucket**: Removes bucket and all contents (if not skipped)
3. **Source Account IAM**: Removes roles, users, and policies
4. **Destination Account IAM**: Removes roles, users, and policies
5. **Configuration File**: Optionally removes the config file

This order ensures that OpenSearch security is properly cleaned up regardless of the state of other resources.

### Why This Matters

- **Prevents orphaned mappings**: Ensures OpenSearch security mappings are cleaned up even if IAM cleanup fails
- **Handles partial failures**: If IAM resources were deleted manually, OpenSearch cleanup still works
- **Cross-account scenarios**: Properly handles mappings that span multiple AWS accounts
- **Complete cleanup**: Guarantees that all traces of the snapshot setup are removed

## File Structure

```
├── opensearch_snapshot_setup.py    # Main unified setup script
├── delete_all.py                   # Complete cleanup script
├── create_iam_resources.py         # Legacy IAM-only creation script
├── configure_opensearch_security.py # Legacy security configuration script
├── README.md                        # This file
└── opensearch_snapshot_config.json # Generated output (after running setup script)
```

## Migration from Legacy Scripts

If you were using the separate `create_iam_resources.py` and `configure_opensearch_security.py` scripts, you can now use the unified script:

### Old Way (2 scripts):
```bash
# Step 1: Create IAM resources
python create_iam_resources.py --src-domain ... --dest-domain ...

# Step 2: Configure security
python configure_opensearch_security.py --username admin --password mypassword
```

### New Way (1 script):
```bash
# Single command does everything (IAM + Security + Repository)
python opensearch_snapshot_setup.py \
  --src-domain ... --dest-domain ... \
  --username admin --password mypassword
```

The unified script provides the same functionality with additional features like smart S3 bucket management and automatic repository registration.

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