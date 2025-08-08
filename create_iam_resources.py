#!/usr/bin/env python3
"""
Script to create IAM roles and users for OpenSearch manual snapshots
Based on AWS blog: Take manual snapshots and restore in a different domain

Usage:
  python create_iam_resources.py --src-domain SOURCE_ARN --dest-domain DEST_ARN [--s3-bucket S3_ARN]
"""

import json
import boto3
from botocore.exceptions import ClientError
import sys
import argparse
import uuid
import re
import logging
from datetime import datetime

def setup_logging():
    """Setup logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

def parse_opensearch_arn(arn):
    """Parse OpenSearch domain ARN and extract components"""
    # ARN format: arn:aws:es:region:account-id:domain/domain-name
    pattern = r'arn:aws:es:([^:]+):([^:]+):domain/(.+)'
    match = re.match(pattern, arn)
    
    if not match:
        raise ValueError(f"Invalid OpenSearch domain ARN format: {arn}")
    
    return {
        'region': match.group(1),
        'account_id': match.group(2),
        'domain_name': match.group(3),
        'arn': arn
    }

def parse_s3_arn(arn):
    """Parse S3 bucket ARN and extract components"""
    # ARN format: arn:aws:s3:::bucket-name
    pattern = r'arn:aws:s3:::(.+)'
    match = re.match(pattern, arn)
    
    if not match:
        raise ValueError(f"Invalid S3 bucket ARN format: {arn}")
    
    bucket_name = match.group(1)
    
    # Get bucket region and account (requires API call)
    try:
        s3_client = boto3.client('s3')
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = location['LocationConstraint'] or 'us-east-1'  # us-east-1 returns None
        
        # Get bucket owner
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        account_id = acl['Owner']['ID']  # This is actually the canonical user ID, not account ID
        
        # Try to get account ID from bucket policy or tags if available
        try:
            sts_client = boto3.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
        except:
            pass
            
    except ClientError as e:
        print(f"Warning: Could not get bucket details for {bucket_name}: {e}")
        region = 'us-east-1'  # Default region
        account_id = 'unknown'
    
    return {
        'name': bucket_name,
        'region': region,
        'account_id': account_id,
        'arn': arn
    }

def create_trust_policy(account_id, domain_arn, region):
    """Create trust policy for the IAM role with proper conditions"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                    "Service": "es.amazonaws.com"
                },
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": account_id
                    },
                    "ArnLike": {
                        "aws:SourceArn": domain_arn
                    }
                }
            }
        ]
    }

def create_s3_policy(bucket_name):
    """Create S3 policy for snapshot operations"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:ListBucket"
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                "Resource": f"arn:aws:s3:::{bucket_name}/*"
            }
        ]
    }

def create_s3_bucket(s3_client, bucket_name, region):
    """Create S3 bucket for snapshots"""
    logger = logging.getLogger(__name__)
    try:
        logger.info(f"Creating S3 bucket: {bucket_name} in region {region}")
        
        if region == 'us-east-1':
            # us-east-1 doesn't need LocationConstraint
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Enable versioning for better snapshot management
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # Set bucket policy to allow cross-account access
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "opensearch.amazonaws.com"},
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*"
                    ]
                }
            ]
        }
        
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(bucket_policy)
        )
        
        logger.info(f"Successfully created S3 bucket: {bucket_name}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            logger.warning(f"S3 bucket {bucket_name} already exists and is owned by you")
            return True
        elif e.response['Error']['Code'] == 'BucketAlreadyExists':
            logger.error(f"S3 bucket {bucket_name} already exists and is owned by someone else")
            return False
        else:
            logger.error(f"Error creating S3 bucket {bucket_name}: {e}")
            return False

def generate_unique_bucket_name(base_name):
    """Generate a unique bucket name"""
    unique_suffix = str(uuid.uuid4())[:8]
    return f"{base_name}-{unique_suffix}"

def find_existing_snapshot_bucket(s3_client, base_name="opensearch-snapshots"):
    """Find existing S3 bucket created by previous runs"""
    logger = logging.getLogger(__name__)
    try:
        logger.info("Checking for existing snapshot buckets...")
        response = s3_client.list_buckets()
        
        # Look for buckets that match our naming pattern
        matching_buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            if bucket_name.startswith(base_name):
                # Check if bucket has the right tags or policy to confirm it's ours
                try:
                    # Check bucket policy to see if it's configured for OpenSearch
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy = json.loads(policy_response['Policy'])
                    
                    # Look for OpenSearch service principal in policy
                    for statement in policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if isinstance(principal, dict) and principal.get('Service') == 'opensearch.amazonaws.com':
                            matching_buckets.append({
                                'name': bucket_name,
                                'creation_date': bucket['CreationDate']
                            })
                            break
                except ClientError:
                    # If we can't read the policy, skip this bucket
                    continue
        
        if matching_buckets:
            # Sort by creation date and return the most recent
            matching_buckets.sort(key=lambda x: x['creation_date'], reverse=True)
            latest_bucket = matching_buckets[0]
            logger.info(f"Found existing snapshot bucket: {latest_bucket['name']} (created: {latest_bucket['creation_date']})")
            
            # Log info about older buckets that could be cleaned up
            if len(matching_buckets) > 1:
                logger.info(f"Found {len(matching_buckets) - 1} older snapshot buckets that could be cleaned up:")
                for old_bucket in matching_buckets[1:]:
                    logger.info(f"  - {old_bucket['name']} (created: {old_bucket['creation_date']})")
                logger.info("Consider running the cleanup script to remove unused buckets")
            
            return latest_bucket['name']
        else:
            logger.info("No existing snapshot buckets found")
            return None
            
    except ClientError as e:
        logger.warning(f"Could not list buckets: {e}")
        return None

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Create IAM resources for OpenSearch snapshots',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With existing S3 bucket
  python create_iam_resources.py \\
    --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \\
    --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain" \\
    --s3-bucket "arn:aws:s3:::my-snapshots-bucket"
  
  # Create new S3 bucket
  python create_iam_resources.py \\
    --src-domain "arn:aws:es:us-east-1:111111111111:domain/source-domain" \\
    --dest-domain "arn:aws:es:us-west-2:222222222222:domain/dest-domain"
        """
    )
    
    parser.add_argument(
        '--src-domain',
        required=True,
        help='Source OpenSearch domain ARN (e.g., arn:aws:es:us-east-1:111111111111:domain/source-domain)'
    )
    
    parser.add_argument(
        '--dest-domain',
        required=True,
        help='Destination OpenSearch domain ARN (e.g., arn:aws:es:us-west-2:222222222222:domain/dest-domain)'
    )
    
    parser.add_argument(
        '--s3-bucket',
        help='S3 bucket ARN for snapshots (e.g., arn:aws:s3:::my-snapshots-bucket). If not provided, a new bucket will be created.'
    )
    
    parser.add_argument(
        '--role-name',
        default='OpenSearchSnapshotRole',
        help='IAM role name to create (default: OpenSearchSnapshotRole)'
    )
    
    parser.add_argument(
        '--user-name',
        default='OpenSearchSnapshotUser',
        help='IAM user name to create (default: OpenSearchSnapshotUser)'
    )
    
    parser.add_argument(
        '--force-new-bucket',
        action='store_true',
        help='Force creation of a new S3 bucket even if existing ones are found'
    )
    
    return parser.parse_args()

def create_iam_role(iam_client, role_name, trust_policy, s3_policy, bucket_name, account_type):
    """Create or update IAM role with necessary policies"""
    logger = logging.getLogger(__name__)
    try:
        role_arn = None
        role_exists = False
        
        # Check if role already exists
        try:
            role = iam_client.get_role(RoleName=role_name)
            role_arn = role['Role']['Arn']
            role_exists = True
            logger.info(f"Role {role_name} already exists, updating policies")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                role_exists = False
            else:
                raise e
        
        if not role_exists:
            # Create the role
            logger.info(f"Creating IAM role: {role_name}")
            role_response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Role for OpenSearch snapshots ({account_type}) to S3 bucket {bucket_name}"
            )
            role_arn = role_response['Role']['Arn']
        else:
            # Update trust policy if role exists
            logger.info(f"Updating trust policy for existing role: {role_name}")
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy)
            )
        
        # Create/update the S3 policy (this will overwrite existing policy with same name)
        policy_name = f"{role_name}S3Policy"
        logger.info(f"Creating/updating policy: {policy_name} for bucket {bucket_name}")
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(s3_policy)
        )
        
        logger.info(f"Successfully {'created' if not role_exists else 'updated'} role: {role_name}")
        return role_arn
        
    except ClientError as e:
        logger.error(f"Error creating/updating role {role_name}: {e}")
        return None

def create_iam_user(iam_client, user_name, role_arn):
    """Create or update IAM user with policy to assume the snapshot role"""
    logger = logging.getLogger(__name__)
    try:
        user_arn = None
        user_exists = False
        access_keys = None
        
        # Check if user already exists
        try:
            user = iam_client.get_user(UserName=user_name)
            user_arn = user['User']['Arn']
            user_exists = True
            logger.info(f"User {user_name} already exists, updating policies")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                user_exists = False
            else:
                raise e
        
        if not user_exists:
            # Create the user
            logger.info(f"Creating IAM user: {user_name}")
            user_response = iam_client.create_user(
                UserName=user_name,
                Path='/',
            )
            user_arn = user_response['User']['Arn']
            
            # Create access keys for new user
            logger.info(f"Creating access keys for user: {user_name}")
            keys_response = iam_client.create_access_key(UserName=user_name)
            access_keys = {
                'AccessKeyId': keys_response['AccessKey']['AccessKeyId'],
                'SecretAccessKey': keys_response['AccessKey']['SecretAccessKey']
            }
        else:
            # For existing users, check if they have access keys
            try:
                keys_list = iam_client.list_access_keys(UserName=user_name)
                if keys_list['AccessKeyMetadata']:
                    logger.info(f"User {user_name} already has access keys")
                    access_keys = {'AccessKeyId': 'EXISTING', 'SecretAccessKey': 'EXISTING'}
                else:
                    logger.info(f"Creating new access keys for existing user: {user_name}")
                    keys_response = iam_client.create_access_key(UserName=user_name)
                    access_keys = {
                        'AccessKeyId': keys_response['AccessKey']['AccessKeyId'],
                        'SecretAccessKey': keys_response['AccessKey']['SecretAccessKey']
                    }
            except ClientError as e:
                logger.warning(f"Could not check/create access keys for {user_name}: {e}")
                access_keys = {'AccessKeyId': 'ERROR', 'SecretAccessKey': 'ERROR'}
        
        # Create/update policy to assume the role (this will overwrite existing policy with same name)
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": role_arn
                }
            ]
        }
        
        policy_name = f"{user_name}AssumeRolePolicy"
        logger.info(f"Creating/updating policy: {policy_name}")
        
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(assume_role_policy)
        )
        
        logger.info(f"Successfully {'created' if not user_exists else 'updated'} user: {user_name}")
        
        result = {'UserArn': user_arn}
        if access_keys:
            result.update(access_keys)
        
        return result
        
    except ClientError as e:
        logger.error(f"Error creating/updating user {user_name}: {e}")
        return None

def main():
    logger = setup_logging()
    args = parse_arguments()
    
    logger.info("=== Starting OpenSearch Snapshot IAM Resources Creation ===")
    logger.info(f"Source domain ARN: {args.src_domain}")
    logger.info(f"Destination domain ARN: {args.dest_domain}")
    if args.s3_bucket:
        logger.info(f"S3 bucket ARN: {args.s3_bucket}")
    else:
        logger.info("S3 bucket: Will create new bucket")
    
    try:
        # Parse source domain ARN
        logger.info("Parsing source domain ARN")
        source_info = parse_opensearch_arn(args.src_domain)
        logger.info(f"Source domain: {source_info['domain_name']} in {source_info['region']} (Account: {source_info['account_id']})")
        
        # Parse destination domain ARN
        logger.info("Parsing destination domain ARN")
        dest_info = parse_opensearch_arn(args.dest_domain)
        logger.info(f"Destination domain: {dest_info['domain_name']} in {dest_info['region']} (Account: {dest_info['account_id']})")
        
        # Handle S3 bucket
        if args.s3_bucket:
            logger.info("Parsing S3 bucket ARN")
            s3_info = parse_s3_arn(args.s3_bucket)
            logger.info(f"Using existing S3 bucket: {s3_info['name']} in {s3_info['region']}")
        else:
            logger.info("Looking for existing S3 bucket or creating new one")
            base_bucket_name = "opensearch-snapshots"
            bucket_region = source_info['region']  # Create in source region
            s3_client = boto3.client('s3', region_name=bucket_region)
            
            # First, try to find an existing bucket (unless forced to create new)
            existing_bucket = None if args.force_new_bucket else find_existing_snapshot_bucket(s3_client, base_bucket_name)
            
            if existing_bucket and not args.force_new_bucket:
                logger.info(f"Reusing existing S3 bucket: {existing_bucket}")
                bucket_name = existing_bucket
                bucket_created = True
            else:
                logger.info("No existing bucket found, creating new S3 bucket")
                # Try up to 5 times to create a bucket with unique name
                max_attempts = 5
                bucket_created = False
                
                for attempt in range(max_attempts):
                    bucket_name = generate_unique_bucket_name(base_bucket_name)
                    logger.info(f"Attempt {attempt + 1}/{max_attempts}: Trying bucket name {bucket_name}")
                    
                    if create_s3_bucket(s3_client, bucket_name, bucket_region):
                        bucket_created = True
                        break
                    else:
                        logger.warning(f"Bucket name {bucket_name} not available, trying another")
            
            if not bucket_created:
                logger.error("Failed to create S3 bucket after multiple attempts")
                return
            
            s3_info = {
                'name': bucket_name,
                'region': bucket_region,
                'account_id': source_info['account_id'],
                'arn': f"arn:aws:s3:::{bucket_name}"
            }
            logger.info(f"Using S3 Bucket: {s3_info['name']} in {s3_info['region']}")
        
    except ValueError as e:
        logger.error(f"Error parsing ARNs: {e}")
        return
    except Exception as e:
        logger.error(f"Error processing inputs: {e}")
        return
    
    # Create S3 policy for the bucket
    logger.info("Creating S3 policy for snapshot operations")
    s3_policy = create_s3_policy(s3_info['name'])
    
    # Process source account
    logger.info("Processing SOURCE account resources")
    try:
        logger.info(f"Connecting to IAM in source region: {source_info['region']}")
        source_iam = boto3.client('iam', region_name=source_info['region'])
        
        # Create role and user with source-specific names
        source_role_name = f"{args.role_name}-src"
        source_user_name = f"{args.user_name}-src"
        logger.info(f"Source role name: {source_role_name}")
        logger.info(f"Source user name: {source_user_name}")
        
        # Create role and user for source
        logger.info("Creating trust policy for source account")
        trust_policy = create_trust_policy(
            source_info['account_id'], 
            source_info['arn'], 
            source_info['region']
        )
        
        logger.info("Creating IAM role in source account")
        source_role_arn = create_iam_role(
            source_iam, 
            source_role_name, 
            trust_policy, 
            s3_policy,
            s3_info['name'],
            "source"
        )
        
        logger.info("Creating IAM user in source account")
        source_user_info = create_iam_user(
            source_iam, 
            source_user_name, 
            source_role_arn
        )
        
        # Add additional policy for source user to pass role and access OpenSearch
        source_additional_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": source_role_arn
                },
                {
                    "Effect": "Allow",
                    "Action": "es:ESHttpPut",
                    "Resource": source_info['arn']
                }
            ]
        }
        
        additional_policy_name = f"{source_user_name}OpenSearchPolicy"
        logger.info(f"Creating/updating additional policy for source user: {additional_policy_name}")
        
        try:
            source_iam.put_user_policy(
                UserName=source_user_name,
                PolicyName=additional_policy_name,
                PolicyDocument=json.dumps(source_additional_policy)
            )
            logger.info(f"Successfully attached/updated OpenSearch policy to user: {source_user_name}")
        except ClientError as e:
            logger.warning(f"Could not attach/update OpenSearch policy to user {source_user_name}: {e}")
        
    except Exception as e:
        logger.error(f"Error processing source account: {e}")
        return
    
    # Process destination account
    logger.info("Processing DESTINATION account resources")
    try:
        logger.info(f"Connecting to IAM in destination region: {dest_info['region']}")
        dest_iam = boto3.client('iam', region_name=dest_info['region'])
        
        # Create role and user with destination-specific names
        dest_role_name = f"{args.role_name}-dest"
        dest_user_name = f"{args.user_name}-dest"
        logger.info(f"Destination role name: {dest_role_name}")
        logger.info(f"Destination user name: {dest_user_name}")
        
        # Create role and user for destination
        logger.info("Creating trust policy for destination account")
        trust_policy = create_trust_policy(
            dest_info['account_id'], 
            dest_info['arn'], 
            dest_info['region']
        )
        
        logger.info("Creating IAM role in destination account")
        dest_role_arn = create_iam_role(
            dest_iam, 
            dest_role_name, 
            trust_policy, 
            s3_policy,
            s3_info['name'],
            "destination"
        )
        
        logger.info("Creating IAM user in destination account")
        dest_user_info = create_iam_user(
            dest_iam, 
            dest_user_name, 
            dest_role_arn
        )
        
    except Exception as e:
        logger.error(f"Error processing destination account: {e}")
        return
    
    # Save credentials and ARNs
    logger.info("Saving configuration to output file")
    output = {
        'input_arns': {
            'source_domain': args.src_domain,
            'dest_domain': args.dest_domain,
            's3_bucket': args.s3_bucket or s3_info['arn']
        },
        's3_bucket': {
            'name': s3_info['name'],
            'region': s3_info['region'],
            'arn': s3_info['arn']
        },
        'source': {
            'domain_name': source_info['domain_name'],
            'region': source_info['region'],
            'account_id': source_info['account_id'],
            'domain_arn': source_info['arn'],
            'role_name': source_role_name,
            'role_arn': source_role_arn,
            'user_name': source_user_name,
            'user_info': source_user_info
        },
        'destination': {
            'domain_name': dest_info['domain_name'],
            'region': dest_info['region'],
            'account_id': dest_info['account_id'],
            'domain_arn': dest_info['arn'],
            'role_name': dest_role_name,
            'role_arn': dest_role_arn,
            'user_name': dest_user_name,
            'user_info': dest_user_info
        }
    }
    
    with open('iam_resources_output.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    logger.info("=== IAM resources setup completed successfully! ===")
    logger.info(f"Complete configuration saved to: iam_resources_output.json")
    logger.info(f"S3 bucket: {s3_info['name']} ({s3_info['arn']})")
    logger.info(f"Source Account Resources - Role: {source_role_name} ({source_role_arn})")
    logger.info(f"Source Account Resources - User: {source_user_name}")
    logger.info(f"Destination Account Resources - Role: {dest_role_name} ({dest_role_arn})")
    logger.info(f"Destination Account Resources - User: {dest_user_name}")
    logger.info("")
    logger.info("IMPORTANT NOTES:")
    logger.info("- IAM policies have been updated to reference the current S3 bucket")
    logger.info("- Existing resources were updated rather than creating duplicates")
    logger.info("- Store access keys securely and delete them from the output file after use!")
    logger.info("- If you see 'EXISTING' for access keys, the user already had keys - check AWS console")
    logger.info("")
    logger.info("NEXT STEPS:")
    logger.info("1. Set up S3 bucket replication if cross-region")
    logger.info("2. Configure OpenSearch snapshot repositories using the respective roles")
    logger.info("3. Test snapshot creation and restoration")
    logger.info("4. Consider cleaning up old unused S3 buckets if any were reported")

if __name__ == "__main__":
    main()