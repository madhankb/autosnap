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
    
    return parser.parse_args()

def create_iam_role(iam_client, role_name, trust_policy, s3_policy, bucket_name, account_type):
    """Create IAM role with necessary policies"""
    logger = logging.getLogger(__name__)
    try:
        # Create the role
        logger.info(f"Creating IAM role: {role_name}")
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=f"Role for OpenSearch snapshots ({account_type}) to S3 bucket {bucket_name}"
        )
        
        # Create and attach the S3 policy
        policy_name = f"{role_name}S3Policy"
        logger.info(f"Creating and attaching policy: {policy_name}")
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(s3_policy)
        )
        
        logger.info(f"Successfully created role: {role_name}")
        return role_response['Role']['Arn']
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logger.warning(f"Role {role_name} already exists")
            # Get existing role ARN
            role = iam_client.get_role(RoleName=role_name)
            return role['Role']['Arn']
        else:
            logger.error(f"Error creating role {role_name}: {e}")
            return None

def create_iam_user(iam_client, user_name, role_arn):
    """Create IAM user with policy to assume the snapshot role"""
    logger = logging.getLogger(__name__)
    try:
        # Create the user
        logger.info(f"Creating IAM user: {user_name}")
        user_response = iam_client.create_user(
            UserName=user_name,
            Path='/',
        )
        
        # Create policy to assume the role
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
        logger.info(f"Creating and attaching policy: {policy_name}")
        
        iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(assume_role_policy)
        )
        
        # Create access keys
        logger.info(f"Creating access keys for user: {user_name}")
        keys_response = iam_client.create_access_key(UserName=user_name)
        
        logger.info(f"Successfully created user: {user_name}")
        return {
            'UserArn': user_response['User']['Arn'],
            'AccessKeyId': keys_response['AccessKey']['AccessKeyId'],
            'SecretAccessKey': keys_response['AccessKey']['SecretAccessKey']
        }
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            logger.warning(f"User {user_name} already exists")
            user = iam_client.get_user(UserName=user_name)
            return {'UserArn': user['User']['Arn']}
        else:
            logger.error(f"Error creating user {user_name}: {e}")
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
            logger.info("Creating new S3 bucket")
            base_bucket_name = "opensearch-snapshots"
            bucket_region = source_info['region']  # Create in source region
            s3_client = boto3.client('s3', region_name=bucket_region)
            
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
            logger.info(f"Created S3 Bucket: {s3_info['name']} in {s3_info['region']}")
        
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
        logger.info(f"Creating additional policy for source user: {additional_policy_name}")
        
        try:
            source_iam.put_user_policy(
                UserName=source_user_name,
                PolicyName=additional_policy_name,
                PolicyDocument=json.dumps(source_additional_policy)
            )
            logger.info(f"Successfully attached OpenSearch policy to user: {source_user_name}")
        except ClientError as e:
            logger.warning(f"Could not attach OpenSearch policy to user {source_user_name}: {e}")
        
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
    
    logger.info("IAM resources created successfully!")
    logger.info(f"Complete configuration saved to: iam_resources_output.json")
    logger.info(f"S3 bucket: {s3_info['name']} ({s3_info['arn']})")
    logger.info(f"Source Account Resources - Role: {source_role_name} ({source_role_arn})")
    logger.info(f"Source Account Resources - User: {source_user_name}")
    logger.info(f"Destination Account Resources - Role: {dest_role_name} ({dest_role_arn})")
    logger.info(f"Destination Account Resources - User: {dest_user_name}")
    logger.info("IMPORTANT: Store the access keys securely and delete them from the output file after use!")
    logger.info("Next steps: 1. Set up S3 bucket replication if cross-region")
    logger.info("Next steps: 2. Configure OpenSearch snapshot repositories using the respective roles")
    logger.info("Next steps: 3. Test snapshot creation and restoration")

if __name__ == "__main__":
    main()