#!/usr/bin/env python3
"""
Unified script for OpenSearch snapshot setup
Creates IAM resources and configures OpenSearch security for snapshot operations

Usage:
  python opensearch_snapshot_setup.py --src-domain SOURCE_ARN --dest-domain DEST_ARN [options]
"""

import json
import boto3
import requests
import sys
import argparse
import uuid
import re
import logging
from datetime import datetime
from urllib.parse import urljoin, urlparse
import urllib3
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def setup_logging(debug=False):
    """Setup logging configuration"""
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger(__name__)

def log_separator():
    """Log a separator line"""
    logger = logging.getLogger(__name__)
    logger.info("-" * 60)

def parse_opensearch_arn(arn):
    """Parse OpenSearch domain ARN and extract components"""
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
    pattern = r'arn:aws:s3:::(.+)'
    match = re.match(pattern, arn)
    
    if not match:
        raise ValueError(f"Invalid S3 bucket ARN format: {arn}")
    
    bucket_name = match.group(1)
    
    try:
        s3_client = boto3.client('s3')
        location = s3_client.get_bucket_location(Bucket=bucket_name)
        region = location['LocationConstraint'] or 'us-east-1'
        
        sts_client = boto3.client('sts')
        account_id = sts_client.get_caller_identity()['Account']
    except ClientError as e:
        print(f"Warning: Could not get bucket details for {bucket_name}: {e}")
        region = 'us-east-1'
        account_id = 'unknown'
    
    return {
        'name': bucket_name,
        'region': region,
        'account_id': account_id,
        'arn': arn
    }

def is_bucket_empty(s3_client, bucket_name):
    """Check if S3 bucket is empty"""
    logger = logging.getLogger(__name__)
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        is_empty = 'Contents' not in response
        logger.debug(f"Bucket {bucket_name} is {'empty' if is_empty else 'not empty'}")
        return is_empty
    except ClientError as e:
        logger.warning(f"Could not check if bucket {bucket_name} is empty: {e}")
        return False

def find_existing_empty_bucket(s3_client, base_name="opensearch-snapshots"):
    """Find existing empty S3 bucket created by previous runs"""
    logger = logging.getLogger(__name__)
    try:
        logger.info("Checking for existing empty snapshot buckets...")
        response = s3_client.list_buckets()
        
        matching_buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            if bucket_name.startswith(base_name):
                try:
                    # Check if bucket has OpenSearch policy
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy = json.loads(policy_response['Policy'])
                    
                    # Look for OpenSearch service principal
                    for statement in policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if isinstance(principal, dict) and principal.get('Service') == 'opensearch.amazonaws.com':
                            # Check if bucket is empty
                            if is_bucket_empty(s3_client, bucket_name):
                                matching_buckets.append({
                                    'name': bucket_name,
                                    'creation_date': bucket['CreationDate']
                                })
                            else:
                                logger.info(f"Bucket {bucket_name} contains data, skipping")
                            break
                except ClientError:
                    continue
        
        if matching_buckets:
            # Sort by creation date and return the most recent
            matching_buckets.sort(key=lambda x: x['creation_date'], reverse=True)
            latest_bucket = matching_buckets[0]
            logger.info(f"Found existing empty bucket: {latest_bucket['name']}")
            return latest_bucket['name']
        else:
            logger.info("No existing empty snapshot buckets found")
            return None
            
    except ClientError as e:
        logger.warning(f"Could not list buckets: {e}")
        return None

def create_trust_policy(account_id, domain_arn, region):
    """Create trust policy for the IAM role"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "es.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": domain_arn}
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
                "Action": ["s3:ListBucket"],
                "Resource": f"arn:aws:s3:::{bucket_name}"
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
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
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # Set bucket policy
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
            logger.warning(f"S3 bucket {bucket_name} already exists")
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

def create_or_update_iam_role(iam_client, role_name, trust_policy, s3_policy, bucket_name, account_type, dry_run=False):
    """Create or update IAM role with necessary policies"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would create/update IAM role: {role_name}")
        logger.debug(f"[DRY RUN] Role trust policy: {json.dumps(trust_policy, indent=2)}")
        logger.debug(f"[DRY RUN] Role S3 policy for bucket: {bucket_name}")
        return f"arn:aws:iam::123456789012:role/{role_name}"
    
    try:
        role_arn = None
        role_exists = False
        
        # Check if role exists
        try:
            role = iam_client.get_role(RoleName=role_name)
            role_arn = role['Role']['Arn']
            role_exists = True
            logger.debug(f"Role {role_name} already exists with ARN: {role_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                role_exists = False
                logger.debug(f"Role {role_name} does not exist, will create")
            else:
                raise e
        
        if not role_exists:
            logger.debug(f"Creating IAM role: {role_name}")
            role_response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"Role for OpenSearch snapshots ({account_type}) to S3 bucket {bucket_name}"
            )
            role_arn = role_response['Role']['Arn']
            logger.debug(f"Created role with ARN: {role_arn}")
        else:
            logger.debug(f"Updating trust policy for existing role: {role_name}")
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(trust_policy)
            )
        
        # Update S3 policy
        policy_name = f"{role_name}S3Policy"
        logger.debug(f"Attaching S3 policy: {policy_name}")
        
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(s3_policy)
        )
        
        logger.info(f"Successfully {'created' if not role_exists else 'updated'} role: {role_name}")
        return role_arn
        
    except ClientError as e:
        logger.error(f"Error with role {role_name}: {e}")
        logger.debug(f"ClientError details: {str(e)}", exc_info=True)
        return None

def create_or_update_iam_user(iam_client, user_name, role_arn, dry_run=False):
    """Create or update IAM user with policy to assume the snapshot role"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would create/update IAM user: {user_name}")
        logger.debug(f"[DRY RUN] User would assume role: {role_arn}")
        return {'UserArn': f"arn:aws:iam::123456789012:user/{user_name}"}
    
    try:
        user_arn = None
        user_exists = False
        access_keys = None
        
        # Check if user exists
        try:
            user = iam_client.get_user(UserName=user_name)
            user_arn = user['User']['Arn']
            user_exists = True
            logger.debug(f"User {user_name} already exists with ARN: {user_arn}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                user_exists = False
                logger.debug(f"User {user_name} does not exist, will create")
            else:
                raise e
        
        if not user_exists:
            logger.debug(f"Creating IAM user: {user_name}")
            user_response = iam_client.create_user(UserName=user_name, Path='/')
            user_arn = user_response['User']['Arn']
            logger.debug(f"Created user with ARN: {user_arn}")
            
            # Create access keys
            logger.debug(f"Creating access keys for user: {user_name}")
            keys_response = iam_client.create_access_key(UserName=user_name)
            access_keys = {
                'AccessKeyId': keys_response['AccessKey']['AccessKeyId'],
                'SecretAccessKey': keys_response['AccessKey']['SecretAccessKey']
            }
        else:
            # Check existing access keys
            try:
                keys_list = iam_client.list_access_keys(UserName=user_name)
                if keys_list['AccessKeyMetadata']:
                    logger.debug(f"User {user_name} already has access keys")
                    access_keys = {'AccessKeyId': 'EXISTING', 'SecretAccessKey': 'EXISTING'}
                else:
                    logger.debug(f"Creating new access keys for existing user: {user_name}")
                    keys_response = iam_client.create_access_key(UserName=user_name)
                    access_keys = {
                        'AccessKeyId': keys_response['AccessKey']['AccessKeyId'],
                        'SecretAccessKey': keys_response['AccessKey']['SecretAccessKey']
                    }
            except ClientError as e:
                logger.warning(f"Could not manage access keys for {user_name}: {e}")
                logger.debug(f"Access key error details: {str(e)}", exc_info=True)
                access_keys = {'AccessKeyId': 'ERROR', 'SecretAccessKey': 'ERROR'}
        
        # Update assume role policy
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
        logger.info(f"Updating policy: {policy_name}")
        logger.debug(f"Assume role policy: {json.dumps(assume_role_policy, indent=2)}")
        
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
        logger.error(f"Error with user {user_name}: {e}")
        logger.debug(f"ClientError details: {str(e)}", exc_info=True)
        return None

def get_opensearch_endpoint(domain_arn):
    """Extract OpenSearch endpoint from domain ARN"""
    logger = logging.getLogger(__name__)
    
    parts = domain_arn.split(':')
    region = parts[3]
    domain_name = parts[5].split('/')[1]
    
    logger.debug(f"Getting endpoint for domain: {domain_name} in region: {region}")
    
    try:
        es_client = boto3.client('es', region_name=region)
        response = es_client.describe_elasticsearch_domain(DomainName=domain_name)
        endpoint = response['DomainStatus']['Endpoint']
        logger.debug(f"Retrieved endpoint: {endpoint}")
        return f"https://{endpoint}"
    except ClientError as e:
        logger.error(f"Error getting domain endpoint: {e}")
        return None

def create_security_session(endpoint, username=None, password=None):
    """Create authenticated session for OpenSearch Security API"""
    session = requests.Session()
    
    if username and password:
        session.auth = HTTPBasicAuth(username, password)
    
    session.headers.update({
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    
    return session

def test_opensearch_connection(session, endpoint, dry_run=False):
    """Test connection to OpenSearch Security API"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would test OpenSearch connection")
        return True
    
    try:
        url = urljoin(endpoint, "_plugins/_security/api/account")
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            return True
        else:
            logger.error(f"Failed to connect to OpenSearch Security API: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Exception testing connection: {e}")
        return False

def get_current_user_arn(dry_run=False):
    """Get current AWS user ARN"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would get current user ARN")
        return "arn:aws:iam::123456789012:user/example-user"
    
    try:
        sts_client = boto3.client('sts')
        response = sts_client.get_caller_identity()
        user_arn = response['Arn']
        logger.info(f"Current AWS user ARN: {user_arn}")
        return user_arn
    except ClientError as e:
        logger.error(f"Error getting current user ARN: {e}")
        return None

def update_role_mapping(session, endpoint, role_name, mapping_config, dry_run=False):
    """Update role mapping in OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would update role mapping for {role_name}")
        return True
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        
        response = session.put(url, json=mapping_config, verify=False)
        
        if response.status_code in [200, 201]:
            return True
        else:
            logger.error(f"Failed to update role mapping: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Exception updating role mapping: {e}")
        return False

def configure_opensearch_security(config, username, password, dry_run=False):
    """Configure OpenSearch security mappings"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Configuring OpenSearch Security ===")
    
    # Get source domain endpoint
    logger.debug(f"Getting endpoint for domain: {config['source']['domain_arn']}")
    source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
    if not source_endpoint:
        logger.error("Could not get source domain endpoint")
        return False
    
    logger.info(f"Source domain endpoint: {source_endpoint}")
    
    if dry_run:
        logger.info("[DRY RUN] Would create security session and test connection")
        logger.info("[DRY RUN] Would configure role mappings")
        return True
    
    # Create session
    logger.debug("Creating OpenSearch security session")
    session = create_security_session(source_endpoint, username, password)
    
    # Test connection
    logger.debug("Testing OpenSearch connection")
    if not test_opensearch_connection(session, source_endpoint, dry_run):
        logger.error("Failed to connect to OpenSearch Security API")
        return False
    
    # Get current user ARN
    logger.debug("Getting current AWS user ARN")
    current_user_arn = get_current_user_arn(dry_run)
    if not current_user_arn:
        logger.error("Could not get current user ARN")
        return False
    
    success_count = 0
    
    # Configure all_access role mapping
    all_access_mapping = {
        "backend_roles": [],
        "users": [current_user_arn],
        "description": "Mapping current AWS user to all_access role"
    }
    logger.debug(f"all_access mapping: {json.dumps(all_access_mapping, indent=2)}")
    
    if update_role_mapping(session, source_endpoint, "all_access", all_access_mapping, dry_run):
        success_count += 1
        logger.info("Configured all_access role mapping")
    
    # Configure manage_snapshots role mapping
    manage_snapshots_mapping = {
        "backend_roles": [config['source']['role_arn']],
        "users": [config['source']['user_info']['UserArn']],
        "description": "Mapping for OpenSearch snapshot operations"
    }
    logger.debug(f"manage_snapshots mapping: {json.dumps(manage_snapshots_mapping, indent=2)}")
    
    if update_role_mapping(session, source_endpoint, "manage_snapshots", manage_snapshots_mapping, dry_run):
        success_count += 1
        logger.info("Configured manage_snapshots role mapping")
    
    return success_count == 2

def aws_signed_request(method, url, region, service, payload, access_key, secret_key, session_token=None):
    """Make AWS signed request"""
    logger = logging.getLogger(__name__)
    
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    
    credentials = Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=session_token
    )
    
    headers = {
        'Content-Type': 'application/json',
        'Host': host
    }
    
    request = AWSRequest(
        method=method,
        url=url,
        data=payload,
        headers=headers
    )
    
    SigV4Auth(credentials, service, region).add_auth(request)
    
    response = requests.request(
        method=method,
        url=url,
        data=payload,
        headers=dict(request.headers),
        verify=False
    )
    
    return response

def register_snapshot_repository(config, dry_run=False):
    """Register snapshot repository using AWS IAM authentication"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Registering Snapshot Repository ===")
    
    if dry_run:
        logger.info("[DRY RUN] Would register snapshot repository: automated-snapshots")
        logger.debug(f"[DRY RUN] Repository would use S3 bucket: {config['s3_bucket']['name']}")
        logger.debug(f"[DRY RUN] Repository would use IAM role: {config['source']['role_arn']}")
        return True
    
    try:
        logger.debug(f"Getting endpoint for domain: {config['source']['domain_arn']}")
        source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
        if not source_endpoint:
            logger.error("Could not get source domain endpoint")
            return False
        
        source_region = config['source']['region']
        logger.debug(f"Source region: {source_region}")
        
        # Get AWS credentials
        logger.debug("Getting AWS credentials")
        boto_session = boto3.Session()
        credentials = boto_session.get_credentials()
        
        if credentials is None:
            logger.error("No AWS credentials found")
            return False
        
        # Repository configuration
        repo_name = "automated-snapshots"
        repository_config = {
            "type": "s3",
            "settings": {
                "bucket": config['s3_bucket']['name'],
                "region": config['s3_bucket']['region'],
                "role_arn": config['source']['role_arn']
            }
        }
        
        url = f"{source_endpoint}/_snapshot/{repo_name}"
        payload = json.dumps(repository_config)
        
        logger.debug(f"Repository URL: {url}")
        logger.debug(f"Repository config: {json.dumps(repository_config, indent=2)}")
        
        logger.debug("Making signed AWS request to register repository")
        response = aws_signed_request(
            method='PUT',
            url=url,
            region=source_region,
            service='es',
            payload=payload,
            access_key=credentials.access_key,
            secret_key=credentials.secret_key,
            session_token=credentials.token
        )
        
        logger.debug(f"Repository registration response status: {response.status_code}")
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully registered snapshot repository: {repo_name}")
            return True
        else:
            logger.error(f"Failed to register repository: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception registering snapshot repository: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Unified OpenSearch snapshot setup script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Complete setup (creates IAM resources, configures security, registers repository)
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword
  
  # With existing S3 bucket
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --s3-bucket "arn:aws:s3:::my-bucket" \\
    --username admin --password mypassword
  
  # Skip repository registration
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword --skip-repository
  
  # Dry run to see what would be done
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword --dry-run
        """
    )
    
    parser.add_argument('--src-domain', required=True,
                       help='Source OpenSearch domain ARN')
    parser.add_argument('--dest-domain', required=True,
                       help='Destination OpenSearch domain ARN')
    parser.add_argument('--s3-bucket',
                       help='S3 bucket ARN (if not provided, will create/reuse empty bucket)')
    parser.add_argument('--s3',
                       help='Alias for --s3-bucket (S3 bucket ARN)')
    parser.add_argument('--role-name', default='OpenSearchSnapshotRole',
                       help='IAM role name prefix (default: OpenSearchSnapshotRole)')
    parser.add_argument('--user-name', default='OpenSearchSnapshotUser',
                       help='IAM user name prefix (default: OpenSearchSnapshotUser)')
    parser.add_argument('--username',
                       help='OpenSearch admin username (required for security config)')
    parser.add_argument('--password',
                       help='OpenSearch admin password (required for security config)')
    parser.add_argument('--force-new-bucket', action='store_true',
                       help='Force creation of new S3 bucket')
    parser.add_argument('--skip-security', action='store_true',
                       help='Skip OpenSearch security configuration')
    parser.add_argument('--skip-repository', action='store_true',
                       help='Skip snapshot repository registration')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Handle s3 alias
    if args.s3 and not args.s3_bucket:
        args.s3_bucket = args.s3
    
    logger = setup_logging(debug=args.debug)
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
        log_separator()
    else:
        logger.info("=== Starting OpenSearch Snapshot Setup ===")
        log_separator()
    
    try:
        # Parse domain ARNs
        logger.debug(f"Parsing source domain ARN: {args.src_domain}")
        source_info = parse_opensearch_arn(args.src_domain)
        logger.debug(f"Parsing destination domain ARN: {args.dest_domain}")
        dest_info = parse_opensearch_arn(args.dest_domain)
        
        logger.info(f"Source: {source_info['domain_name']} ({source_info['region']})")
        logger.info(f"Destination: {dest_info['domain_name']} ({dest_info['region']})")
        log_separator()
        
        # Handle S3 bucket
        if args.s3_bucket:
            logger.info("Using provided S3 bucket")
            logger.debug(f"Parsing S3 bucket ARN: {args.s3_bucket}")
            s3_info = parse_s3_arn(args.s3_bucket)
            logger.debug(f"S3 bucket details: {s3_info}")
        else:
            logger.info("Managing S3 bucket automatically")
            base_bucket_name = "opensearch-snapshots"
            bucket_region = source_info['region']
            s3_client = boto3.client('s3', region_name=bucket_region)
            
            # Find existing empty bucket or create new one
            if args.force_new_bucket:
                logger.debug("Force new bucket flag set, skipping existing bucket search")
                existing_bucket = None
            else:
                existing_bucket = find_existing_empty_bucket(s3_client, base_bucket_name)
            
            if existing_bucket and not args.force_new_bucket:
                bucket_name = existing_bucket
                logger.debug(f"Reusing existing empty bucket: {bucket_name}")
            else:
                if args.force_new_bucket:
                    logger.debug("Creating new bucket due to --force-new-bucket flag")
                else:
                    logger.debug("No suitable existing bucket found, creating new one")
                    
                max_attempts = 5
                bucket_created = False
                
                for attempt in range(max_attempts):
                    bucket_name = generate_unique_bucket_name(base_bucket_name)
                    logger.debug(f"Attempt {attempt + 1}/{max_attempts}: Trying bucket name {bucket_name}")
                    
                    if args.dry_run:
                        logger.info(f"[DRY RUN] Would create bucket: {bucket_name}")
                        bucket_created = True
                        break
                    elif create_s3_bucket(s3_client, bucket_name, bucket_region):
                        bucket_created = True
                        break
                    else:
                        logger.debug(f"Bucket name {bucket_name} not available")
                
                if not bucket_created:
                    logger.error("Failed to create S3 bucket after multiple attempts")
                    return
            
            s3_info = {
                'name': bucket_name,
                'region': bucket_region,
                'account_id': source_info['account_id'],
                'arn': f"arn:aws:s3:::{bucket_name}"
            }
        
        logger.info(f"Using S3 bucket: {s3_info['name']}")
        log_separator()
        
    except ValueError as e:
        logger.error(f"Error parsing ARNs: {e}")
        logger.debug(f"ValueError details: {str(e)}", exc_info=True)
        return
    except Exception as e:
        logger.error(f"Error processing inputs: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return
    
    # Create S3 policy
    logger.debug("Creating S3 policy for snapshot operations")
    s3_policy = create_s3_policy(s3_info['name'])
    logger.debug(f"S3 policy: {json.dumps(s3_policy, indent=2)}")
    
    # Process source account
    logger.info("=== Processing SOURCE account ===")
    try:
        if not args.dry_run:
            logger.debug(f"Creating IAM client for source region: {source_info['region']}")
            source_iam = boto3.client('iam', region_name=source_info['region'])
        
        source_role_name = f"{args.role_name}-src"
        source_user_name = f"{args.user_name}-src"
        
        logger.debug(f"Source role name: {source_role_name}")
        logger.debug(f"Source user name: {source_user_name}")
        
        trust_policy = create_trust_policy(
            source_info['account_id'], 
            source_info['arn'], 
            source_info['region']
        )
        logger.debug(f"Source trust policy: {json.dumps(trust_policy, indent=2)}")
        
        if args.dry_run:
            logger.info(f"[DRY RUN] Would create/update role: {source_role_name}")
            logger.info(f"[DRY RUN] Would create/update user: {source_user_name}")
            logger.info(f"[DRY RUN] Would add OpenSearch policy to user: {source_user_name}")
            source_role_arn = f"arn:aws:iam::{source_info['account_id']}:role/{source_role_name}"
            source_user_info = {'UserArn': f"arn:aws:iam::{source_info['account_id']}:user/{source_user_name}"}
        else:
            source_role_arn = create_or_update_iam_role(
                source_iam, source_role_name, trust_policy, s3_policy, s3_info['name'], "source", args.dry_run
            )
            
            source_user_info = create_or_update_iam_user(
                source_iam, source_user_name, source_role_arn, args.dry_run
            )
            
            # Add OpenSearch policy to user
            opensearch_policy = {
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
            logger.debug(f"OpenSearch policy for user: {json.dumps(opensearch_policy, indent=2)}")
            
            try:
                source_iam.put_user_policy(
                    UserName=source_user_name,
                    PolicyName=f"{source_user_name}OpenSearchPolicy",
                    PolicyDocument=json.dumps(opensearch_policy)
                )
                logger.info(f"Added OpenSearch policy to user: {source_user_name}")
            except ClientError as e:
                logger.warning(f"Could not add OpenSearch policy: {e}")
                logger.debug(f"OpenSearch policy error details: {str(e)}", exc_info=True)
        
        log_separator()
        
    except Exception as e:
        logger.error(f"Error processing source account: {e}")
        logger.debug(f"Source account error details: {str(e)}", exc_info=True)
        return
    
    # Process destination account
    logger.info("=== Processing DESTINATION account ===")
    try:
        if not args.dry_run:
            logger.debug(f"Creating IAM client for destination region: {dest_info['region']}")
            dest_iam = boto3.client('iam', region_name=dest_info['region'])
        
        dest_role_name = f"{args.role_name}-dest"
        dest_user_name = f"{args.user_name}-dest"
        
        logger.debug(f"Destination role name: {dest_role_name}")
        logger.debug(f"Destination user name: {dest_user_name}")
        
        trust_policy = create_trust_policy(
            dest_info['account_id'], 
            dest_info['arn'], 
            dest_info['region']
        )
        logger.debug(f"Destination trust policy: {json.dumps(trust_policy, indent=2)}")
        
        if args.dry_run:
            logger.info(f"[DRY RUN] Would create/update role: {dest_role_name}")
            logger.info(f"[DRY RUN] Would create/update user: {dest_user_name}")
            dest_role_arn = f"arn:aws:iam::{dest_info['account_id']}:role/{dest_role_name}"
            dest_user_info = {'UserArn': f"arn:aws:iam::{dest_info['account_id']}:user/{dest_user_name}"}
        else:
            dest_role_arn = create_or_update_iam_role(
                dest_iam, dest_role_name, trust_policy, s3_policy, s3_info['name'], "destination", args.dry_run
            )
            
            dest_user_info = create_or_update_iam_user(
                dest_iam, dest_user_name, dest_role_arn, args.dry_run
            )
        
        log_separator()
        
    except Exception as e:
        logger.error(f"Error processing destination account: {e}")
        logger.debug(f"Destination account error details: {str(e)}", exc_info=True)
        return
    
    # Create configuration
    config = {
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
    
    # Save configuration
    if not args.dry_run:
        with open('opensearch_snapshot_config.json', 'w') as f:
            json.dump(config, f, indent=2)
    
    # Configure OpenSearch security if requested
    if not args.skip_security:
        if not args.username or not args.password:
            logger.warning("OpenSearch username/password not provided, skipping security configuration")
            logger.warning("Use --username and --password to configure security mappings")
            log_separator()
        else:
            if args.dry_run:
                logger.info("=== Configuring OpenSearch Security ===")
                logger.info(f"[DRY RUN] Would configure security for: {source_info['domain_name']}")
                logger.info(f"[DRY RUN] Would map current user to all_access role")
                logger.info(f"[DRY RUN] Would map IAM role/user to manage_snapshots role")
                log_separator()
            else:
                security_success = configure_opensearch_security(config, args.username, args.password, args.dry_run)
                log_separator()
    
    # Register repository by default (unless skipped or no credentials)
    if not args.skip_repository:
        if not args.username or not args.password:
            if not args.skip_security:
                logger.warning("Cannot register repository without OpenSearch credentials")
                logger.warning("Use --username and --password to enable repository registration")
            log_separator()
        else:
            if args.dry_run:
                logger.info("=== Registering Snapshot Repository ===")
                logger.info("[DRY RUN] Would register snapshot repository: automated-snapshots")
                log_separator()
            else:
                repo_success = register_snapshot_repository(config, args.dry_run)
                log_separator()
    
    # Summary
    logger.info("=== Setup Summary ===")
    logger.info(f"S3 bucket: {s3_info['name']}")
    logger.info(f"Source role: {source_role_name}")
    logger.info(f"Source user: {source_user_name}")
    logger.info(f"Destination role: {dest_role_name}")
    logger.info(f"Destination user: {dest_user_name}")
    log_separator()
    
    if args.dry_run:
        logger.info("DRY RUN COMPLETE - No actual changes were made")
    else:
        logger.info("Setup completed successfully!")

if __name__ == "__main__":
    main()