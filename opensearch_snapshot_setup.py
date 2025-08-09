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
import random
import string
import time
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

def generate_repository_name():
    """Generate a unique repository name in format: manualsnap-repo-<4 chars>"""
    unique_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    return f"manualsnap-repo-{unique_suffix}"

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

def get_existing_role_mapping(session, endpoint, role_name, dry_run=False):
    """Get existing role mapping from OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug(f"[DRY RUN] Would get existing role mapping for {role_name}")
        return {}
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            mapping_data = response.json()
            existing_mapping = mapping_data.get(role_name, {})
            logger.debug(f"Retrieved existing mapping for {role_name}: {json.dumps(existing_mapping, indent=2)}")
            return existing_mapping
        elif response.status_code == 404:
            logger.debug(f"Role mapping {role_name} does not exist yet")
            return {}
        else:
            logger.warning(f"Could not get existing role mapping {role_name}: {response.status_code}")
            return {}
            
    except Exception as e:
        logger.warning(f"Exception getting existing role mapping {role_name}: {e}")
        return {}

def add_to_role_mapping(session, endpoint, role_name, users_to_add=None, backend_roles_to_add=None, description=None, dry_run=False):
    """Add users/roles to existing role mapping without overwriting"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would add to role mapping for {role_name}")
        if users_to_add:
            logger.debug(f"[DRY RUN] Would add users: {users_to_add}")
        if backend_roles_to_add:
            logger.debug(f"[DRY RUN] Would add backend roles: {backend_roles_to_add}")
        return True
    
    try:
        # Get existing mapping first
        existing_mapping = get_existing_role_mapping(session, endpoint, role_name, dry_run)
        
        # Start with existing values or empty lists
        existing_users = existing_mapping.get('users', [])
        existing_backend_roles = existing_mapping.get('backend_roles', [])
        existing_description = existing_mapping.get('description', '')
        
        # Add new users (avoid duplicates)
        updated_users = existing_users.copy()
        if users_to_add:
            for user in users_to_add:
                if user and user not in updated_users:
                    updated_users.append(user)
                    logger.info(f"Adding user {user} to {role_name} role")
                elif user in updated_users:
                    logger.debug(f"User {user} already exists in {role_name} role")
        
        # Add new backend roles (avoid duplicates)
        updated_backend_roles = existing_backend_roles.copy()
        if backend_roles_to_add:
            for role in backend_roles_to_add:
                if role and role not in updated_backend_roles:
                    updated_backend_roles.append(role)
                    logger.info(f"Adding backend role {role} to {role_name} role")
                elif role in updated_backend_roles:
                    logger.debug(f"Backend role {role} already exists in {role_name} role")
        
        # Use provided description or keep existing one
        final_description = description if description else existing_description
        
        # Create updated mapping
        updated_mapping = {
            "backend_roles": updated_backend_roles,
            "users": updated_users,
            "description": final_description
        }
        
        logger.debug(f"Updated mapping for {role_name}: {json.dumps(updated_mapping, indent=2)}")
        
        # Update the mapping
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        response = session.put(url, json=updated_mapping, verify=False)
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully updated role mapping for {role_name}")
            return True
        else:
            logger.error(f"Failed to update role mapping {role_name}: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception updating role mapping {role_name}: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def update_role_mapping(session, endpoint, role_name, mapping_config, dry_run=False):
    """Update role mapping in OpenSearch (legacy function - use add_to_role_mapping for safer updates)"""
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
    
    # Add current user to all_access role mapping (preserving existing users)
    logger.debug(f"Adding current user to all_access role: {current_user_arn}")
    
    if add_to_role_mapping(
        session, 
        source_endpoint, 
        "all_access", 
        users_to_add=[current_user_arn],
        description="Mapping AWS users to all_access role",
        dry_run=dry_run
    ):
        success_count += 1
        logger.info("Added current user to all_access role mapping")
    
    # Add IAM role and user to manage_snapshots role mapping (preserving existing mappings)
    logger.debug(f"Adding IAM resources to manage_snapshots role:")
    logger.debug(f"  Backend role: {config['source']['role_arn']}")
    logger.debug(f"  User: {config['source']['user_info']['UserArn']}")
    
    if add_to_role_mapping(
        session,
        source_endpoint,
        "manage_snapshots",
        users_to_add=[config['source']['user_info']['UserArn']],
        backend_roles_to_add=[config['source']['role_arn']],
        description="Mapping for OpenSearch snapshot operations",
        dry_run=dry_run
    ):
        success_count += 1
        logger.info("Added IAM resources to manage_snapshots role mapping")
    
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

def validate_repository_prerequisites(config):
    """Validate that IAM role and S3 bucket are properly configured"""
    logger = logging.getLogger(__name__)
    
    logger.debug("Validating repository prerequisites...")
    
    # Check if IAM role exists and is accessible
    try:
        source_region = config['source']['region']
        iam_client = boto3.client('iam', region_name=source_region)
        role_name = config['source']['role_name']
        
        role = iam_client.get_role(RoleName=role_name)
        logger.debug(f"IAM role {role_name} exists and is accessible")
        
        # Check role policies
        policies = iam_client.list_role_policies(RoleName=role_name)
        logger.debug(f"Role has {len(policies['PolicyNames'])} inline policies")
        
    except ClientError as e:
        logger.warning(f"Could not validate IAM role: {e}")
        return False
    
    # Check if S3 bucket exists and is accessible
    try:
        bucket_name = config['s3_bucket']['name']
        bucket_region = config['s3_bucket']['region']
        s3_client = boto3.client('s3', region_name=bucket_region)
        
        # Check bucket exists
        s3_client.head_bucket(Bucket=bucket_name)
        logger.debug(f"S3 bucket {bucket_name} exists and is accessible")
        
        # Check bucket policy
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(policy_response['Policy'])
            
            # Look for OpenSearch service principal
            has_opensearch_policy = False
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, dict) and principal.get('Service') == 'opensearch.amazonaws.com':
                    has_opensearch_policy = True
                    break
            
            if has_opensearch_policy:
                logger.debug("S3 bucket has OpenSearch service policy")
            else:
                logger.warning("S3 bucket may not have proper OpenSearch service policy")
                
        except ClientError as e:
            logger.warning(f"Could not check S3 bucket policy: {e}")
        
    except ClientError as e:
        logger.warning(f"Could not validate S3 bucket: {e}")
        return False
    
    logger.debug("Repository prerequisites validation completed")
    return True

def verify_repository_registration(config, repo_name=None):
    """Verify that the repository was registered successfully"""
    logger = logging.getLogger(__name__)
    
    if repo_name is None:
        repo_name = config.get('repository_name', 'automated-snapshots')
    
    try:
        source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
        if not source_endpoint:
            logger.error("Could not get source domain endpoint for verification")
            return False
        
        source_region = config['source']['region']
        
        # Get AWS credentials
        boto_session = boto3.Session()
        credentials = boto_session.get_credentials()
        
        if credentials is None:
            logger.error("No AWS credentials found for verification")
            return False
        
        # Check if repository exists
        url = f"{source_endpoint}/_snapshot/{repo_name}"
        
        logger.debug(f"Verifying repository at: {url}")
        response = aws_signed_request(
            method='GET',
            url=url,
            region=source_region,
            service='es',
            payload=None,
            access_key=credentials.access_key,
            secret_key=credentials.secret_key,
            session_token=credentials.token
        )
        
        if response.status_code == 200:
            repo_data = response.json()
            logger.info(f"Repository verification successful: {repo_name}")
            logger.debug(f"Repository details: {json.dumps(repo_data, indent=2)}")
            return True
        else:
            logger.warning(f"Repository verification failed: {response.status_code}")
            logger.debug(f"Verification response: {response.text}")
            return False
            
    except Exception as e:
        logger.warning(f"Exception during repository verification: {e}")
        return False

# Snapshot-related functions (from take_snapshot.py)
def create_snapshot_session(endpoint, username=None, password=None, use_aws_auth=False, region=None):
    """Create authenticated session for OpenSearch API"""
    session = requests.Session()
    
    if use_aws_auth and region:
        # AWS IAM authentication will be handled per request
        pass
    elif username and password:
        session.auth = HTTPBasicAuth(username, password)
    
    session.headers.update({
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    
    return session

def test_snapshot_connection(session, endpoint, use_aws_auth=False, region=None, dry_run=False):
    """Test connection to OpenSearch cluster"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would test OpenSearch connection")
        return True
    
    try:
        # Try to get cluster info
        url = urljoin(endpoint, "_cluster/health")
        logger.debug(f"Testing connection to: {url}")
        
        if use_aws_auth and region:
            response = aws_signed_request_snapshot('GET', url, region, 'es', session=session)
        else:
            response = session.get(url, verify=False)
        
        if response and response.status_code == 200:
            logger.debug("OpenSearch connection test successful")
            cluster_info = response.json()
            cluster_name = cluster_info.get('cluster_name', 'unknown')
            status = cluster_info.get('status', 'unknown')
            logger.debug(f"Connected to cluster: {cluster_name} (status: {status})")
            return True
        else:
            status_code = response.status_code if response else 'No response'
            logger.error(f"OpenSearch connection test failed: {status_code}")
            
            if response:
                logger.debug(f"Connection test response: {response.text}")
                
                if response.status_code == 401:
                    logger.error("AUTHENTICATION FAILED - Check username/password")
                elif response.status_code == 403:
                    logger.error("PERMISSION DENIED - User may not have cluster access")
                elif response.status_code == 404:
                    logger.error("ENDPOINT NOT FOUND - Check domain URL")
            
            return False
            
    except Exception as e:
        logger.error(f"Exception testing OpenSearch connection: {e}")
        logger.debug(f"Connection test exception: {str(e)}", exc_info=True)
        return False

def aws_signed_request_snapshot(method, url, region, service, payload=None, session=None):
    """Make AWS signed request for snapshots"""
    logger = logging.getLogger(__name__)
    
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    
    # Get AWS credentials
    boto_session = boto3.Session()
    credentials = boto_session.get_credentials()
    
    if credentials is None:
        logger.error("No AWS credentials found")
        return None
    
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
    
    if session:
        response = session.request(
            method=method,
            url=url,
            data=payload,
            headers=dict(request.headers),
            verify=False
        )
    else:
        response = requests.request(
            method=method,
            url=url,
            data=payload,
            headers=dict(request.headers),
            verify=False
        )
    
    return response

def check_snapshot_status(session, endpoint, use_aws_auth=False, region=None, dry_run=False):
    """Check if any snapshots are currently in progress"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would check snapshot status")
        return True, []
    
    try:
        url = urljoin(endpoint, "_snapshot/_status")
        logger.debug(f"Checking snapshot status at: {url}")
        
        if use_aws_auth and region:
            response = aws_signed_request_snapshot('GET', url, region, 'es', session=session)
        else:
            response = session.get(url, verify=False)
        
        if response.status_code == 200:
            status_data = response.json()
            snapshots = status_data.get('snapshots', [])
            
            if snapshots:
                logger.warning(f"Found {len(snapshots)} snapshots in progress:")
                for snapshot in snapshots:
                    repo = snapshot.get('repository', 'unknown')
                    name = snapshot.get('snapshot', 'unknown')
                    state = snapshot.get('state', 'unknown')
                    logger.warning(f"  - {repo}/{name} (state: {state})")
                return False, snapshots
            else:
                logger.info("No snapshots currently in progress")
                return True, []
        else:
            logger.error(f"Failed to check snapshot status: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False, []
            
    except Exception as e:
        logger.error(f"Exception checking snapshot status: {e}")
        return False, []

def create_snapshot_async(session, endpoint, repository, snapshot_name, indices=None, 
                         use_aws_auth=False, region=None, dry_run=False):
    """Create a manual snapshot asynchronously and return task ID"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would create snapshot: {repository}/{snapshot_name}")
        if indices:
            logger.info(f"[DRY RUN] Would include indices: {', '.join(indices)}")
        return True, "dry-run-task-id"
    
    try:
        # Use wait_for_completion=false to make it asynchronous
        url = urljoin(endpoint, f"_snapshot/{repository}/{snapshot_name}?wait_for_completion=false")
        logger.info(f"Creating snapshot asynchronously: {repository}/{snapshot_name}")
        logger.debug(f"Snapshot URL: {url}")
        
        # Prepare snapshot configuration
        snapshot_config = {}
        if indices:
            snapshot_config['indices'] = ','.join(indices)
            logger.info(f"Including specific indices: {', '.join(indices)}")
        else:
            logger.info("Including all indices")
        
        payload = json.dumps(snapshot_config) if snapshot_config else None
        
        if use_aws_auth and region:
            response = aws_signed_request_snapshot('PUT', url, region, 'es', payload=payload, session=session)
        else:
            response = session.put(url, json=snapshot_config, verify=False)
        
        if response.status_code in [200, 201, 202]:
            response_data = response.json()
            task_id = response_data.get('task')
            
            if task_id:
                logger.info(f"Successfully initiated async snapshot: {repository}/{snapshot_name}")
                logger.info(f"Task ID: {task_id}")
                return True, task_id
            else:
                # Fallback: snapshot might have completed immediately
                logger.info(f"Snapshot initiated (no task ID returned - may have completed immediately)")
                return True, None
        else:
            logger.error(f"Failed to create snapshot: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False, None
            
    except Exception as e:
        logger.error(f"Exception creating snapshot: {e}")
        return False, None

def get_snapshot_info(session, endpoint, repository, snapshot_name=None, 
                     use_aws_auth=False, region=None, dry_run=False):
    """Get information about snapshots"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would get snapshot info for: {repository}")
        return True, {}
    
    try:
        if snapshot_name:
            url = urljoin(endpoint, f"_snapshot/{repository}/{snapshot_name}")
            logger.debug(f"Getting info for specific snapshot: {snapshot_name}")
        else:
            url = urljoin(endpoint, f"_snapshot/{repository}/_all?pretty")
            logger.debug(f"Getting info for all snapshots in repository: {repository}")
        
        logger.debug(f"Snapshot info URL: {url}")
        
        if use_aws_auth and region:
            response = aws_signed_request_snapshot('GET', url, region, 'es', session=session)
        else:
            response = session.get(url, verify=False)
        
        if response.status_code == 200:
            snapshot_data = response.json()
            return True, snapshot_data
        else:
            logger.error(f"Failed to get snapshot info: {response.status_code}")
            logger.debug(f"Response: {response.text}")
            return False, {}
            
    except Exception as e:
        logger.error(f"Exception getting snapshot info: {e}")
        return False, {}

def get_task_status(session, endpoint, task_id, use_aws_auth=False, region=None, dry_run=False):
    """Get task status from OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug(f"[DRY RUN] Would check task status: {task_id}")
        return True, {"completed": True, "task": {"status": "SUCCESS"}}
    
    try:
        url = urljoin(endpoint, f"_tasks/{task_id}")
        logger.debug(f"Checking task status at: {url}")
        
        if use_aws_auth and region:
            response = aws_signed_request_snapshot('GET', url, region, 'es', session=session)
        else:
            response = session.get(url, verify=False)
        
        if response.status_code == 200:
            task_data = response.json()
            return True, task_data
        elif response.status_code == 404:
            # Task might have completed and been cleaned up
            logger.debug(f"Task {task_id} not found (may have completed)")
            return True, {"completed": True, "task": {"status": "COMPLETED"}}
        else:
            logger.warning(f"Failed to get task status: {response.status_code}")
            logger.debug(f"Task status response: {response.text}")
            return False, {}
            
    except Exception as e:
        logger.warning(f"Exception getting task status: {e}")
        return False, {}

def wait_for_task_completion(session, endpoint, task_id, repository, snapshot_name,
                           timeout_minutes=60, use_aws_auth=False, region=None):
    """Wait for task to complete using task ID monitoring"""
    logger = logging.getLogger(__name__)
    
    logger.info(f"Monitoring task completion for snapshot {repository}/{snapshot_name}")
    logger.info(f"Task ID: {task_id}")
    logger.info(f"Timeout: {timeout_minutes} minutes")
    
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    check_interval = 10  # Check every 10 seconds
    
    while True:
        success, task_data = get_task_status(session, endpoint, task_id, use_aws_auth, region)
        
        if success:
            completed = task_data.get('completed', False)
            
            if completed:
                task_info = task_data.get('task', {})
                status = task_info.get('status', 'UNKNOWN')
                
                if status in ['SUCCESS', 'COMPLETED']:
                    # Get final snapshot info to show details
                    snapshot_success, snapshot_data = get_snapshot_info(
                        session, endpoint, repository, snapshot_name, use_aws_auth, region
                    )
                    
                    if snapshot_success and 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                        snapshot = snapshot_data['snapshots'][0]
                        duration = snapshot.get('duration_in_millis', 0) / 1000
                        logger.info(f"Task completed successfully in {duration:.1f} seconds")
                        return True, snapshot
                    else:
                        logger.info("Task completed successfully")
                        return True, task_info
                        
                elif status == 'FAILED':
                    failures = task_info.get('failures', [])
                    error = task_info.get('error', {})
                    logger.error(f"Task failed. Status: {status}")
                    if failures:
                        logger.error(f"Failures: {failures}")
                    if error:
                        logger.error(f"Error: {error}")
                    return False, task_info
                else:
                    logger.warning(f"Task completed with unexpected status: {status}")
                    return False, task_info
            else:
                # Task still running
                elapsed = time.time() - start_time
                task_info = task_data.get('task', {})
                description = task_info.get('description', 'snapshot operation')
                
                # Try to get progress info if available
                status_info = task_info.get('status', {})
                if isinstance(status_info, dict):
                    total = status_info.get('total', 0)
                    created = status_info.get('created', 0)
                    if total > 0:
                        progress = (created / total) * 100
                        logger.info(f"Task in progress: {description} ({progress:.1f}% - {created}/{total}) (elapsed: {elapsed:.0f}s)")
                    else:
                        logger.info(f"Task in progress: {description} (elapsed: {elapsed:.0f}s)")
                else:
                    logger.info(f"Task in progress: {description} (elapsed: {elapsed:.0f}s)")
        else:
            # Fallback to snapshot status if task monitoring fails
            logger.debug("Task monitoring failed, falling back to snapshot status check")
            snapshot_success, snapshot_data = get_snapshot_info(
                session, endpoint, repository, snapshot_name, use_aws_auth, region
            )
            
            if snapshot_success and 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                snapshot = snapshot_data['snapshots'][0]
                state = snapshot.get('state', 'UNKNOWN')
                
                if state == 'SUCCESS':
                    duration = snapshot.get('duration_in_millis', 0) / 1000
                    logger.info(f"Snapshot completed successfully in {duration:.1f} seconds")
                    return True, snapshot
                elif state == 'FAILED':
                    failures = snapshot.get('failures', [])
                    logger.error(f"Snapshot failed. Failures: {failures}")
                    return False, snapshot
        
        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout_seconds:
            logger.error(f"Timeout waiting for task completion ({timeout_minutes} minutes)")
            return False, {}
        
        # Wait before next check
        time.sleep(check_interval)

def generate_snapshot_name(base_name=None):
    """Generate a unique snapshot name with timestamp"""
    if not base_name:
        base_name = "manual-snapshot"
    
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{base_name}-{timestamp}"

def normalize_domain_url(domain_url):
    """Normalize domain URL to ensure it has proper scheme"""
    logger = logging.getLogger(__name__)
    
    if not domain_url:
        raise ValueError("Domain URL cannot be empty")
    
    # Remove any trailing slashes
    domain_url = domain_url.rstrip('/')
    
    # Add https:// if no scheme is provided
    if not domain_url.startswith(('http://', 'https://')):
        domain_url = f"https://{domain_url}"
        logger.debug(f"Added https:// scheme to domain URL: {domain_url}")
    
    # Validate the URL format
    try:
        parsed = urlparse(domain_url)
        if not parsed.netloc:
            raise ValueError(f"Invalid domain URL format: {domain_url}")
        logger.debug(f"Normalized domain URL: {domain_url}")
        return domain_url
    except Exception as e:
        raise ValueError(f"Invalid domain URL: {domain_url} - {e}")

def load_config_for_snapshot(config_file='opensearch_snapshot_config.json'):
    """Load configuration for snapshot operations"""
    logger = logging.getLogger(__name__)
    try:
        logger.debug(f"Loading configuration from: {config_file}")
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.debug("Configuration loaded successfully")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_file} not found")
        logger.error("Make sure you have run the setup mode first")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {config_file}: {e}")
        return None

def take_manual_snapshot(config, username, password, snapshot_name=None, indices=None, 
                        use_aws_auth=False, region=None, wait_for_completion=False, 
                        timeout_minutes=60, force=False, dry_run=False):
    """Take a manual snapshot using the configured repository"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Taking Manual Snapshot ===")
    
    # Get source domain endpoint
    source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
    if not source_endpoint:
        logger.error("Could not get source domain endpoint")
        return False
    
    # Normalize domain URL
    try:
        domain_url = normalize_domain_url(source_endpoint)
        logger.info(f"OpenSearch domain: {domain_url}")
    except ValueError as e:
        logger.error(f"Invalid domain URL: {e}")
        return False
    
    # Get repository name from config
    repository_name = config.get('repository_name', 'automated-snapshots')
    logger.info(f"Repository: {repository_name}")
    
    # Generate snapshot name if not provided
    if not snapshot_name:
        snapshot_name = generate_snapshot_name()
    logger.info(f"Snapshot name: {snapshot_name}")
    
    # Parse indices if provided
    parsed_indices = None
    if indices:
        parsed_indices = [idx.strip() for idx in indices.split(',')]
        logger.info(f"Target indices: {', '.join(parsed_indices)}")
    else:
        logger.info("Target: All indices")
    
    # Determine region for AWS auth
    if use_aws_auth and not region:
        region = config['source']['region']
        logger.info(f"Using region from config: {region}")
    
    log_separator()
    
    try:
        # Create session
        logger.debug("Creating OpenSearch session")
        session = create_snapshot_session(
            domain_url, 
            username, 
            password, 
            use_aws_auth, 
            region
        )
        
        # Test connection first
        logger.debug("Testing OpenSearch connection...")
        if not test_snapshot_connection(session, domain_url, use_aws_auth, region, dry_run):
            logger.error("Cannot connect to OpenSearch cluster")
            logger.error("Please check your credentials and domain URL")
            return False
        
        # Check snapshot status (unless forced)
        if not force:
            logger.info("=== Checking Snapshot Status ===")
            can_proceed, running_snapshots = check_snapshot_status(
                session, domain_url, use_aws_auth, region, dry_run
            )
            
            if not can_proceed and not dry_run:
                logger.error("Cannot create snapshot while other snapshots are in progress")
                logger.error("Use --force to override this check (not recommended)")
                return False
            
            log_separator()
        else:
            logger.warning("Skipping snapshot status check (--force enabled)")
            log_separator()
        
        # Create snapshot asynchronously
        logger.info("=== Creating Snapshot ===")
        success, task_id = create_snapshot_async(
            session, domain_url, repository_name, snapshot_name, 
            parsed_indices, use_aws_auth, region, dry_run
        )
        
        if not success and not dry_run:
            logger.error("Failed to create snapshot")
            return False
        
        log_separator()
        
        # Wait for completion if requested
        if wait_for_completion and not dry_run:
            logger.info("=== Waiting for Completion ===")
            
            if task_id and task_id != "dry-run-task-id":
                # Use task-based monitoring (preferred method)
                success, snapshot_info = wait_for_task_completion(
                    session, domain_url, task_id, repository_name, snapshot_name,
                    timeout_minutes, use_aws_auth, region
                )
            else:
                # Fallback: check final status
                logger.info("No task ID available, checking final snapshot status")
                time.sleep(5)  # Give it a moment
                success, snapshot_data = get_snapshot_info(
                    session, domain_url, repository_name, snapshot_name,
                    use_aws_auth, region, dry_run
                )
                
                if success and 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                    snapshot = snapshot_data['snapshots'][0]
                    state = snapshot.get('state', 'UNKNOWN')
                    if state == 'SUCCESS':
                        logger.info("Snapshot completed successfully!")
                    elif state in ['IN_PROGRESS', 'STARTED']:
                        logger.info("Snapshot is still in progress")
                    else:
                        logger.warning(f"Snapshot state: {state}")
            
            if success:
                logger.info("Snapshot operation completed!")
            else:
                logger.error("Snapshot did not complete successfully")
                return False
            
            log_separator()
        
        # Get final snapshot info
        logger.info("=== Snapshot Information ===")
        success, snapshot_data = get_snapshot_info(
            session, domain_url, repository_name, snapshot_name,
            use_aws_auth, region, dry_run
        )
        
        if success and not dry_run:
            if 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                snapshot = snapshot_data['snapshots'][0]
                state = snapshot.get('state', 'UNKNOWN')
                start_time = snapshot.get('start_time', 'Unknown')
                duration = snapshot.get('duration_in_millis', 0) / 1000 if snapshot.get('duration_in_millis') else 0
                
                logger.info(f"Repository: {repository_name}")
                logger.info(f"Snapshot: {snapshot_name}")
                logger.info(f"State: {state}")
                logger.info(f"Start time: {start_time}")
                if duration > 0:
                    logger.info(f"Duration: {duration:.1f} seconds")
                
                if 'indices' in snapshot:
                    logger.info(f"Indices: {', '.join(snapshot['indices'])}")
        
        log_separator()
        
        if dry_run:
            logger.info("DRY RUN COMPLETE - No actual changes were made")
        else:
            logger.info("Snapshot operation completed successfully!")
            logger.info(f"Repository: {repository_name}")
            logger.info(f"Snapshot: {snapshot_name}")
            
            if not wait_for_completion:
                logger.info("")
                logger.info("To check snapshot status:")
                logger.info(f"curl -XGET '{domain_url}/_snapshot/{repository_name}/{snapshot_name}'")
                logger.info("")
                logger.info("To list all snapshots:")
                logger.info(f"curl -XGET '{domain_url}/_snapshot/{repository_name}/_all?pretty'")
        
        return True
        
    except Exception as e:
        logger.error(f"Unexpected error during snapshot: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def register_snapshot_repository(config, dry_run=False):
    """Register snapshot repository using AWS IAM authentication"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Registering Snapshot Repository ===")
    
    if dry_run:
        repo_name = config.get('repository_name', 'automated-snapshots')
        logger.info(f"[DRY RUN] Would register snapshot repository: {repo_name}")
        logger.debug(f"[DRY RUN] Repository would use S3 bucket: {config['s3_bucket']['name']}")
        logger.debug(f"[DRY RUN] Repository would use IAM role: {config['source']['role_arn']}")
        return True
    
    try:
        # Validate prerequisites first
        logger.debug("Validating repository prerequisites...")
        if not validate_repository_prerequisites(config):
            logger.warning("Repository prerequisites validation failed, but continuing...")
        
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
        repo_name = config.get('repository_name', 'automated-snapshots')
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
        logger.debug(f"Request payload: {payload}")
        
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
            
            # Verify the registration
            logger.debug("Verifying repository registration...")
            if verify_repository_registration(config, repo_name):
                logger.info("Repository registration verified successfully")
                return True
            else:
                logger.warning("Repository registration could not be verified")
                return True  # Still return True since the registration request succeeded
        else:
            logger.error(f"Failed to register repository: {response.status_code}")
            logger.error(f"Error response: {response.text}")
            
            # Try to parse error details
            try:
                error_data = response.json()
                if 'error' in error_data:
                    error_info = error_data['error']
                    if isinstance(error_info, dict):
                        error_type = error_info.get('type', 'unknown')
                        error_reason = error_info.get('reason', 'unknown')
                        logger.error(f"Error type: {error_type}")
                        logger.error(f"Error reason: {error_reason}")
                        
                        # Common error scenarios and suggestions
                        if 'role' in error_reason.lower() or 'assume' in error_reason.lower():
                            logger.error("SUGGESTION: This might be an IAM role permission issue")
                            logger.error("- Check that the IAM role has proper trust policy for OpenSearch service")
                            logger.error("- Verify the role ARN is correct")
                            logger.error("- Ensure the role has S3 permissions for the bucket")
                        elif 'bucket' in error_reason.lower() or 's3' in error_reason.lower():
                            logger.error("SUGGESTION: This might be an S3 bucket access issue")
                            logger.error("- Check that the S3 bucket exists and is accessible")
                            logger.error("- Verify bucket policies allow OpenSearch service access")
                            logger.error("- Ensure bucket is in the correct region")
                        elif 'region' in error_reason.lower():
                            logger.error("SUGGESTION: This might be a region mismatch issue")
                            logger.error("- Check that the S3 bucket region matches the OpenSearch domain region")
                        elif 'security' in error_reason.lower() or 'auth' in error_reason.lower():
                            logger.error("SUGGESTION: This might be an authentication issue")
                            logger.error("- Check that OpenSearch security is properly configured")
                            logger.error("- Verify the current user has snapshot management permissions")
                        else:
                            logger.error("SUGGESTION: Check OpenSearch logs for more details")
                    else:
                        logger.error(f"Error details: {error_info}")
            except:
                logger.error("Could not parse error response as JSON")
                logger.error("SUGGESTION: Enable debug logging (--debug) for more details")
            
            return False
            
    except Exception as e:
        logger.error(f"Exception registering snapshot repository: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Unified OpenSearch snapshot setup and management script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SETUP MODE Examples:
  # Complete setup (creates IAM resources, configures security, registers repository, and takes snapshot)
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword
  
  # Setup with custom snapshot name and wait for completion
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword \\
    --snapshot-name "initial-backup" --wait
  
  # Setup only (skip snapshot)
  python opensearch_snapshot_setup.py \\
    --src-domain "arn:aws:es:us-east-1:111:domain/source" \\
    --dest-domain "arn:aws:es:us-west-2:222:domain/dest" \\
    --username admin --password mypassword \\
    --skip-snapshot

SNAPSHOT MODE Examples:
  # Take snapshot using existing config
  python opensearch_snapshot_setup.py --snapshot-only \\
    --username admin --password mypassword
  
  # Take snapshot with custom name and wait for completion
  python opensearch_snapshot_setup.py --snapshot-only \\
    --username admin --password mypassword \\
    --snapshot-name "backup-before-upgrade" --wait
  
  # Take snapshot of specific indices
  python opensearch_snapshot_setup.py --snapshot-only \\
    --username admin --password mypassword \\
    --indices "index1,index2,index3"
        """
    )
    
    # Mode selection
    parser.add_argument('--snapshot-only', action='store_true',
                       help='Skip setup and only take snapshot using existing config')
    
    # Setup mode arguments
    parser.add_argument('--src-domain',
                       help='Source OpenSearch domain ARN (required for setup mode)')
    parser.add_argument('--dest-domain',
                       help='Destination OpenSearch domain ARN (required for setup mode)')
    parser.add_argument('--s3-bucket',
                       help='S3 bucket ARN (if not provided, will create/reuse empty bucket)')
    parser.add_argument('--s3',
                       help='Alias for --s3-bucket (S3 bucket ARN)')
    parser.add_argument('--role-name', default='OpenSearchSnapshotRole',
                       help='IAM role name prefix (default: OpenSearchSnapshotRole)')
    parser.add_argument('--user-name', default='OpenSearchSnapshotUser',
                       help='IAM user name prefix (default: OpenSearchSnapshotUser)')
    parser.add_argument('--force-new-bucket', action='store_true',
                       help='Force creation of new S3 bucket')
    parser.add_argument('--skip-security', action='store_true',
                       help='Skip OpenSearch security configuration')
    parser.add_argument('--skip-repository', action='store_true',
                       help='Skip snapshot repository registration')
    
    # Snapshot arguments
    parser.add_argument('--skip-snapshot', action='store_true',
                       help='Skip taking snapshot after setup completion (default: take snapshot)')
    parser.add_argument('--snapshot-name',
                       help='Snapshot name (auto-generated if not provided)')
    parser.add_argument('--indices',
                       help='Comma-separated list of indices to snapshot (all indices if not specified)')
    parser.add_argument('--wait', action='store_true',
                       help='Wait for snapshot to complete')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Timeout in minutes when waiting (default: 60)')
    parser.add_argument('--force', action='store_true',
                       help='Skip snapshot status check and create anyway')
    
    # Authentication and common arguments
    parser.add_argument('--username',
                       help='OpenSearch admin username (required for security config and snapshots)')
    parser.add_argument('--password',
                       help='OpenSearch admin password (required for security config and snapshots)')
    parser.add_argument('--use-aws-auth', action='store_true',
                       help='Use AWS IAM authentication instead of basic auth for snapshots')
    parser.add_argument('--region',
                       help='AWS region (required when using AWS auth for snapshots)')
    
    # Common arguments
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
    
    # Handle snapshot-only mode
    if args.snapshot_only:
        if args.dry_run:
            logger.info("=== DRY RUN MODE - Snapshot Only ===")
            log_separator()
        else:
            logger.info("=== OpenSearch Manual Snapshot ===")
            log_separator()
        
        # Load existing configuration
        config = load_config_for_snapshot()
        if not config:
            logger.error("Cannot proceed without configuration file")
            logger.error("Run setup mode first to create the configuration")
            return
        
        # Validate authentication for snapshot
        if args.use_aws_auth:
            if not args.region:
                # Try to get region from config
                args.region = config.get('source', {}).get('region')
                if not args.region:
                    logger.error("--region is required when using AWS authentication")
                    return
            logger.info("Using AWS IAM authentication")
        else:
            if not args.username or not args.password:
                logger.error("--username and --password are required for basic authentication")
                return
            logger.info("Using basic authentication")
        
        # Take snapshot
        success = take_manual_snapshot(
            config=config,
            username=args.username,
            password=args.password,
            snapshot_name=args.snapshot_name,
            indices=args.indices,
            use_aws_auth=args.use_aws_auth,
            region=args.region,
            wait_for_completion=args.wait,
            timeout_minutes=args.timeout,
            force=args.force,
            dry_run=args.dry_run
        )
        
        if success:
            logger.info("Snapshot operation completed successfully!")
        else:
            logger.error("Snapshot operation failed!")
            sys.exit(1)
        
        return
    
    # Setup mode validation
    if not args.src_domain or not args.dest_domain:
        logger.error("--src-domain and --dest-domain are required for setup mode")
        logger.error("Use --snapshot-only for snapshot-only operations")
        return
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - Setup Mode ===")
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
    
    # Generate unique repository name
    repository_name = generate_repository_name()
    logger.info(f"Generated repository name: {repository_name}")
    
    # Create configuration
    config = {
        'repository_name': repository_name,
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
                logger.info(f"[DRY RUN] Would register snapshot repository: {repository_name}")
                log_separator()
            else:
                repo_success = register_snapshot_repository(config, args.dry_run)
                log_separator()
    
    # Take snapshot by default (unless skipped)
    if not args.skip_snapshot:
        if not args.username or not args.password:
            logger.warning("Cannot take snapshot without OpenSearch credentials")
            logger.warning("Use --username and --password to enable snapshot creation")
        else:
            log_separator()
            logger.info("=== Taking Initial Snapshot ===")
            
            # Take snapshot using the setup configuration
            snapshot_success = take_manual_snapshot(
                config=config,
                username=args.username,
                password=args.password,
                snapshot_name=args.snapshot_name,
                indices=args.indices,
                use_aws_auth=args.use_aws_auth,
                region=args.region,
                wait_for_completion=args.wait,
                timeout_minutes=args.timeout,
                force=args.force,
                dry_run=args.dry_run
            )
            
            if not snapshot_success and not args.dry_run:
                logger.warning("Setup completed but snapshot failed")
            
            log_separator()
    
    # Summary
    logger.info("=== Setup Summary ===")
    logger.info(f"S3 bucket: {s3_info['name']}")
    logger.info(f"Repository: {repository_name}")
    logger.info(f"Source role: {source_role_name}")
    logger.info(f"Source user: {source_user_name}")
    logger.info(f"Destination role: {dest_role_name}")
    logger.info(f"Destination user: {dest_user_name}")
    
    if not args.skip_snapshot:
        logger.info(f"Initial snapshot: {'Taken' if not args.skip_snapshot else 'Skipped'}")
    
    log_separator()
    
    if args.dry_run:
        logger.info("DRY RUN COMPLETE - No actual changes were made")
    else:
        logger.info("Setup completed successfully!")
        
        if args.skip_snapshot:
            logger.info("")
            logger.info("To take a snapshot now, run:")
            logger.info(f"python {sys.argv[0]} --snapshot-only --username <username> --password <password>")

if __name__ == "__main__":
    main()