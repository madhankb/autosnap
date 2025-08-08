#!/usr/bin/env python3
"""
Script to delete all resources created by opensearch_snapshot_setup.py
Reads from opensearch_snapshot_config.json and removes all created resources including:
- IAM roles and users
- S3 bucket and contents
- OpenSearch role mappings
- Snapshot repositories

Usage:
  python delete_all.py [--config-file CONFIG_FILE] [--dry-run]
"""

import json
import boto3
import requests
from botocore.exceptions import ClientError
import sys
import argparse
import logging
from datetime import datetime
from urllib.parse import urljoin
import urllib3
from requests.auth import HTTPBasicAuth

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

def load_config(config_file):
    """Load configuration from output file"""
    logger = logging.getLogger(__name__)
    try:
        logger.debug(f"Loading configuration from: {config_file}")
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.debug("Configuration loaded successfully")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_file} not found")
        logger.error("Make sure you have run opensearch_snapshot_setup.py first")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {config_file}: {e}")
        sys.exit(1)

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

def delete_snapshot_repository(config, username, password, dry_run=False):
    """Delete snapshot repository from OpenSearch"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Deleting Snapshot Repository ===")
    
    if dry_run:
        logger.info("[DRY RUN] Would delete snapshot repository: automated-snapshots")
        return True
    
    if not username or not password:
        logger.warning("Cannot delete repository without OpenSearch credentials")
        logger.warning("Repository may still exist and need manual deletion")
        return True
    
    try:
        source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
        if not source_endpoint:
            logger.error("Could not get source domain endpoint")
            return False
        
        logger.debug(f"Source endpoint: {source_endpoint}")
        session = create_security_session(source_endpoint, username, password)
        
        repo_name = "automated-snapshots"
        url = urljoin(source_endpoint, f"_snapshot/{repo_name}")
        
        logger.debug(f"Deleting repository at: {url}")
        response = session.delete(url, verify=False)
        
        if response.status_code in [200, 404]:
            if response.status_code == 404:
                logger.info(f"Snapshot repository {repo_name} does not exist (already deleted)")
            else:
                logger.info(f"Successfully deleted snapshot repository: {repo_name}")
            return True
        else:
            logger.error(f"Failed to delete repository: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception deleting snapshot repository: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def get_current_user_arn(dry_run=False):
    """Get current AWS user ARN"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug("[DRY RUN] Would get current user ARN")
        return "arn:aws:iam::123456789012:user/example-user"
    
    try:
        sts_client = boto3.client('sts')
        response = sts_client.get_caller_identity()
        user_arn = response['Arn']
        logger.debug(f"Current AWS user ARN: {user_arn}")
        return user_arn
    except ClientError as e:
        logger.error(f"Error getting current user ARN: {e}")
        logger.debug(f"STS error details: {str(e)}", exc_info=True)
        return None

def check_and_clean_role_mapping(session, endpoint, role_name, arns_to_check, dry_run=False):
    """Check if any of the provided ARNs exist in the role mapping and remove them"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would check and clean role mapping: {role_name}")
        return True
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        logger.debug(f"Checking role mapping: {url}")
        
        response = session.get(url, verify=False)
        
        if response.status_code == 404:
            logger.debug(f"Role mapping {role_name} does not exist")
            return True
        elif response.status_code != 200:
            logger.warning(f"Could not check role mapping {role_name}: {response.status_code}")
            return False
        
        current_mapping = response.json().get(role_name, {})
        users = current_mapping.get('users', [])
        backend_roles = current_mapping.get('backend_roles', [])
        
        # Check which ARNs from our list are present
        arns_to_remove_users = []
        arns_to_remove_roles = []
        
        for arn in arns_to_check:
            if arn and arn in users:
                arns_to_remove_users.append(arn)
                logger.debug(f"Found user ARN to remove: {arn}")
            if arn and arn in backend_roles:
                arns_to_remove_roles.append(arn)
                logger.debug(f"Found backend role ARN to remove: {arn}")
        
        # Remove found ARNs
        if arns_to_remove_users or arns_to_remove_roles:
            for arn in arns_to_remove_users:
                users.remove(arn)
                logger.info(f"Removed user {arn} from {role_name}")
            
            for arn in arns_to_remove_roles:
                backend_roles.remove(arn)
                logger.info(f"Removed backend role {arn} from {role_name}")
            
            # Update the mapping
            updated_mapping = {
                "backend_roles": backend_roles,
                "users": users,
                "description": current_mapping.get('description', '')
            }
            
            response = session.put(url, json=updated_mapping, verify=False)
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully cleaned role mapping: {role_name}")
                return True
            else:
                logger.error(f"Failed to update role mapping: {response.status_code}")
                return False
        else:
            logger.debug(f"No ARNs from config found in {role_name} mapping")
            return True
            
    except Exception as e:
        logger.error(f"Exception checking role mapping {role_name}: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def revert_role_mapping(session, endpoint, role_name, user_arn_to_remove, role_arn_to_remove, dry_run=False):
    """Remove specific user/role from OpenSearch role mapping"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would remove mappings from role: {role_name}")
        if user_arn_to_remove:
            logger.debug(f"[DRY RUN] Would remove user: {user_arn_to_remove}")
        if role_arn_to_remove:
            logger.debug(f"[DRY RUN] Would remove backend role: {role_arn_to_remove}")
        return True
    
    try:
        # Get current role mapping
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        logger.debug(f"Getting current role mapping from: {url}")
        
        response = session.get(url, verify=False)
        
        if response.status_code == 404:
            logger.info(f"Role mapping {role_name} does not exist")
            return True
        elif response.status_code != 200:
            logger.error(f"Failed to get role mapping: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
        
        current_mapping = response.json().get(role_name, {})
        logger.debug(f"Current mapping for {role_name}: {json.dumps(current_mapping, indent=2)}")
        
        # Remove our entries from the mapping
        users = current_mapping.get('users', [])
        backend_roles = current_mapping.get('backend_roles', [])
        
        changes_made = False
        
        # Remove user ARN if present
        if user_arn_to_remove and user_arn_to_remove in users:
            users.remove(user_arn_to_remove)
            logger.info(f"Removed user {user_arn_to_remove} from {role_name}")
            changes_made = True
        elif user_arn_to_remove:
            logger.debug(f"User {user_arn_to_remove} not found in {role_name} mapping")
        
        # Remove role ARN if present
        if role_arn_to_remove and role_arn_to_remove in backend_roles:
            backend_roles.remove(role_arn_to_remove)
            logger.info(f"Removed backend role {role_arn_to_remove} from {role_name}")
            changes_made = True
        elif role_arn_to_remove:
            logger.debug(f"Backend role {role_arn_to_remove} not found in {role_name} mapping")
        
        # If no changes were made, we're done
        if not changes_made:
            logger.info(f"No mappings to remove from {role_name}")
            return True
        
        # Update the mapping
        updated_mapping = {
            "backend_roles": backend_roles,
            "users": users,
            "description": current_mapping.get('description', '')
        }
        
        logger.debug(f"Updated mapping: {json.dumps(updated_mapping, indent=2)}")
        
        response = session.put(url, json=updated_mapping, verify=False)
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully updated role mapping for: {role_name}")
            return True
        else:
            logger.error(f"Failed to update role mapping: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception updating role mapping: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def revert_opensearch_security(config, username, password, dry_run=False):
    """Revert OpenSearch security mappings"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Reverting OpenSearch Security Mappings ===")
    
    if not username or not password:
        logger.warning("Cannot revert security mappings without OpenSearch credentials")
        logger.warning("Role mappings may still exist and need manual cleanup")
        return True
    
    if dry_run:
        logger.info("[DRY RUN] Would revert OpenSearch security mappings")
        logger.info("[DRY RUN] Would remove current user from all_access role")
        logger.info("[DRY RUN] Would remove IAM role/user from manage_snapshots role")
        return True
    
    try:
        source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
        if not source_endpoint:
            logger.error("Could not get source domain endpoint")
            return False
        
        logger.debug(f"Source endpoint: {source_endpoint}")
        session = create_security_session(source_endpoint, username, password)
        
        # Test connection
        test_url = urljoin(source_endpoint, "_plugins/_security/api/account")
        test_response = session.get(test_url, verify=False)
        
        if test_response.status_code != 200:
            logger.error(f"Failed to connect to OpenSearch Security API: {test_response.status_code}")
            return False
        
        success_count = 0
        
        # Collect all ARNs that might be mapped to OpenSearch roles
        current_user_arn = get_current_user_arn(dry_run)
        source_role_arn = config.get('source', {}).get('role_arn')
        source_user_arn = config.get('source', {}).get('user_info', {}).get('UserArn')
        dest_role_arn = config.get('destination', {}).get('role_arn')
        dest_user_arn = config.get('destination', {}).get('user_info', {}).get('UserArn')
        
        logger.debug(f"ARNs to check for cleanup:")
        logger.debug(f"  Current user: {current_user_arn}")
        logger.debug(f"  Source role: {source_role_arn}")
        logger.debug(f"  Source user: {source_user_arn}")
        logger.debug(f"  Dest role: {dest_role_arn}")
        logger.debug(f"  Dest user: {dest_user_arn}")
        
        # Clean up all_access role mapping (remove current user)
        if current_user_arn:
            logger.debug("Cleaning up all_access role mapping")
            if check_and_clean_role_mapping(session, source_endpoint, "all_access", [current_user_arn], dry_run):
                success_count += 1
                logger.info("Cleaned up all_access role mapping")
        else:
            logger.warning("Could not get current user ARN, skipping all_access role mapping cleanup")
        
        # Clean up manage_snapshots role mapping (remove all related ARNs)
        arns_to_check = [arn for arn in [source_role_arn, source_user_arn, dest_role_arn, dest_user_arn] if arn]
        
        if arns_to_check:
            logger.debug(f"Cleaning up manage_snapshots role mapping for ARNs: {arns_to_check}")
            if check_and_clean_role_mapping(session, source_endpoint, "manage_snapshots", arns_to_check, dry_run):
                success_count += 1
                logger.info("Cleaned up manage_snapshots role mapping")
        else:
            logger.warning("No IAM ARNs found in config, skipping manage_snapshots role mapping cleanup")
        
        return success_count >= 1
        
    except Exception as e:
        logger.error(f"Exception reverting OpenSearch security: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def delete_s3_bucket(s3_client, bucket_name, dry_run=False):
    """Delete S3 bucket and all its contents"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete S3 bucket: {bucket_name}")
        logger.debug("[DRY RUN] Would delete all objects and versions")
        return True
    
    try:
        logger.info(f"Deleting S3 bucket: {bucket_name}")
        
        # First, delete all objects in the bucket
        logger.debug(f"Deleting all objects in bucket: {bucket_name}")
        try:
            # List and delete all objects
            paginator = s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=bucket_name)
            
            for page in pages:
                if 'Contents' in page:
                    objects = [{'Key': obj['Key']} for obj in page['Contents']]
                    if objects:
                        s3_client.delete_objects(
                            Bucket=bucket_name,
                            Delete={'Objects': objects}
                        )
                        logger.debug(f"Deleted {len(objects)} objects from bucket")
            
            # Delete all object versions (if versioning is enabled)
            version_paginator = s3_client.get_paginator('list_object_versions')
            version_pages = version_paginator.paginate(Bucket=bucket_name)
            
            for page in version_pages:
                versions = []
                if 'Versions' in page:
                    versions.extend([{'Key': v['Key'], 'VersionId': v['VersionId']} for v in page['Versions']])
                if 'DeleteMarkers' in page:
                    versions.extend([{'Key': d['Key'], 'VersionId': d['VersionId']} for d in page['DeleteMarkers']])
                
                if versions:
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={'Objects': versions}
                    )
                    logger.debug(f"Deleted {len(versions)} object versions from bucket")
        
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchBucket':
                logger.warning(f"Error deleting objects from bucket {bucket_name}: {e}")
        
        # Now delete the bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        logger.info(f"Successfully deleted S3 bucket: {bucket_name}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            logger.warning(f"S3 bucket {bucket_name} does not exist")
            return True
        else:
            logger.error(f"Error deleting S3 bucket {bucket_name}: {e}")
            logger.debug(f"S3 error details: {str(e)}", exc_info=True)
            return False

def delete_iam_user(iam_client, user_name, dry_run=False):
    """Delete IAM user and all attached policies and access keys"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete IAM user: {user_name}")
        logger.debug("[DRY RUN] Would delete access keys and policies")
        return True
    
    try:
        logger.info(f"Deleting IAM user: {user_name}")
        
        # Delete access keys
        try:
            keys_response = iam_client.list_access_keys(UserName=user_name)
            for key in keys_response['AccessKeyMetadata']:
                logger.debug(f"Deleting access key: {key['AccessKeyId']}")
                iam_client.delete_access_key(
                    UserName=user_name,
                    AccessKeyId=key['AccessKeyId']
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.warning(f"Error deleting access keys for user {user_name}: {e}")
        
        # Delete inline policies
        try:
            policies_response = iam_client.list_user_policies(UserName=user_name)
            for policy_name in policies_response['PolicyNames']:
                logger.debug(f"Deleting user policy: {policy_name}")
                iam_client.delete_user_policy(
                    UserName=user_name,
                    PolicyName=policy_name
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.warning(f"Error deleting policies for user {user_name}: {e}")
        
        # Delete attached managed policies
        try:
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached_policies['AttachedPolicies']:
                logger.debug(f"Detaching managed policy: {policy['PolicyName']}")
                iam_client.detach_user_policy(
                    UserName=user_name,
                    PolicyArn=policy['PolicyArn']
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.warning(f"Error detaching managed policies for user {user_name}: {e}")
        
        # Delete the user
        iam_client.delete_user(UserName=user_name)
        logger.info(f"Successfully deleted IAM user: {user_name}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            logger.warning(f"IAM user {user_name} does not exist")
            return True
        else:
            logger.error(f"Error deleting IAM user {user_name}: {e}")
            logger.debug(f"IAM user error details: {str(e)}", exc_info=True)
            return False

def delete_iam_role(iam_client, role_name, dry_run=False):
    """Delete IAM role and all attached policies"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete IAM role: {role_name}")
        logger.debug("[DRY RUN] Would delete inline and managed policies")
        return True
    
    try:
        logger.info(f"Deleting IAM role: {role_name}")
        
        # Delete inline policies
        try:
            policies_response = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policies_response['PolicyNames']:
                logger.debug(f"Deleting role policy: {policy_name}")
                iam_client.delete_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.warning(f"Error deleting policies for role {role_name}: {e}")
        
        # Delete attached managed policies
        try:
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies['AttachedPolicies']:
                logger.debug(f"Detaching managed policy: {policy['PolicyName']}")
                iam_client.detach_role_policy(
                    RoleName=role_name,
                    PolicyArn=policy['PolicyArn']
                )
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.warning(f"Error detaching managed policies for role {role_name}: {e}")
        
        # Delete the role
        iam_client.delete_role(RoleName=role_name)
        logger.info(f"Successfully deleted IAM role: {role_name}")
        return True
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            logger.warning(f"IAM role {role_name} does not exist")
            return True
        else:
            logger.error(f"Error deleting IAM role {role_name}: {e}")
            logger.debug(f"IAM role error details: {str(e)}", exc_info=True)
            return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Delete all resources created by opensearch_snapshot_setup.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Delete using default config file
  python delete_all.py
  
  # Use custom config file
  python delete_all.py --config-file my_config.json
  
  # Dry run to see what would be deleted
  python delete_all.py --dry-run
  
  # Skip S3 bucket deletion
  python delete_all.py --skip-s3
  
  # Skip OpenSearch operations (security and repository)
  python delete_all.py --skip-opensearch
  
  # Debug mode for detailed logging
  python delete_all.py --debug
        """
    )
    
    parser.add_argument(
        '--config-file',
        default='opensearch_snapshot_config.json',
        help='Configuration file with resource details (default: opensearch_snapshot_config.json)'
    )
    
    parser.add_argument(
        '--username',
        help='OpenSearch admin username (required for security and repository cleanup)'
    )
    
    parser.add_argument(
        '--password',
        help='OpenSearch admin password (required for security and repository cleanup)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be deleted without actually deleting anything'
    )
    
    parser.add_argument(
        '--skip-s3',
        action='store_true',
        help='Skip S3 bucket deletion (useful if bucket contains other data)'
    )
    
    parser.add_argument(
        '--skip-opensearch',
        action='store_true',
        help='Skip OpenSearch operations (security mappings and repository deletion)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging for detailed error messages'
    )
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    logger = setup_logging(debug=args.debug)
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No resources will be deleted ===")
        log_separator()
    else:
        logger.info("=== Starting OpenSearch Snapshot Resources Deletion ===")
        log_separator()
    
    # Load configuration
    logger.info(f"Loading configuration from: {args.config_file}")
    config = load_config(args.config_file)
    
    # Display what will be deleted
    logger.info("Resources to be deleted:")
    if 's3_bucket' in config and not args.skip_s3:
        logger.info(f"  S3 Bucket: {config['s3_bucket']['name']}")
    if 'source' in config:
        logger.info(f"  Source IAM Role: {config['source']['role_name']}")
        logger.info(f"  Source IAM User: {config['source']['user_name']}")
    if 'destination' in config:
        logger.info(f"  Destination IAM Role: {config['destination']['role_name']}")
        logger.info(f"  Destination IAM User: {config['destination']['user_name']}")
    if not args.skip_opensearch:
        logger.info(f"  OpenSearch Security Mappings (all_access, manage_snapshots)")
        logger.info(f"  Snapshot Repository: automated-snapshots")
    
    log_separator()
    
    if not args.dry_run:
        response = input("Are you sure you want to delete these resources? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            logger.info("Deletion cancelled by user")
            return
        log_separator()
    
    success_count = 0
    total_count = 0
    
    # Delete OpenSearch resources first (repository and security mappings)
    # This is done first and independently of IAM resource state
    if not args.skip_opensearch:
        total_count += 2
        
        # Delete snapshot repository
        logger.debug("Attempting to delete snapshot repository (independent of IAM resource state)")
        if delete_snapshot_repository(config, args.username, args.password, args.dry_run):
            success_count += 1
        log_separator()
        
        # Revert security mappings (works even if IAM resources are already deleted)
        logger.debug("Attempting to revert security mappings (independent of IAM resource state)")
        if revert_opensearch_security(config, args.username, args.password, args.dry_run):
            success_count += 1
        log_separator()
    
    # Delete S3 bucket (if not skipped)
    if 's3_bucket' in config and not args.skip_s3:
        total_count += 1
        logger.info("=== Deleting S3 Bucket ===")
        try:
            s3_client = boto3.client('s3', region_name=config['s3_bucket']['region'])
            if delete_s3_bucket(s3_client, config['s3_bucket']['name'], args.dry_run):
                success_count += 1
        except Exception as e:
            logger.error(f"Error processing S3 bucket: {e}")
            logger.debug(f"S3 exception details: {str(e)}", exc_info=True)
        log_separator()
    
    # Delete source account resources
    if 'source' in config:
        total_count += 2
        logger.info("=== Deleting SOURCE Account Resources ===")
        try:
            source_iam = boto3.client('iam', region_name=config['source']['region'])
            
            # Delete source user
            if delete_iam_user(source_iam, config['source']['user_name'], args.dry_run):
                success_count += 1
            
            # Delete source role
            if delete_iam_role(source_iam, config['source']['role_name'], args.dry_run):
                success_count += 1
                
        except Exception as e:
            logger.error(f"Error processing source account resources: {e}")
            logger.debug(f"Source account exception details: {str(e)}", exc_info=True)
        log_separator()
    
    # Delete destination account resources
    if 'destination' in config:
        total_count += 2
        logger.info("=== Deleting DESTINATION Account Resources ===")
        try:
            dest_iam = boto3.client('iam', region_name=config['destination']['region'])
            
            # Delete destination user
            if delete_iam_user(dest_iam, config['destination']['user_name'], args.dry_run):
                success_count += 1
            
            # Delete destination role
            if delete_iam_role(dest_iam, config['destination']['role_name'], args.dry_run):
                success_count += 1
                
        except Exception as e:
            logger.error(f"Error processing destination account resources: {e}")
            logger.debug(f"Destination account exception details: {str(e)}", exc_info=True)
        log_separator()
    
    # Summary
    logger.info("=== Deletion Summary ===")
    if args.dry_run:
        logger.info(f"DRY RUN COMPLETE: Would have processed {total_count} resources")
    else:
        logger.info(f"Deletion completed: {success_count}/{total_count} resources processed successfully")
        
        if success_count == total_count:
            logger.info("All resources deleted successfully!")
            
            # Optionally delete the config file
            delete_config = input(f"\nDelete configuration file {args.config_file}? (yes/no): ")
            if delete_config.lower() in ['yes', 'y']:
                try:
                    import os
                    os.remove(args.config_file)
                    logger.info(f"Deleted configuration file: {args.config_file}")
                except Exception as e:
                    logger.warning(f"Could not delete configuration file: {e}")
        else:
            logger.warning("Some resources could not be deleted. Check the logs above for details.")
            logger.warning("You may need to manually clean up remaining resources.")

if __name__ == "__main__":
    main()