#!/usr/bin/env python3
"""
Script to configure OpenSearch security role mappings for snapshot operations
Maps IAM roles and users to OpenSearch internal roles using the Security API

Usage:
  python configure_opensearch_security.py [--config-file CONFIG_FILE] [--dry-run]
"""

import json
import requests
import sys
import argparse
import logging
from datetime import datetime
from urllib.parse import urljoin
import urllib3
from requests.auth import HTTPBasicAuth
import boto3
from botocore.exceptions import ClientError
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from urllib.parse import urlparse

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

def load_config(config_file):
    """Load configuration from output file"""
    logger = logging.getLogger(__name__)
    
    try:
        logger.debug(f"Loading configuration from: {config_file}")
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.debug(f"Configuration loaded successfully")
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file {config_file} not found")
        logger.error("Make sure you have run create_iam_resources.py first")
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {config_file}: {e}")
        sys.exit(1)

def get_opensearch_endpoint(domain_arn):
    """Extract OpenSearch endpoint from domain ARN"""
    logger = logging.getLogger(__name__)
    
    # Parse ARN to get region and domain name
    # ARN format: arn:aws:es:region:account-id:domain/domain-name
    parts = domain_arn.split(':')
    region = parts[3]
    domain_name = parts[5].split('/')[1]
    
    logger.debug(f"Parsing domain ARN: {domain_arn}")
    logger.debug(f"Extracted region: {region}, domain: {domain_name}")
    
    # Get domain endpoint using AWS API
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
    
    # Common headers
    session.headers.update({
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    })
    
    return session

def test_connection(session, endpoint, dry_run=False):
    """Test connection to OpenSearch Security API"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would test connection to OpenSearch")
        return True
    
    try:
        url = urljoin(endpoint, "_plugins/_security/api/account")
        logger.debug(f"Testing connection to: {url}")
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            logger.info("Successfully connected to OpenSearch Security API")
            logger.debug(f"Connection response: {response.text}")
            return True
        else:
            logger.error(f"Failed to connect to OpenSearch Security API: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception testing connection: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def list_all_roles(session, endpoint, dry_run=False):
    """List all available roles in OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug("[DRY RUN] Would list all roles")
        return True
    
    try:
        url = urljoin(endpoint, "_plugins/_security/api/roles")
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            roles = response.json()
            logger.debug("Available roles in OpenSearch:")
            for role_name in roles.keys():
                logger.debug(f"  - {role_name}")
            return True
        else:
            logger.error(f"Error listing roles: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception listing roles: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def check_role_exists(session, endpoint, role_name, dry_run=False):
    """Check if the role exists in OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug(f"[DRY RUN] Would check if role exists: {role_name}")
        return True
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/roles/{role_name}")
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            logger.debug(f"Role {role_name} exists in OpenSearch")
            return True
        elif response.status_code == 404:
            logger.debug(f"Role {role_name} does not exist via API (expected for built-in roles)")
            list_all_roles(session, endpoint, dry_run)
            return True  # Built-in roles may not be visible via API but still exist
        else:
            logger.error(f"Error checking role: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception checking role: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def get_current_role_mapping(session, endpoint, role_name, dry_run=False):
    """Get current role mapping from OpenSearch"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.debug(f"[DRY RUN] Would get role mapping for: {role_name}")
        return {}
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        logger.debug(f"Getting current role mapping from: {url}")
        
        response = session.get(url, verify=False)
        
        if response.status_code == 200:
            mapping = response.json().get(role_name, {})
            logger.debug(f"Current mapping for {role_name}: {json.dumps(mapping, indent=2)}")
            return mapping
        elif response.status_code == 404:
            logger.debug(f"Role mapping {role_name} does not exist yet")
            return {}
        else:
            logger.error(f"Error getting role mapping: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return None
            
    except Exception as e:
        logger.error(f"Exception getting role mapping: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return None

def update_role_mapping(session, endpoint, role_name, mapping_config, dry_run=False):
    """Update role mapping in OpenSearch using correct API format"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would update role mapping for {role_name} with:")
        logger.info(json.dumps(mapping_config, indent=2))
        return True
    
    try:
        url = urljoin(endpoint, f"_plugins/_security/api/rolesmapping/{role_name}")
        logger.debug(f"Updating role mapping at: {url}")
        logger.debug(f"Mapping configuration: {json.dumps(mapping_config, indent=2)}")
        
        # Try PUT method first (most common for role mappings)
        response = session.put(url, json=mapping_config, verify=False)
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully updated role mapping for: {role_name}")
            logger.debug(f"PUT response: {response.text}")
            return True
        else:
            logger.error(f"PUT method failed: {response.status_code}")
            logger.debug(f"PUT error response: {response.text}")
            
            # Try PATCH method with simple JSON body (not JSON Patch format)
            logger.debug("Trying PATCH method...")
            response = session.patch(url, json=mapping_config, verify=False)
            
            if response.status_code in [200, 201]:
                logger.info(f"Successfully updated role mapping using PATCH method for: {role_name}")
                logger.debug(f"PATCH response: {response.text}")
                return True
            else:
                logger.error(f"PATCH method also failed: {response.status_code}")
                logger.debug(f"PATCH error response: {response.text}")
                return False
            
    except Exception as e:
        logger.error(f"Exception updating role mapping: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def get_current_user_arn(dry_run=False):
    """Get current AWS user ARN using STS get-caller-identity"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info("[DRY RUN] Would get current user ARN from AWS STS")
        return "arn:aws:iam::123456789012:user/example-user"
    
    try:
        logger.debug("Getting current user ARN from AWS STS")
        sts_client = boto3.client('sts')
        response = sts_client.get_caller_identity()
        user_arn = response['Arn']
        logger.info(f"Current AWS user ARN: {user_arn}")
        logger.debug(f"STS response: {json.dumps(response, indent=2)}")
        return user_arn
    except ClientError as e:
        logger.error(f"Error getting current user ARN: {e}")
        logger.debug(f"ClientError details: {str(e)}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Exception getting current user ARN: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return None

def get_aws_credentials():
    """Get current AWS credentials"""
    logger = logging.getLogger(__name__)
    
    try:
        session = boto3.Session()
        credentials = session.get_credentials()
        
        if credentials is None:
            logger.error("No AWS credentials found")
            return None
            
        return {
            'access_key': credentials.access_key,
            'secret_key': credentials.secret_key,
            'session_token': credentials.token
        }
    except Exception as e:
        logger.error(f"Error getting AWS credentials: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return None



def create_manage_snapshots_mapping(iam_role_arn, iam_user_arn):
    """Create role mapping configuration for manage_snapshots role"""
    return {
        "backend_roles": [iam_role_arn],
        "users": [iam_user_arn],
        "description": "Mapping for OpenSearch snapshot operations"
    }

def create_all_access_mapping(current_user_arn):
    """Create role mapping configuration for all_access role"""
    return {
        "backend_roles": [],
        "users": [current_user_arn],
        "description": "Mapping current AWS user to all_access role for OpenSearch administration"
    }

def configure_all_access_mapping(endpoint, session, current_user_arn, dry_run=False):
    """Configure all_access role mapping for current user"""
    logger = logging.getLogger(__name__)
    
    logger.debug("Configuring all_access role mapping")
    
    # Check if all_access role exists
    if not check_role_exists(session, endpoint, "all_access", dry_run):
        logger.error("all_access role does not exist")
        return False
    
    # Get current role mapping
    current_mapping = get_current_role_mapping(session, endpoint, "all_access", dry_run)
    if current_mapping is None:
        return False
    
    # Create new mapping configuration
    new_mapping = create_all_access_mapping(current_user_arn)
    
    # Merge with existing mapping if it exists
    if current_mapping:
        logger.debug("Merging with existing all_access role mapping")
        # Merge backend_roles
        existing_backend_roles = current_mapping.get('backend_roles', [])
        new_backend_roles = new_mapping['backend_roles']
        merged_backend_roles = list(set(existing_backend_roles + new_backend_roles))
        
        # Merge users
        existing_users = current_mapping.get('users', [])
        new_users = new_mapping['users']
        merged_users = list(set(existing_users + new_users))
        
        new_mapping['backend_roles'] = merged_backend_roles
        new_mapping['users'] = merged_users
    
    # Update role mapping
    success = update_role_mapping(session, endpoint, "all_access", new_mapping, dry_run)
    
    if success:
        logger.info("Configured all_access role mapping")
    else:
        logger.error("Failed to configure all_access role mapping")
    
    return success

def aws_request(method, url, region, service, payload, access_key, secret_key, session_token=None):
    """Make AWS signed request following AWS documentation pattern"""
    logger = logging.getLogger(__name__)
    
    # Parse the URL
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path
    
    # Create credentials object
    from botocore.credentials import Credentials
    credentials = Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=session_token
    )
    
    # Prepare headers
    headers = {
        'Content-Type': 'application/json',
        'Host': host
    }
    
    # Create the request
    request = AWSRequest(
        method=method,
        url=url,
        data=payload,
        headers=headers
    )
    
    # Sign the request
    SigV4Auth(credentials, service, region).add_auth(request)
    
    logger.debug(f"Signed request headers: {dict(request.headers)}")
    
    # Make the HTTP request
    response = requests.request(
        method=method,
        url=url,
        data=payload,
        headers=dict(request.headers),
        verify=False
    )
    
    return response

def register_snapshot_repository(config, dry_run=False):
    """Register snapshot repository using AWS IAM authentication following AWS docs pattern"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Registering Snapshot Repository ===")
    
    if dry_run:
        logger.info("[DRY RUN] Would register snapshot repository")
        return True
    
    try:
        # Get source domain endpoint
        source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
        if not source_endpoint:
            logger.error("Could not get source domain endpoint")
            return False
        
        # Extract region from domain ARN
        source_region = config['source']['region']
        
        # Get AWS credentials
        boto_session = boto3.Session()
        credentials = boto_session.get_credentials()
        
        if credentials is None:
            logger.error("No AWS credentials found")
            return False
        
        logger.info("Using AWS IAM authentication for repository registration")
        
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
        
        # Prepare the request
        url = f"{source_endpoint}/_snapshot/{repo_name}"
        payload = json.dumps(repository_config)
        
        logger.info(f"Registering repository: {repo_name}")
        logger.info(f"S3 bucket: {config['s3_bucket']['name']}")
        logger.info(f"IAM role: {config['source']['role_arn']}")
        logger.debug(f"Repository URL: {url}")
        logger.debug(f"Repository config: {json.dumps(repository_config, indent=2)}")
        
        # Make the AWS signed request
        response = aws_request(
            method='PUT',
            url=url,
            region=source_region,
            service='es',
            payload=payload,
            access_key=credentials.access_key,
            secret_key=credentials.secret_key,
            session_token=credentials.token
        )
        
        if response.status_code in [200, 201]:
            logger.info(f"Successfully registered snapshot repository: {repo_name}")
            logger.debug(f"Response: {response.text}")
            return True
        elif response.status_code == 500:
            logger.error(f"Repository registration failed with server error: {response.status_code}")
            
            # Parse the error response to provide specific guidance
            try:
                error_data = response.json()
                if "repository_verification_exception" in str(error_data):
                    logger.error("Repository verification failed - this usually means:")
                    logger.error("1. The IAM role doesn't have proper S3 permissions")
                    logger.error("2. The S3 bucket policy doesn't allow the OpenSearch service")
                    logger.error("3. The IAM role trust policy doesn't allow OpenSearch to assume it")
                    
                    if "s3:PutObject" in str(error_data):
                        logger.error("Specific issue: IAM role lacks s3:PutObject permission on the S3 bucket")
                        logger.error(f"Role: {config['source']['role_arn']}")
                        logger.error(f"Bucket: {config['s3_bucket']['name']}")
                        logger.error("Check the IAM role's attached policies")
                        
            except:
                pass
                
            logger.debug(f"Error response: {response.text}")
            return False
        elif response.status_code == 403:
            logger.error(f"Failed to register repository: 403 Forbidden")
            logger.error("Current AWS user may not have permissions to register repositories")
            logger.error("Make sure your AWS user has OpenSearch domain access permissions")
            logger.debug(f"Error response: {response.text}")
            return False
        else:
            logger.error(f"Failed to register repository: {response.status_code}")
            logger.debug(f"Error response: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Exception registering snapshot repository: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)
        return False

def configure_source_domain_security(config, username, password, dry_run=False):
    """Configure security mappings for source domain"""
    logger = logging.getLogger(__name__)
    
    logger.info("=== Configuring SOURCE domain security ===")
    
    # Get source domain endpoint
    source_endpoint = get_opensearch_endpoint(config['source']['domain_arn'])
    if not source_endpoint:
        logger.error("Could not get source domain endpoint")
        return False
    
    logger.info(f"Source domain endpoint: {source_endpoint}")
    
    # Create session
    session = create_security_session(source_endpoint, username, password)
    
    # Test connection first
    if not test_connection(session, source_endpoint, dry_run):
        logger.error("Failed to connect to OpenSearch Security API")
        return False
    
    # Get current user ARN for all_access mapping
    current_user_arn = get_current_user_arn(dry_run)
    if not current_user_arn:
        logger.error("Could not get current user ARN")
        return False
    
    # Configure all_access role mapping first
    all_access_success = configure_all_access_mapping(source_endpoint, session, current_user_arn, dry_run)
    
    # Check if manage_snapshots role exists
    if not check_role_exists(session, source_endpoint, "manage_snapshots", dry_run):
        logger.error("manage_snapshots role does not exist")
        return False
    
    # Get current role mapping
    current_mapping = get_current_role_mapping(session, source_endpoint, "manage_snapshots", dry_run)
    if current_mapping is None:
        return False
    
    # Create new mapping configuration
    new_mapping = create_manage_snapshots_mapping(
        config['source']['role_arn'],
        config['source']['user_info']['UserArn']
    )
    
    # Merge with existing mapping if it exists
    if current_mapping:
        logger.debug("Merging with existing manage_snapshots role mapping")
        # Merge backend_roles
        existing_backend_roles = current_mapping.get('backend_roles', [])
        new_backend_roles = new_mapping['backend_roles']
        merged_backend_roles = list(set(existing_backend_roles + new_backend_roles))
        
        # Merge users
        existing_users = current_mapping.get('users', [])
        new_users = new_mapping['users']
        merged_users = list(set(existing_users + new_users))
        
        new_mapping['backend_roles'] = merged_backend_roles
        new_mapping['users'] = merged_users
    
    # Update role mapping
    manage_snapshots_success = update_role_mapping(session, source_endpoint, "manage_snapshots", new_mapping, dry_run)
    
    # Both mappings should succeed
    success = all_access_success and manage_snapshots_success
    
    if success:
        logger.info("Source domain security configuration completed successfully")
    else:
        logger.error("Failed to configure source domain security")
    
    return success



def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Configure OpenSearch security role mappings for snapshot operations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Configure source domain with admin credentials
  python configure_opensearch_security.py --username admin --password mypassword
  
  # Dry run to see what would be configured
  python configure_opensearch_security.py --username admin --password mypassword --dry-run
  
  # Use custom config file
  python configure_opensearch_security.py --config-file my_config.json --username admin --password mypassword
  
  # Enable debug logging for troubleshooting
  python configure_opensearch_security.py --username admin --password mypassword --debug
  
  # Configure security and register snapshot repository (uses AWS IAM auth for repository)
  python configure_opensearch_security.py --username admin --password mypassword --register-repository
        """
    )
    
    parser.add_argument(
        '--config-file',
        default='iam_resources_output.json',
        help='Configuration file with resource details (default: iam_resources_output.json)'
    )
    
    parser.add_argument(
        '--username',
        help='OpenSearch admin username (required for authentication)'
    )
    
    parser.add_argument(
        '--password',
        help='OpenSearch admin password (required for authentication)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be configured without making actual changes'
    )
    

    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging for detailed error messages and troubleshooting'
    )
    
    parser.add_argument(
        '--register-repository',
        action='store_true',
        help='Also register snapshot repository using AWS IAM authentication (uses current user credentials)'
    )
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    logger = setup_logging(debug=args.debug)
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
    else:
        logger.info("=== Starting OpenSearch Security Configuration ===")
    
    # Validate authentication parameters
    if not args.username or not args.password:
        logger.error("Username and password are required for OpenSearch authentication")
        logger.error("Use --username and --password arguments")
        sys.exit(1)
    
    # Load configuration
    logger.info(f"Loading configuration from: {args.config_file}")
    config = load_config(args.config_file)
    
    # Get current user ARN for display
    current_user_arn = get_current_user_arn(args.dry_run)
    
    # Display what will be configured
    logger.info("Security mappings to be configured:")
    logger.info(f"  Source Domain: {config['source']['domain_name']}")
    logger.info(f"    Current AWS User -> all_access role: {current_user_arn}")
    logger.info(f"    IAM Role -> manage_snapshots role: {config['source']['role_arn']}")
    logger.info(f"    IAM User -> manage_snapshots role: {config['source']['user_info']['UserArn']}")
    
    success_count = 0
    total_count = 1
    
    # Configure source domain security
    security_success = configure_source_domain_security(config, args.username, args.password, args.dry_run)
    if security_success:
        success_count += 1
    
    # Register snapshot repository if requested
    repository_success = True
    if args.register_repository:
        total_count += 1
        repository_success = register_snapshot_repository(config, args.dry_run)
        if repository_success:
            success_count += 1
    
    # Summary
    if args.dry_run:
        if args.register_repository:
            logger.info("DRY RUN COMPLETE: Would have configured security mappings and registered repository")
        else:
            logger.info("DRY RUN COMPLETE: Would have configured security mappings")
    else:
        logger.info(f"Configuration completed: {success_count}/{total_count} operations completed successfully")
        
        if success_count == total_count:
            logger.info("All security mappings configured successfully")
        else:
            logger.error("Some operations failed. Use --debug for detailed error information.")

if __name__ == "__main__":
    main()