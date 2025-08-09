#!/usr/bin/env python3
"""
Script to automate OpenSearch manual snapshot creation
Handles snapshot status checking, creation, and verification

Usage:
  python take_snapshot.py --domain DOMAIN_ENDPOINT --snapshot-name SNAPSHOT_NAME [options]
"""

import json
import requests
import sys
import argparse
import time
import logging
from datetime import datetime
from urllib.parse import urljoin
import urllib3
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
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

def log_separator():
    """Log a separator line"""
    logger = logging.getLogger(__name__)
    logger.info("-" * 60)

def create_session(endpoint, username=None, password=None, use_aws_auth=False, region=None):
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

def test_connection(session, endpoint, use_aws_auth=False, region=None, dry_run=False):
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
            response = aws_signed_request('GET', url, region, 'es', session=session)
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

def aws_signed_request(method, url, region, service, payload=None, session=None):
    """Make AWS signed request"""
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
            response = aws_signed_request('GET', url, region, 'es', session=session)
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
            
            # Provide specific error guidance
            if response.status_code == 401:
                logger.error("AUTHENTICATION FAILED - This is likely due to:")
                logger.error("- Incorrect OpenSearch username/password")
                logger.error("- User credentials have expired")
                logger.error("SUGGESTION: Verify your username and password are correct")
            elif response.status_code == 403:
                logger.error("PERMISSION DENIED - This is likely due to:")
                logger.error("- User doesn't have snapshot management permissions")
                logger.error("- OpenSearch security configuration issues")
                logger.error("SUGGESTION: Check that the user has proper OpenSearch roles")
            elif response.status_code == 404:
                logger.error("NOT FOUND - This is likely due to:")
                logger.error("- Incorrect OpenSearch domain endpoint")
                logger.error("- OpenSearch cluster is not accessible")
                logger.error("SUGGESTION: Verify the domain URL is correct")
            elif response.status_code == 500:
                logger.error("INTERNAL SERVER ERROR - OpenSearch may have issues")
                logger.error("SUGGESTION: Check OpenSearch cluster health")
            
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
                    else:
                        logger.error(f"Error details: {error_info}")
            except:
                logger.error("Could not parse error response as JSON")
            
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
            response = aws_signed_request('PUT', url, region, 'es', payload=payload, session=session)
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
            
            # Provide specific error guidance
            if response.status_code == 401:
                logger.error("AUTHENTICATION FAILED - Check username/password")
            elif response.status_code == 403:
                logger.error("PERMISSION DENIED - User may not have snapshot permissions")
                logger.error("SUGGESTION: Check that the user has 'manage_snapshots' role")
            elif response.status_code == 404:
                logger.error("REPOSITORY NOT FOUND - Check repository name")
                logger.error(f"SUGGESTION: Verify repository '{repository}' exists")
            elif response.status_code == 400:
                logger.error("BAD REQUEST - Check snapshot configuration")
            elif response.status_code == 500:
                logger.error("INTERNAL SERVER ERROR - OpenSearch may have issues")
            
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
                    else:
                        logger.error(f"Error details: {error_info}")
            except:
                logger.error("Could not parse error response as JSON")
            
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
            response = aws_signed_request('GET', url, region, 'es', session=session)
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
            response = aws_signed_request('GET', url, region, 'es', session=session)
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
    check_interval = 10  # Check every 10 seconds as requested
    
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

def wait_for_snapshot_completion(session, endpoint, repository, snapshot_name, 
                               timeout_minutes=60, use_aws_auth=False, region=None):
    """Wait for snapshot to complete with timeout (legacy method - kept for compatibility)"""
    logger = logging.getLogger(__name__)
    
    logger.info(f"Waiting for snapshot {repository}/{snapshot_name} to complete...")
    logger.info(f"Timeout: {timeout_minutes} minutes")
    
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    check_interval = 30  # Check every 30 seconds
    
    while True:
        success, snapshot_data = get_snapshot_info(
            session, endpoint, repository, snapshot_name, use_aws_auth, region
        )
        
        if success and 'snapshots' in snapshot_data:
            snapshots = snapshot_data['snapshots']
            if snapshots:
                snapshot = snapshots[0]
                state = snapshot.get('state', 'UNKNOWN')
                
                if state == 'SUCCESS':
                    duration = snapshot.get('duration_in_millis', 0) / 1000
                    logger.info(f"Snapshot completed successfully in {duration:.1f} seconds")
                    return True, snapshot
                elif state == 'FAILED':
                    failures = snapshot.get('failures', [])
                    logger.error(f"Snapshot failed. Failures: {failures}")
                    return False, snapshot
                elif state in ['IN_PROGRESS', 'STARTED']:
                    elapsed = time.time() - start_time
                    logger.info(f"Snapshot in progress... (elapsed: {elapsed:.0f}s)")
                else:
                    logger.warning(f"Unexpected snapshot state: {state}")
        
        # Check timeout
        elapsed = time.time() - start_time
        if elapsed > timeout_seconds:
            logger.error(f"Timeout waiting for snapshot completion ({timeout_minutes} minutes)")
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

def load_config_repository_name(config_file='opensearch_snapshot_config.json'):
    """Load repository name from config file if it exists"""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config.get('repository_name', 'automated-snapshots')
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return 'automated-snapshots'

def parse_arguments():
    """Parse command line arguments"""
    # Get default repository name from config file
    default_repository = load_config_repository_name()
    
    parser = argparse.ArgumentParser(
        description='Automate OpenSearch manual snapshot creation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Basic snapshot with auto-generated name
  python take_snapshot.py \\
    --domain "https://search-mydomain-abc123.us-east-1.es.amazonaws.com" \\
    --repository "{default_repository}" \\
    --username admin --password mypassword
  
  # Snapshot with custom name
  python take_snapshot.py \\
    --domain "https://search-mydomain-abc123.us-east-1.es.amazonaws.com" \\
    --repository "{default_repository}" \\
    --snapshot-name "backup-before-upgrade" \\
    --username admin --password mypassword
  
  # Snapshot specific indices only
  python take_snapshot.py \\
    --domain "https://search-mydomain-abc123.us-east-1.es.amazonaws.com" \\
    --repository "{default_repository}" \\
    --indices "index1,index2,index3" \\
    --username admin --password mypassword
  
  # Using AWS IAM authentication
  python take_snapshot.py \\
    --domain "https://search-mydomain-abc123.us-east-1.es.amazonaws.com" \\
    --repository "{default_repository}" \\
    --region us-east-1 --use-aws-auth
  
  # Dry run to see what would be done
  python take_snapshot.py \\
    --domain "https://search-mydomain-abc123.us-east-1.es.amazonaws.com" \\
    --repository "{default_repository}" \\
    --username admin --password mypassword --dry-run
        """
    )
    
    parser.add_argument('--domain', required=True,
                       help='OpenSearch domain endpoint URL')
    parser.add_argument('--repository', default=default_repository,
                       help=f'Snapshot repository name (default: {default_repository})')
    parser.add_argument('--snapshot-name',
                       help='Snapshot name (auto-generated if not provided)')
    parser.add_argument('--indices',
                       help='Comma-separated list of indices to snapshot (all indices if not specified)')
    parser.add_argument('--username',
                       help='OpenSearch username for basic auth')
    parser.add_argument('--password',
                       help='OpenSearch password for basic auth')
    parser.add_argument('--use-aws-auth', action='store_true',
                       help='Use AWS IAM authentication instead of basic auth')
    parser.add_argument('--region',
                       help='AWS region (required when using AWS auth)')
    parser.add_argument('--wait', action='store_true',
                       help='Wait for snapshot to complete')
    parser.add_argument('--timeout', type=int, default=60,
                       help='Timeout in minutes when waiting (default: 60)')
    parser.add_argument('--force', action='store_true',
                       help='Skip snapshot status check and create anyway')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    return parser.parse_a

def main():
    args = parse_arguments()
    
    logger = setup_logging(debug=args.debug)
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
        log_separator()
    else:
        logger.info("=== Starting OpenSearch Manual Snapshot ===")
        log_separator()
    
    # Normalize and validate domain URL
    try:
        domain_url = normalize_domain_url(args.domain)
        logger.info(f"OpenSearch domain: {domain_url}")
    except ValueError as e:
        logger.error(f"Invalid domain URL: {e}")
        return
    
    # Validate authentication
    if args.use_aws_auth:
        if not args.region:
            logger.error("--region is required when using AWS authentication")
            return
        logger.info("Using AWS IAM authentication")
    else:
        if not args.username or not args.password:
            logger.error("--username and --password are required for basic authentication")
            return
        logger.info("Using basic authentication")
    
    # Generate snapshot name if not provided
    snapshot_name = args.snapshot_name or generate_snapshot_name()
    logger.info(f"Snapshot name: {snapshot_name}")
    
    # Parse indices if provided
    indices = None
    if args.indices:
        indices = [idx.strip() for idx in args.indices.split(',')]
        logger.info(f"Target indices: {', '.join(indices)}")
    else:
        logger.info("Target: All indices")
    
    log_separator()
    
    try:
        # Create session
        logger.debug("Creating OpenSearch session")
        session = create_session(
            domain_url, 
            args.username, 
            args.password, 
            args.use_aws_auth, 
            args.region
        )
        
        # Test connection first
        logger.debug("Testing OpenSearch connection...")
        if not test_connection(session, domain_url, args.use_aws_auth, args.region, args.dry_run):
            logger.error("Cannot connect to OpenSearch cluster")
            logger.error("Please check your credentials and domain URL")
            return
        
        # Check snapshot status (unless forced)
        if not args.force:
            logger.info("=== Checking Snapshot Status ===")
            can_proceed, running_snapshots = check_snapshot_status(
                session, domain_url, args.use_aws_auth, args.region, args.dry_run
            )
            
            if not can_proceed and not args.dry_run:
                logger.error("Cannot create snapshot while other snapshots are in progress")
                logger.error("Use --force to override this check (not recommended)")
                return
            
            log_separator()
        else:
            logger.warning("Skipping snapshot status check (--force enabled)")
            log_separator()
        
        # Create snapshot asynchronously
        logger.info("=== Creating Snapshot ===")
        success, task_id = create_snapshot_async(
            session, domain_url, args.repository, snapshot_name, 
            indices, args.use_aws_auth, args.region, args.dry_run
        )
        
        if not success and not args.dry_run:
            logger.error("Failed to create snapshot")
            return
        
        log_separator()
        
        # Wait for completion if requested
        if args.wait and not args.dry_run:
            logger.info("=== Waiting for Completion ===")
            
            if task_id and task_id != "dry-run-task-id":
                # Use task-based monitoring (preferred method)
                success, snapshot_info = wait_for_task_completion(
                    session, domain_url, task_id, args.repository, snapshot_name,
                    args.timeout, args.use_aws_auth, args.region
                )
            else:
                # Fallback to snapshot status monitoring
                logger.info("No task ID available, using snapshot status monitoring")
                success, snapshot_info = wait_for_snapshot_completion(
                    session, domain_url, args.repository, snapshot_name,
                    args.timeout, args.use_aws_auth, args.region
                )
            
            if success:
                logger.info("Snapshot completed successfully!")
            else:
                logger.error("Snapshot did not complete successfully")
                return
            
            log_separator()
        
        # Get final snapshot info
        logger.info("=== Snapshot Information ===")
        success, snapshot_data = get_snapshot_info(
            session, domain_url, args.repository, snapshot_name,
            args.use_aws_auth, args.region, args.dry_run
        )
        
        if success and not args.dry_run:
            if 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                snapshot = snapshot_data['snapshots'][0]
                state = snapshot.get('state', 'UNKNOWN')
                start_time = snapshot.get('start_time', 'Unknown')
                duration = snapshot.get('duration_in_millis', 0) / 1000 if snapshot.get('duration_in_millis') else 0
                
                logger.info(f"Repository: {args.repository}")
                logger.info(f"Snapshot: {snapshot_name}")
                logger.info(f"State: {state}")
                logger.info(f"Start time: {start_time}")
                if duration > 0:
                    logger.info(f"Duration: {duration:.1f} seconds")
                
                if 'indices' in snapshot:
                    logger.info(f"Indices: {', '.join(snapshot['indices'])}")
        
        log_separator()
        
        if args.dry_run:
            logger.info("DRY RUN COMPLETE - No actual changes were made")
        else:
            # Determine the appropriate completion message based on snapshot state
            snapshot_state = None
            if success and not args.dry_run:
                if 'snapshots' in snapshot_data and snapshot_data['snapshots']:
                    snapshot = snapshot_data['snapshots'][0]
                    snapshot_state = snapshot.get('state', 'UNKNOWN')
            
            # Show appropriate completion message
            if args.wait:
                # If we waited, we know the final result
                logger.info("Snapshot operation completed!")
            elif snapshot_state in ['SUCCESS', 'COMPLETED']:
                logger.info("Snapshot completed successfully!")
            elif snapshot_state in ['IN_PROGRESS', 'STARTED']:
                logger.info("Snapshot initiated successfully and is in progress")
            elif snapshot_state == 'FAILED':
                logger.info("Snapshot was initiated but has failed")
            else:
                logger.info("Snapshot initiated successfully")
            
            logger.info(f"Repository: {args.repository}")
            logger.info(f"Snapshot: {snapshot_name}")
            
            if not args.wait:
                logger.info("")
                if snapshot_state in ['IN_PROGRESS', 'STARTED']:
                    logger.info("Snapshot is still running. To monitor progress:")
                elif snapshot_state == 'SUCCESS':
                    logger.info("To view snapshot details:")
                else:
                    logger.info("To check snapshot status:")
                    
                logger.info(f"curl -XGET '{domain_url}/_snapshot/{args.repository}/{snapshot_name}'")
                logger.info("")
                logger.info("To list all snapshots:")
                logger.info(f"curl -XGET '{domain_url}/_snapshot/{args.repository}/_all?pretty'")
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.debug(f"Exception details: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()