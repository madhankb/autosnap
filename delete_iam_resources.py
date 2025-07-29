#!/usr/bin/env python3
"""
Script to delete IAM resources created by create_iam_resources.py
Reads from iam_resources_output.json and removes all created resources

Usage:
  python delete_iam_resources.py [--config-file CONFIG_FILE] [--dry-run]
"""

import json
import boto3
from botocore.exceptions import ClientError
import sys
import argparse
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

def load_config(config_file):
    """Load configuration from output file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: {config_file} not found")
        print("Make sure you have run create_iam_resources.py first")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in {config_file}")
        sys.exit(1)

def delete_s3_bucket(s3_client, bucket_name, dry_run=False):
    """Delete S3 bucket and all its contents"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete S3 bucket: {bucket_name}")
        return True
    
    try:
        logger.info(f"Deleting S3 bucket: {bucket_name}")
        
        # First, delete all objects in the bucket
        logger.info(f"Deleting all objects in bucket: {bucket_name}")
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
                        logger.info(f"Deleted {len(objects)} objects from bucket")
            
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
                    logger.info(f"Deleted {len(versions)} object versions from bucket")
        
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
            return False

def delete_iam_user(iam_client, user_name, dry_run=False):
    """Delete IAM user and all attached policies and access keys"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete IAM user: {user_name}")
        return True
    
    try:
        logger.info(f"Deleting IAM user: {user_name}")
        
        # Delete access keys
        try:
            keys_response = iam_client.list_access_keys(UserName=user_name)
            for key in keys_response['AccessKeyMetadata']:
                logger.info(f"Deleting access key: {key['AccessKeyId']}")
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
                logger.info(f"Deleting user policy: {policy_name}")
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
                logger.info(f"Detaching managed policy: {policy['PolicyName']}")
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
            return False

def delete_iam_role(iam_client, role_name, dry_run=False):
    """Delete IAM role and all attached policies"""
    logger = logging.getLogger(__name__)
    
    if dry_run:
        logger.info(f"[DRY RUN] Would delete IAM role: {role_name}")
        return True
    
    try:
        logger.info(f"Deleting IAM role: {role_name}")
        
        # Delete inline policies
        try:
            policies_response = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policies_response['PolicyNames']:
                logger.info(f"Deleting role policy: {policy_name}")
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
                logger.info(f"Detaching managed policy: {policy['PolicyName']}")
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
            return False

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Delete IAM resources created by create_iam_resources.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python delete_iam_resources.py                           # Delete using default config file
  python delete_iam_resources.py --config-file my_config.json  # Use custom config file
  python delete_iam_resources.py --dry-run                 # Show what would be deleted without actually deleting
        """
    )
    
    parser.add_argument(
        '--config-file',
        default='iam_resources_output.json',
        help='Configuration file with resource details (default: iam_resources_output.json)'
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
    
    return parser.parse_args()

def main():
    logger = setup_logging()
    args = parse_arguments()
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No resources will be deleted ===")
    else:
        logger.info("=== Starting OpenSearch Snapshot IAM Resources Deletion ===")
    
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
    
    if not args.dry_run:
        response = input("\nAre you sure you want to delete these resources? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            logger.info("Deletion cancelled by user")
            return
    
    success_count = 0
    total_count = 0
    
    # Delete S3 bucket (if not skipped)
    if 's3_bucket' in config and not args.skip_s3:
        total_count += 1
        logger.info("Deleting S3 bucket resources")
        try:
            s3_client = boto3.client('s3', region_name=config['s3_bucket']['region'])
            if delete_s3_bucket(s3_client, config['s3_bucket']['name'], args.dry_run):
                success_count += 1
        except Exception as e:
            logger.error(f"Error processing S3 bucket: {e}")
    
    # Delete source account resources
    if 'source' in config:
        total_count += 2
        logger.info("Deleting SOURCE account resources")
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
    
    # Delete destination account resources
    if 'destination' in config:
        total_count += 2
        logger.info("Deleting DESTINATION account resources")
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
    
    # Summary
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

if __name__ == "__main__":
    main()