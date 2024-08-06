import boto3
import json
import logging
import os
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
s3_client = boto3.client('s3')
sns_client = boto3.client('sns')
org_client = boto3.client('organizations')

# Environment variables
S3_BUCKET = os.environ['S3_BUCKET']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

def get_waf_client(region):
    return boto3.client('wafv2', region_name=region)

def get_rule_group_details(waf_client, rule_group_arn, scope):
    try:
        response = waf_client.get_rule_group(
            ARN=rule_group_arn,
            Scope=scope
        )
        return response['RuleGroup']
    except ClientError as error:
        logger.error(f"Error fetching rule group details for {rule_group_arn}: {error}")
        return None

def get_waf_details(waf_client, scope):
    waf_details = []
    try:
        paginator = waf_client.get_paginator('list_web_acls')
        for page in paginator.paginate(Scope=scope):
            for waf in page['WebACLs']:
                waf_info = waf_client.get_web_acl(Name=waf['Name'], Id=waf['Id'], Scope=scope)
                web_acl = waf_info['WebACL']
                
                # Get detailed rule information
                rules = []
                for rule in web_acl.get('Rules', []):
                    if rule.get('Statement', {}).get('RuleGroupReferenceStatement'):
                        rule_group_arn = rule['Statement']['RuleGroupReferenceStatement']['ARN']
                        rule_group_details = get_rule_group_details(waf_client, rule_group_arn, scope)
                        if rule_group_details:
                            rules.append({
                                'Type': 'RuleGroup',
                                'Name': rule.get('Name'),
                                'Priority': rule.get('Priority'),
                                'OverrideAction': rule.get('OverrideAction'),
                                'RuleGroupDetails': rule_group_details
                            })
                    else:
                        rules.append({
                            'Type': 'Rule',
                            'Name': rule.get('Name'),
                            'Priority': rule.get('Priority'),
                            'Action': rule.get('Action'),
                            'Statement': rule.get('Statement')
                        })
                
                web_acl['DetailedRules'] = rules
                waf_details.append(web_acl)
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            logger.error(f"Access denied when fetching WAF details for scope {scope}. Ensure proper SCPs are in place.")
        else:
            logger.error(f"Error fetching WAF details for scope {scope}: {error}")
    return waf_details

def process_account(account_id):
    account_waf_details = {'AccountId': account_id, 'WAFs': []}
    regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 
               'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 
               'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 
               'ap-southeast-2', 'ap-south-1', 'sa-east-1', 'me-south-1', 'af-south-1']

    for region in regions:
        waf_client = get_waf_client(region)
        
        for scope in ['REGIONAL', 'CLOUDFRONT']:
            waf_details = get_waf_details(waf_client, scope)
            for waf in waf_details:
                account_waf_details['WAFs'].append({
                    'Region': region,
                    'Scope': scope,
                    'Details': waf
                })

    return account_waf_details

def list_accounts():
    accounts = []
    try:
        paginator = org_client.get_paginator('list_accounts')
        for page in paginator.paginate():
            accounts.extend([account['Id'] for account in page['Accounts']])
    except ClientError as error:
        logger.error(f"Error listing accounts: {error}")
    return accounts

def save_to_s3(data, filename):
    try:
        s3_client.put_object(Bucket=S3_BUCKET, Key=filename, Body=json.dumps(data))
        logger.info(f"Saved {filename} to S3 bucket {S3_BUCKET}")
    except ClientError as error:
        logger.error(f"Error saving to S3: {error}")

def get_previous_inventory():
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    filename = f'waf_inventory_{yesterday}.json'
    try:
        response = s3_client.get_object(Bucket=S3_BUCKET, Key=filename)
        return json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchKey':
            logger.info("No previous inventory found. This might be the first run.")
        else:
            logger.error(f"Error retrieving previous inventory: {error}")
        return None

def detect_changes(previous_inventory, current_inventory):
    changes = []
    for prev_account, curr_account in zip(previous_inventory, current_inventory):
        if prev_account != curr_account:
            changes.append({
                'AccountId': curr_account['AccountId'],
                'Changes': json.dumps(curr_account, default=str)
            })
    return changes

def send_sns_notification(changes):
    message = "The following WAF changes were detected:\n\n"
    message += json.dumps(changes, indent=2)
    try:
        sns_client.publish(TopicArn=SNS_TOPIC_ARN, Message=message, Subject="WAF Configuration Changes Detected")
        logger.info("Sent SNS notification")
    except ClientError as error:
        logger.error(f"Error sending SNS notification: {error}")

def lambda_handler(event, context):
    logger.info("Starting WAF inventory process")
    all_waf_details = []
    accounts = list_accounts()
    
    logger.info(f"Found {len(accounts)} accounts to process")
    for account_id in accounts:
        logger.info(f"Processing account: {account_id}")
        result = process_account(account_id)
        if result:
            all_waf_details.append(result)
            logger.info(f"Successfully processed account {account_id}")
        else:
            logger.warning(f"No WAF details found for account {account_id}")

    today = datetime.now().strftime('%Y-%m-%d')
    filename = f'waf_inventory_{today}.json'
    save_to_s3(all_waf_details, filename)

    previous_inventory = get_previous_inventory()
    if previous_inventory:
        logger.info("Comparing with previous inventory")
        changes = detect_changes(previous_inventory, all_waf_details)
        if changes:
            logger.info(f"Detected changes in {len(changes)} accounts")
            send_sns_notification(changes)
        else:
            logger.info("No changes detected")
    else:
        logger.info("No previous inventory found for comparison")

    logger.info("WAF inventory process completed")
    return {
        'statusCode': 200,
        'body': json.dumps('WAF inventory completed successfully')
    }
