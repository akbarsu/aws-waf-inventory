import boto3
import json
import logging
from botocore.exceptions import ClientError

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize AWS client
org_client = boto3.client('organizations')

def create_scp():
    policy_content = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowWAFReadAccess",
                "Effect": "Allow",
                "Action": [
                    "wafv2:ListWebACLs",
                    "wafv2:GetWebACL",
                    "wafv2:ListRuleGroups",
                    "wafv2:GetRuleGroup"
                ],
                "Resource": "*"
            }
        ]
    }
    
    try:
        response = org_client.create_policy(
            Content=json.dumps(policy_content),
            Description='Allows WAF read access for inventory',
            Name='WAFInventoryAccess',
            Type='SERVICE_CONTROL_POLICY'
        )
        logger.info(f"Created SCP: {response['Policy']['PolicySummary']['Name']}")
        return response['Policy']['PolicyId']
    except ClientError as e:
        logger.error(f"Error creating SCP: {e}")
        return None

def attach_scp_to_root(policy_id):
    try:
        roots = org_client.list_roots()['Roots']
        root_id = roots[0]['Id']
        org_client.attach_policy(
            PolicyId=policy_id,
            TargetId=root_id
        )
        logger.info(f"Attached SCP to root: {root_id}")
    except ClientError as e:
        logger.error(f"Error attaching SCP to root: {e}")

def list_scps():
    try:
        paginator = org_client.get_paginator('list_policies')
        for page in paginator.paginate(Filter='SERVICE_CONTROL_POLICY'):
            for policy in page['Policies']:
                logger.info(f"Existing SCP: {policy['Name']} (ID: {policy['Id']})")
    except ClientError as e:
        logger.error(f"Error listing SCPs: {e}")

def main():
    logger.info("Starting SCP deployment for WAF Inventory")
    
    # List existing SCPs
    logger.info("Listing existing SCPs:")
    list_scps()
    
    # Create new SCP
    logger.info("Creating new SCP for WAF Inventory")
    policy_id = create_scp()
    
    if policy_id:
        # Attach SCP to root
        logger.info("Attaching new SCP to organization root")
        attach_scp_to_root(policy_id)
        
        logger.info("SCP deployment completed successfully")
    else:
        logger.error("Failed to create SCP. Deployment unsuccessful")

if __name__ == "__main__":
    main()
