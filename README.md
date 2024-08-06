# AWS WAF Inventory Solution

This solution provides a comprehensive inventory of AWS WAF configurations across an entire AWS Organization. It includes a daily Lambda function run and change detection.

## Components

1. SCP Deployment Script (`scp_deployment.py`)
2. Lambda Function (`lambda_function.py`)

## Prerequisites

- Python 3.8 or later
- Boto3 library
- AWS CLI configured with appropriate permissions
- AWS Organization set up

## Setup Instructions

### 1. Deploy Service Control Policy (SCP)

Run the `scp_deployment.py` script to create and attach the necessary SCP:

```
python scp_deployment.py
```

Ensure you have the necessary permissions to create and attach SCPs in your AWS Organization.

### 2. Set up S3 Bucket and SNS Topic

1. Create an S3 bucket to store the WAF inventory:
   ```
   aws s3 mb s3://your-waf-inventory-bucket-name
   ```

2. Create an SNS topic for change notifications:
   ```
   aws sns create-topic --name WAFInventoryChanges
   ```

   Note the ARN of the created topic.

### 3. Create Lambda Function

1. Create a ZIP file containing the `lambda_function.py`:
   ```
   zip waf_inventory_lambda.zip lambda_function.py
   ```

2. Create the Lambda function:
   ```
   aws lambda create-function --function-name WAFInventoryFunction \
       --zip-file fileb://waf_inventory_lambda.zip \
       --handler lambda_function.lambda_handler \
       --runtime python3.8 \
       --role arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_LAMBDA_EXECUTION_ROLE \
       --timeout 900 \
       --memory-size 512
   ```

3. Set environment variables for the Lambda function:
   ```
   aws lambda update-function-configuration --function-name WAFInventoryFunction \
       --environment Variables={S3_BUCKET=your-waf-inventory-bucket-name,SNS_TOPIC_ARN=your-sns-topic-arn}
   ```

### 4. Set up CloudWatch Events Rule

Create a CloudWatch Events rule to trigger the Lambda function daily:

```
aws events put-rule --name DailyWAFInventory --schedule-expression "rate(1 day)"

aws events put-targets --rule DailyWAFInventory --targets Id=1,Arn=arn:aws:lambda:REGION:ACCOUNT_ID:function:WAFInventoryFunction
```

### 5. Permissions

Ensure the Lambda execution role has the following permissions:

- AWSOrganizationsReadOnlyAccess
- AWSWAFReadOnlyAccess
- S3 write permissions to the inventory bucket
- SNS publish permissions to the notifications topic

## Usage

The Lambda function will run daily and perform the following:

1. Inventory all WAF configurations across the AWS Organization
2. Save the inventory to the S3 bucket
3. Compare with the previous day's inventory
4. Send an SNS notification if changes are detected

You can also manually invoke the Lambda function for immediate execution.

## Troubleshooting

- Check CloudWatch Logs for the Lambda function to see detailed execution logs and any error messages.
- Ensure all required permissions are in place, including the SCP, Lambda execution role, and cross-account access.
- Verify that the S3 bucket and SNS topic are correctly set up and accessible.

## Security Considerations

- Regularly review and audit the permissions granted by the SCP and Lambda execution role.
- Ensure the S3 bucket storing the WAF inventory has appropriate access controls and encryption.
- Monitor and audit access to the SNS topic receiving change notifications.
