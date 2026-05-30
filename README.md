# aws-cloud-identity-threat-detector
AWS cloud security detection system for identifying password spraying, suspicious IAM changes, and unauthorized access activity using CloudTrail logs and Python.




<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/a6c38050-5ccf-4773-ad48-5dd58c20d7f3" />




## Project Overview

This project is an AWS cloud security detection lab that monitors AWS identity activity, analyzes CloudTrail logs, detects suspicious login and IAM activity, and sends email alerts using Amazon SNS.

The goal of this project was to build a simple but realistic cloud detection pipeline that can detect events such as:

* Failed AWS Console login attempts
* Password spray-style login attempts
* IAM tampering activity
* Access key creation
* Suspicious identity-related AWS activity

This project started with sample CloudTrail logs and was later tested with a real AWS Console login failure event. The final result was an email alert sent through SNS when suspicious activity was detected.

---

## Why I Built This Project

Cloud environments generate many logs every day. In a real company, users, administrators, applications, and services are constantly interacting with cloud resources.

Security teams need a way to detect suspicious activity automatically instead of manually checking every log.

This project helped me understand how cloud security monitoring works in AWS by building a small identity threat detection system using:

* AWS CloudTrail
* Amazon S3
* AWS Lambda
* Amazon SNS
* AWS IAM
* Amazon CloudWatch Logs
* Python
* AWS CLI
* Git and GitHub

The project shows how raw cloud logs can be turned into useful security alerts.

---

## Usefulness of This Project

This project can be useful in areas like:

* Cloud Security Monitoring
* SOC Analyst Practice
* Detection Engineering
* AWS Security Automation
* Incident Response
* IAM Security Monitoring
* DevSecOps
* Security Portfolio Building

In a real environment, this type of system can help detect:

* Someone trying to log in with the wrong password
* Password spraying attempts
* Unauthorized IAM access key creation
* Suspicious permission changes
* Login attempts from unknown IP addresses
* Successful login without MFA
* Cloud identity compromise indicators

---

## Services Used

## 1. AWS CloudTrail

AWS CloudTrail records activities happening inside an AWS account.

It captures events such as:

* AWS Console login attempts
* IAM user activity
* API calls
* Access key creation
* Policy changes
* Role changes

In this project, CloudTrail was used as the main source of security logs.

Example event detected:

```text
eventSource = signin.amazonaws.com
eventName   = ConsoleLogin
```

CloudTrail delivered logs into an S3 bucket as compressed `.json.gz` files.

---

## 2. Amazon S3

Amazon S3 stands for Simple Storage Service.

S3 was used to store CloudTrail logs.

In this project, CloudTrail delivered logs into an S3 bucket, and whenever a new log file was created, the S3 bucket triggered the Lambda function.

Example S3 structure:

```text
s3://<BUCKET_NAME>/AWSLogs/<ACCOUNT_ID>/CloudTrail/<REGION>/<YEAR>/<MONTH>/<DAY>/
```

For testing, sample logs were also uploaded to:

```text
s3://<BUCKET_NAME>/test/
```

---

## 3. AWS Lambda

AWS Lambda is a serverless compute service. It runs code without needing to manage a server.

In this project, Lambda was the detection engine.

When a new CloudTrail log file was uploaded to S3, Lambda automatically ran and processed the log.

Lambda performed these tasks:

1. Received the S3 event.
2. Downloaded the CloudTrail log file.
3. Decompressed the `.json.gz` file.
4. Parsed the JSON records.
5. Checked the records for suspicious activity.
6. Sent an alert to SNS if a detection rule matched.

---

## 4. Amazon SNS

Amazon SNS stands for Simple Notification Service.

SNS was used to send email alerts.

When Lambda detected suspicious activity, it published a message to an SNS topic. The SNS topic then sent an email notification to a confirmed email subscriber.

SNS topic example:

```text
arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts
```

---

## 5. IAM

IAM stands for Identity and Access Management.

IAM was used to control permissions for:

* The IAM user used in the AWS CLI
* The Lambda execution role
* S3 access
* SNS publishing
* CloudTrail read access
* Lambda update permissions

This project used least-privilege permissions instead of full administrator access.

That means permissions were added only when needed, such as:

```text
s3:PutObject
s3:GetObject
lambda:UpdateFunctionCode
lambda:GetFunction
sns:Publish
sns:Subscribe
cloudtrail:LookupEvents
cloudtrail:DescribeTrails
```

---

## 6. CloudWatch Logs

Amazon CloudWatch Logs was used to monitor Lambda execution.

CloudWatch Logs helped confirm:

* Lambda was triggered by S3
* Lambda processed CloudTrail records
* Detection rules matched or did not match
* Errors occurred or were fixed
* Alerts were sent successfully

Example Lambda log output:

```text
Lambda triggered
Processing S3 object
Records processed: 139
Alerts sent: 0
```

After fixing the detection rule, the alert email was successfully received.

---

## Architecture Diagram

```text
AWS Console / IAM Activity
          |
          v
AWS CloudTrail
          |
          v
Amazon S3 Bucket
          |
          v
S3 ObjectCreated Event
          |
          v
AWS Lambda Function
          |
          v
Python Detection Logic
          |
          v
Amazon SNS Topic
          |
          v
Email Alert
```

---

## Full Detection Flow

This is how all the services were connected:

1. A user attempts to log in to AWS Console.
2. AWS CloudTrail records the event as a `ConsoleLogin` event.
3. CloudTrail delivers the log file to an S3 bucket.
4. S3 detects that a new object was created.
5. S3 triggers the Lambda function.
6. Lambda downloads the CloudTrail log file from S3.
7. Lambda decompresses and reads the `.json.gz` file.
8. Lambda checks each CloudTrail record against detection rules.
9. If suspicious activity is found, Lambda sends a message to SNS.
10. SNS sends an email alert to the subscribed email address.

---

## Project Folder Structure

```text
aws-cloud-identity-threat-detector/
├── README.md
├── requirements.txt
├── .gitignore
├── lambda_function.py
├── config/
│   ├── approved_ips.json
│   └── detection_rules.yml
├── sample_logs/
│   ├── normal_cloudtrail.json
│   ├── password_spray_cloudtrail.json
│   └── iam_tampering_cloudtrail.json
├── src/
│   ├── main.py
│   ├── parser.py
│   ├── detector.py
│   └── alert_generator.py
└── tests/
    └── test_detector.py
```

---

## Detection Rules

## 1. Failed AWS Console Login

This rule detects failed AWS Console login attempts.

CloudTrail event fields checked:

```text
eventSource = signin.amazonaws.com
eventName = ConsoleLogin
```

The detector checks for failure indicators such as:

```text
responseElements.ConsoleLogin = Failure
```

or:

```text
errorMessage = Failed authentication
```

Why this matters:

A failed login could mean someone is trying to access an AWS account with the wrong password or an invalid username.

---

## 2. Password Spray Detection

Password spraying is when an attacker tries one password against many usernames.

Example:

```text
john-test  -> failed login
mary       -> failed login
david      -> failed login
sarah      -> failed login
alex       -> failed login
```

If multiple failed login attempts come from the same source IP, the detector sends a password spray alert.

Example alert:

```text
Possible password spray detected
Source IP: <SOURCE_IP>
Failed login count: 5
```

---

## 3. IAM Tampering Detection

IAM tampering means suspicious changes to AWS identities, permissions, or credentials.

The detector checks for IAM events such as:

```text
CreateAccessKey
DeleteAccessKey
UpdateAccessKey
AttachUserPolicy
DetachUserPolicy
PutUserPolicy
CreateLoginProfile
UpdateLoginProfile
DeleteLoginProfile
CreatePolicy
CreatePolicyVersion
SetDefaultPolicyVersion
UpdateAssumeRolePolicy
DeactivateMFADevice
DeleteVirtualMFADevice
```

Why this matters:

Attackers often create access keys, attach policies, or modify IAM permissions to maintain access after compromising an account.

---

## 4. Successful Console Login Without MFA

The detector can also identify successful AWS Console logins where MFA was not used.

CloudTrail fields checked:

```text
eventName = ConsoleLogin
ConsoleLogin = Success
MFAUsed = No
```

Why this matters:

A successful login without MFA is risky because the account may be easier to compromise.

---

## Lambda Function Explanation

The main Lambda code is stored in:

```text
lambda_function.py
```

The Lambda function uses Python and the AWS SDK for Python.

Main imports:

```python
import boto3
import gzip
import json
import os
import urllib.parse
from collections import defaultdict
```

Explanation:

* `boto3` is used to interact with AWS services like S3 and SNS.
* `gzip` is used to decompress CloudTrail `.json.gz` files.
* `json` is used to parse CloudTrail log records.
* `os` is used to read environment variables.
* `urllib.parse` is used to decode S3 object keys.
* `defaultdict` is used to group failed login attempts by IP address or username.

---

## Important Lambda Functions

## `publish_alert()`

This function sends an alert to SNS.

```python
def publish_alert(subject, message):
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN is not configured")
        return

    print(f"Sending SNS alert: {subject}")
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=message
    )
```

Purpose:

```text
Send an email alert when suspicious activity is detected.
```

---

## `is_console_login_failure()`

This function checks if a CloudTrail record is a failed AWS Console login.

```python
def is_console_login_failure(record):
    if not (
        record.get("eventSource") == "signin.amazonaws.com"
        and record.get("eventName") == "ConsoleLogin"
    ):
        return False

    response = record.get("responseElements") or {}
    response_login = response.get("ConsoleLogin")

    error_message = (record.get("errorMessage") or "").lower()
    error_code = (record.get("errorCode") or "").lower()

    return (
        response_login == "Failure"
        or "failed authentication" in error_message
        or "failed" in error_message
        or "failure" in error_message
        or "failed" in error_code
        or "unauthorized" in error_code
    )
```

Purpose:

```text
Detect failed AWS Console login attempts.
```

This function was important because different CloudTrail logs can represent login failure in different ways.

Some logs use:

```text
responseElements.ConsoleLogin = Failure
```

Other logs use:

```text
errorMessage = Failed authentication
```

---

## `is_iam_tampering()`

This function checks for suspicious IAM activity.

```python
def is_iam_tampering(record):
    return record.get("eventSource") == "iam.amazonaws.com" and record.get("eventName") in IAM_TAMPERING_EVENTS
```

Purpose:

```text
Detect suspicious IAM changes such as access key creation or policy changes.
```

---

## `process_records()`

This function loops through all CloudTrail records and applies detection rules.

```python
def process_records(records):
    alerts_sent = 0

    failed_logins_by_ip = defaultdict(list)
    failed_logins_by_user = defaultdict(list)

    for record in records:
        if is_console_login_failure(record):
            username = get_username(record)
            source_ip = record.get("sourceIPAddress", "Unknown")

            failed_logins_by_ip[source_ip].append(record)
            failed_logins_by_user[username].append(record)

            subject = "AWS Alert: Failed Console Login"
            message = format_record(record, "Failed AWS Console login detected")
            publish_alert(subject, message)
            alerts_sent += 1
```

Purpose:

```text
Analyze CloudTrail records and send alerts when detection rules match.
```

---

## `lambda_handler()`

This is the main function AWS Lambda runs.

```python
def lambda_handler(event, context):
    print("Lambda triggered")
    print(json.dumps(event, default=str)[:2000])

    for s3_record in event.get("Records", []):
        bucket = s3_record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(s3_record["s3"]["object"]["key"])

        print(f"Processing S3 object: s3://{bucket}/{key}")

        response = s3.get_object(Bucket=bucket, Key=key)
        raw_body = response["Body"].read()

        if key.endswith(".gz"):
            raw_body = gzip.decompress(raw_body)

        data = json.loads(raw_body.decode("utf-8"))

        records = data.get("Records", [])
        if not records:
            print("No CloudTrail Records found in object")
            continue

        process_records(records)

    return {
        "statusCode": 200,
        "body": "Detection completed"
    }
```

Purpose:

```text
Receive S3 trigger events, read CloudTrail files, and run detection logic.
```

---

# Step-by-Step Build Process

## Step 1: Create the Project Folder

```bash
mkdir aws-cloud-identity-threat-detector
cd aws-cloud-identity-threat-detector
```

Purpose:

```text
Create and enter the project directory.
```

---

## Step 2: Create Project Structure

```bash
mkdir config sample_logs src alerts tests lambda_package diagrams
touch README.md requirements.txt .gitignore
touch config/detection_rules.yml config/approved_ips.json
touch src/main.py src/parser.py src/detector.py src/alert_generator.py
touch tests/test_detector.py
touch sample_logs/normal_cloudtrail.json
touch sample_logs/password_spray_cloudtrail.json
touch sample_logs/iam_tampering_cloudtrail.json
```

Purpose:

```text
Create folders and files for code, configs, tests, logs, and documentation.
```

---

## Step 3: Configure AWS CLI Profile

```bash
aws configure --profile threat-detector
```

Purpose:

```text
Configure AWS CLI credentials for the IAM user used in this project.
```

Then confirm identity:

```bash
aws sts get-caller-identity --profile threat-detector
```

Expected result:

```text
The command should show the AWS account and IAM user being used.
```

---

## Step 4: Set AWS Profile in Terminal

```bash
export AWS_PROFILE=threat-detector
```

Purpose:

```text
Make the terminal use the correct AWS CLI profile by default.
```

Then confirm:

```bash
aws sts get-caller-identity
```

---

## Step 5: Create or Use an S3 Bucket for CloudTrail Logs

CloudTrail logs were delivered to an S3 bucket.

Example bucket placeholder:

```text
s3://<BUCKET_NAME>
```

To list objects in the bucket:

```bash
aws s3 ls s3://<BUCKET_NAME>/
```

Purpose:

```text
Confirm that the S3 bucket exists and is accessible.
```

---

## Step 6: Upload Sample Logs to S3

```bash
aws s3 cp ./password_spray_cloudtrail.json.gz s3://<BUCKET_NAME>/test/password_spray_cloudtrail.json.gz
```

Purpose:

```text
Upload a sample CloudTrail log to S3 for testing.
```

To upload with a unique filename:

```bash
aws s3 cp ./password_spray_cloudtrail.json.gz s3://<BUCKET_NAME>/test/password-spray-test-$(date +%s).json.gz
```

Why use `$(date +%s)`?

```text
It adds a unique timestamp so S3 treats the upload as a new object and triggers Lambda again.
```

---

## Step 7: Create an SNS Topic

```bash
aws sns create-topic --name identity-threat-alerts --query TopicArn --output text
```

Purpose:

```text
Create an SNS topic that Lambda can publish alerts to.
```

Example output:

```text
arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts
```

---

## Step 8: Subscribe Email to SNS

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts \
  --protocol email \
  --notification-endpoint <EMAIL_ADDRESS>
```

Purpose:

```text
Subscribe an email address to receive alerts.
```

After running the command, AWS sends a confirmation email. The subscription must be confirmed before alerts can be received.

---

## Step 9: Create Lambda Function

A Lambda function named `aws-identity-threat-detector` was used as the detection engine.

The function used Python 3.12.

The Lambda handler was:

```text
lambda_function.lambda_handler
```

---

## Step 10: Set Lambda Environment Variable

The Lambda function needed the SNS topic ARN.

```bash
aws lambda update-function-configuration \
  --function-name aws-identity-threat-detector \
  --environment "Variables={SNS_TOPIC_ARN=arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts}"
```

Purpose:

```text
Store the SNS topic ARN inside Lambda so the Python code can publish alerts to it.
```

To confirm:

```bash
aws lambda get-function-configuration \
  --function-name aws-identity-threat-detector \
  --query "Environment.Variables" \
  --output json
```

Expected output:

```json
{
  "SNS_TOPIC_ARN": "arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts"
}
```

---

## Step 11: Connect S3 to Lambda

The S3 bucket was configured to trigger Lambda whenever a new object was created.

To check the S3 event notification configuration:

```bash
aws s3api get-bucket-notification-configuration \
  --bucket <BUCKET_NAME>
```

Expected result:

```json
{
  "LambdaFunctionConfigurations": [
    {
      "LambdaFunctionArn": "arn:aws:lambda:<REGION>:<ACCOUNT_ID>:function:aws-identity-threat-detector",
      "Events": [
        "s3:ObjectCreated:*"
      ]
    }
  ]
}
```

Purpose:

```text
Confirm that S3 triggers Lambda when CloudTrail writes a new log file.
```

---

## Step 12: Watch Lambda Logs

```bash
aws logs tail "/aws/lambda/aws-identity-threat-detector" --since 10m --follow
```

Purpose:

```text
Watch Lambda logs live to confirm whether the function is triggered and whether alerts are sent.
```

To stop watching logs:

```text
Ctrl + C
```

---

## Step 13: Deploy Updated Lambda Code

The Lambda code was zipped before deployment.

```bash
cd lambda_downloaded
zip ../lambda_code_updated.zip lambda_function.py
cd ..
```

Then deployed:

```bash
aws lambda update-function-code \
  --function-name aws-identity-threat-detector \
  --zip-file fileb://lambda_code_updated.zip
```

Purpose:

```text
Upload the updated Python detection logic to AWS Lambda.
```

---

## Step 14: Confirm Lambda Deployment

```bash
aws lambda get-function-configuration \
  --function-name aws-identity-threat-detector \
  --query "{State:State,LastUpdateStatus:LastUpdateStatus}" \
  --output table
```

Expected result:

```text
State: Active
LastUpdateStatus: Successful
```

---

## Step 15: Test Password Spray Detection

Upload the password spray sample log:

```bash
aws s3 cp ./password_spray_cloudtrail.json.gz s3://<BUCKET_NAME>/test/password-spray-test-$(date +%s).json.gz
```

Then watch logs:

```bash
aws logs tail "/aws/lambda/aws-identity-threat-detector" --since 5m
```

Expected result:

```text
Lambda triggered
Records processed
Alerts sent
```

Expected email alert:

```text
AWS Alert: Possible Password Spray by Source IP
```

---

## Step 16: Test IAM Tampering Detection

Upload IAM tampering sample log:

```bash
aws s3 cp ./iam_tampering_cloudtrail.json.gz s3://<BUCKET_NAME>/test/iam-tampering-test-$(date +%s).json.gz
```

Expected alert:

```text
AWS Alert: IAM Tampering Activity
```

---

## Step 17: Test Real AWS Console Login Failure

A temporary IAM user was created for safe testing.

The test process:

1. Created a temporary IAM user.
2. Enabled AWS Console access.
3. No admin permissions for the user.
4. Opened an incognito.
5. Logged in with a wrong username or wrong password.
6. Waited for CloudTrail to deliver the log to S3.
7. Confirmed Lambda processes the log.
8. Confirmed SNS sends an email alert.
9. And lastly, I deleted the temporary IAM user.

The final real alert showed:




```text
Alert Type: Failed AWS Console login detected
Event Name: ConsoleLogin
Event Source: signin.amazonaws.com
```


## Detection Proof / Screenshots

The detector successfully generated alerts for:

- Password spray activity
- Failed AWS Console login
- Suspicious IAM policy change





<img width="764" height="1280" alt="WhatsApp Image 2026-05-30 at 07 31 14" src="https://github.com/user-attachments/assets/82bf2f8d-b436-48b3-a6d4-7ebf9b0fd328" />






<img width="776" height="1280" alt="WhatsApp Image 2026-05-30 at 07 35 21" src="https://github.com/user-attachments/assets/650e31b8-4292-4963-9567-761f3572e26b" />






<img width="914" height="1280" alt="WhatsApp Image 2026-05-30 at 07 31 14 (1)" src="https://github.com/user-attachments/assets/557e53aa-f08d-4372-b1c5-754053f34809" />




This confirmed the full detection pipeline worked.

---

## Troubleshooting Issues Faced

## 1. S3 AccessDenied

Issue:

```text
AccessDenied when uploading to S3.
```

Cause:

```text
The AWS CLI was using the wrong profile.
```

Fix:

```bash
aws sts get-caller-identity
aws sts get-caller-identity --profile threat-detector
```

Then use:

```bash
export AWS_PROFILE=threat-detector
```

---

## 2. Lambda Permission Error

Issue:

```text
User is not authorized to perform lambda:UpdateFunctionCode.
```

Fix:

A least-privilege IAM policy was added allowing only:

```text
lambda:UpdateFunctionCode
lambda:GetFunction
```

on the specific Lambda function.

---

## 3. SNS Topic ARN Error

Issue:

```text
InvalidParameterException: TopicArn
```

Cause:

```text
Lambda environment variable had placeholder text instead of a real SNS ARN.
```

Fix:

```bash
aws lambda update-function-configuration \
  --function-name aws-identity-threat-detector \
  --environment "Variables={SNS_TOPIC_ARN=arn:aws:sns:<REGION>:<ACCOUNT_ID>:identity-threat-alerts}"
```

---

## 4. Lambda Python Error

Issue:

```text
NameError: name 'cat' is not defined
```

Cause:

A shell command was accidentally saved inside the Python file:

```bash
cat > lambda_downloaded/lambda_function.py <<'PY'
```

Fix:

```bash
sed -i.bak '1{/^cat > /d;}; ${/^PY$/d;}' lambda_downloaded/lambda_function.py
```

Then check:

```bash
head -n 5 lambda_downloaded/lambda_function.py
tail -n 5 lambda_downloaded/lambda_function.py
python3 -m py_compile lambda_downloaded/lambda_function.py
```

---

## 5. Detection Rule Did Not Match

Issue:

```text
Lambda processed records but alerts sent was 0.
```

Cause:

The first detection rule only checked:

```text
responseElements.ConsoleLogin = Failure
```

But the sample logs used:

```text
errorMessage = Failed authentication
```

Fix:

The detection logic was updated to check both fields.

---

## Important Commands Used

## Check AWS Identity

```bash
aws sts get-caller-identity
```

Used to confirm which AWS user/account the terminal was using.

---

## List S3 Objects

```bash
aws s3 ls s3://<BUCKET_NAME>/test/
```

Used to confirm uploaded test logs.

---

## Upload File to S3

```bash
aws s3 cp ./password_spray_cloudtrail.json.gz s3://<BUCKET_NAME>/test/
```

Used to upload sample CloudTrail logs.

---

## Watch Lambda Logs

```bash
aws logs tail "/aws/lambda/aws-identity-threat-detector" --since 10m --follow
```

Used to monitor Lambda execution live.

---

## Search CloudTrail Console Login Events

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --max-results 10 \
  --region us-east-1
```

Used to confirm AWS recorded console login attempts.

---

## Update Lambda Code

```bash
aws lambda update-function-code \
  --function-name aws-identity-threat-detector \
  --zip-file fileb://lambda_code_updated.zip
```

Used to deploy the updated Python detection logic.

---

## Security Precautions Before Pushing to GitHub

Before pushing this project to GitHub, sensitive files and values were removed.

The `.gitignore` prevents these files from being pushed:

```text
.env
*.env
.aws/
credentials
*.pem
*.key
lambda_code.zip
lambda_code_updated.zip
lambda_url.txt
lambda_downloaded/
lambda_package/
*.gz
alerts/
*.bak
__pycache__/
*.pyc
```

Sensitive values were replaced with placeholders like:

```text
<ACCOUNT_ID>
<BUCKET_NAME>
<REGION>
<EMAIL_ADDRESS>
<SOURCE_IP>
```

A secret scan was also performed using:

```bash
grep -R "AWS_SECRET_ACCESS_KEY\|aws_secret_access_key\|AWS_ACCESS_KEY_ID\|aws_access_key_id\|AKIA\|SECRET\|PRIVATE KEY" -n . --exclude-dir=.git
```

---

## Final Result

The project successfully detected and alerted on:

* Password spray-style failed login activity
* Real AWS Console login failure
* IAM tampering activity
* Suspicious identity-related CloudTrail events

Final working flow:

```text
CloudTrail Event
      ↓
S3 Log File
      ↓
Lambda Trigger
      ↓
Python Detection Logic
      ↓
SNS Email Alert
```

---

## Skills Demonstrated

This project demonstrates:

* AWS Cloud Security
* CloudTrail log analysis
* S3 event-driven architecture
* AWS Lambda serverless processing
* SNS alerting
* IAM least-privilege permissions
* Python automation
* JSON parsing
* CloudWatch troubleshooting
* Detection engineering
* Git and GitHub project documentation
* Secure handling of cloud credentials

---

## What I Learned

From this project, I learned how AWS services can be connected together to build a working cloud security detection pipeline.

I also learned how important IAM permissions are. Many errors came from missing permissions, and fixing them helped me understand least-privilege access better.

The biggest lesson was that detection logic must match the real structure of CloudTrail logs. At first, Lambda was running but sending no alerts because the rule was checking the wrong field. After inspecting the actual logs, the rule was updated and the alert worked.

---

## Future Improvements

Possible future improvements include:

* Add approved IP allowlist
* Add severity levels for alerts
* Store alerts in DynamoDB
* Send alerts to Slack or Microsoft Teams
* Add EventBridge integration
* Add GuardDuty comparison
* Add unit tests for all detection rules
* Add Terraform or CloudFormation deployment
* Add CI/CD deployment to Lambda
* Add detection for root account login
* Add detection for CloudTrail tampering
* Add detection for MFA disablement
* Add detection for unusual region login

---

## Disclaimer

This project was built in a controlled AWS lab environment for learning and portfolio purposes. It should be extended, tested, and hardened before being used in a production environment.
