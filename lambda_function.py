import boto3
import gzip
import json
import os
import urllib.parse
from collections import defaultdict

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")

IAM_TAMPERING_EVENTS = {
    "CreateUser",
    "DeleteUser",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",
}

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

def get_username(record):
    identity = record.get("userIdentity", {}) or {}
    return (
        identity.get("userName")
        or identity.get("principalId")
        or identity.get("arn")
        or "Unknown"
    )

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

def is_console_login_success_without_mfa(record):
    if not (
        record.get("eventSource") == "signin.amazonaws.com"
        and record.get("eventName") == "ConsoleLogin"
        and (record.get("responseElements") or {}).get("ConsoleLogin") == "Success"
    ):
        return False

    additional = record.get("additionalEventData") or {}
    return additional.get("MFAUsed") == "No"

def is_iam_tampering(record):
    return record.get("eventSource") == "iam.amazonaws.com" and record.get("eventName") in IAM_TAMPERING_EVENTS

def format_record(record, alert_type):
    username = get_username(record)
    event_name = record.get("eventName", "Unknown")
    event_time = record.get("eventTime", "Unknown")
    source_ip = record.get("sourceIPAddress", "Unknown")
    user_agent = record.get("userAgent", "Unknown")
    aws_region = record.get("awsRegion", "Unknown")
    account_id = record.get("recipientAccountId", "Unknown")

    return f"""AWS Identity Threat Alert

Alert Type: {alert_type}
Event Name: {event_name}
User: {username}
Source IP: {source_ip}
Region: {aws_region}
Account ID: {account_id}
Event Time: {event_time}
User Agent: {user_agent}

Raw event summary:
{json.dumps(record, indent=2, default=str)[:3500]}
"""

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

        elif is_console_login_success_without_mfa(record):
            subject = "AWS Alert: Console Login Without MFA"
            message = format_record(record, "Successful AWS Console login without MFA")
            publish_alert(subject, message)
            alerts_sent += 1

        elif is_iam_tampering(record):
            subject = "AWS Alert: IAM Tampering Activity"
            message = format_record(record, "Suspicious IAM change detected")
            publish_alert(subject, message)
            alerts_sent += 1

    for source_ip, events in failed_logins_by_ip.items():
        if len(events) >= 3:
            subject = "AWS Alert: Possible Password Spray by Source IP"
            message = (
                f"Possible password spray detected from source IP {source_ip}.\n"
                f"Failed login count in this CloudTrail file: {len(events)}\n\n"
                f"First event:\n{format_record(events[0], 'Possible password spray')}"
            )
            publish_alert(subject, message)
            alerts_sent += 1

    for username, events in failed_logins_by_user.items():
        if len(events) >= 3:
            subject = "AWS Alert: Multiple Failed Logins for User"
            message = (
                f"Multiple failed AWS Console logins detected for user {username}.\n"
                f"Failed login count in this CloudTrail file: {len(events)}\n\n"
                f"First event:\n{format_record(events[0], 'Multiple failed logins')}"
            )
            publish_alert(subject, message)
            alerts_sent += 1

    print(f"Records processed: {len(records)}")
    print(f"Alerts sent: {alerts_sent}")

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
