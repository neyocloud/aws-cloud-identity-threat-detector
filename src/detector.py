from collections import defaultdict

def detect_password_spray(events, unique_user_threshold, failed_attempt_threshold):
    failed_logins_by_ip = defaultdict(list)
    alerts = []

    for event in events:
        if event.get("eventName") != "ConsoleLogin":
            continue

        error_message = event.get("errorMessage", "")
        if "Failed" not in error_message:
            continue

        source_ip = event.get("sourceIPAddress", "unknown")
        username = event.get("userIdentity", {}).get("userName", "unknown")

        failed_logins_by_ip[source_ip].append(username)

    for source_ip, usernames in failed_logins_by_ip.items():
        unique_users = set(usernames)

        if len(unique_users) >= unique_user_threshold and len(usernames) >= failed_attempt_threshold:
            alerts.append({
                "alert_name": "Possible AWS Password Spraying",
                "severity": "High",
                "source_ip": source_ip,
                "failed_attempts": len(usernames),
                "unique_users_targeted": len(unique_users),
                "targeted_users": sorted(list(unique_users)),
                "mitre_attack": "T1110.003",
                "recommendation": "Review source IP, targeted IAM users, MFA status, and any successful login after failed attempts."
            })

    return alerts
def detect_iam_tampering(events, risky_events, approved_ips):
    alerts = []

    for event in events:
        event_name = event.get("eventName")
        source_ip = event.get("sourceIPAddress", "unknown")
        username = event.get("userIdentity", {}).get("userName", "unknown")

        if event_name in risky_events and source_ip not in approved_ips:
            alerts.append({
                "alert_name": "Suspicious IAM or Access Configuration Change",
                "severity": "High",
                "event_name": event_name,
                "source_ip": source_ip,
                "user": username,
                "mitre_attack": "T1098",
                "recommendation": "Verify whether this IAM or access change was authorized. Review recent activity by this user."
            })

    return alerts
