import json
import yaml

from parser import load_cloudtrail_events
from detector import detect_password_spray, detect_iam_tampering
from alert_generator import save_alerts

def load_yaml_config(file_path):
    with open(file_path, "r") as file:
        return yaml.safe_load(file)

def load_json_config(file_path):
    with open(file_path, "r") as file:
        return json.load(file)

rules = load_yaml_config("config/detection_rules.yml")
approved_ip_config = load_json_config("config/approved_ips.json")

password_spray_events = load_cloudtrail_events("sample_logs/password_spray_cloudtrail.json")
iam_tampering_events = load_cloudtrail_events("sample_logs/iam_tampering_cloudtrail.json")

password_spray_alerts = detect_password_spray(
    password_spray_events,
    unique_user_threshold=rules["password_spray"]["unique_user_threshold"],
    failed_attempt_threshold=rules["password_spray"]["failed_attempt_threshold"]
)

iam_tampering_alerts = detect_iam_tampering(
    iam_tampering_events,
    risky_events=rules["iam_tampering"]["risky_events"],
    approved_ips=approved_ip_config["approved_ips"]
)

all_alerts = password_spray_alerts + iam_tampering_alerts

output = save_alerts(all_alerts, output_path="alerts/alerts.json")

print(json.dumps(output, indent=2))
