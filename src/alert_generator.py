import json
from datetime import datetime, timezone

def save_alerts(alerts, output_path="../alerts/alerts.json"):
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert_count": len(alerts),
        "alerts": alerts
    }

    with open(output_path, "w") as file:
        json.dump(output, file, indent=2)

    return output
