import json

def load_cloudtrail_events(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)

    return data.get("Records", [])

