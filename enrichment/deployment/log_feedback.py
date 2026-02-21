import json
from datetime import datetime

OUTPUT_FILE = "data/deployment_feedback.jsonl"

def log(run_id, outcome, lesson):
    record = {
        "layer": "deployment_feedback",
        "run_id": run_id,
        "timestamp": str(datetime.utcnow()),
        "outcome": outcome,
        "lessons_learned": lesson
    }

    with open(OUTPUT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    print("Deployment feedback logged")

if __name__ == "__main__":
    log("run_001", "rollback_successful", "IAM policy too broad")