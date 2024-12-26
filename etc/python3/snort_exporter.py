import json
from flask import Flask, Response
from prometheus_client import Counter, generate_latest

# File path for the Snort JSON logs
SNORT_LOG_PATH = "/var/log/snort/alert_json.txt"
PROCESSED_LOGS_PATH = "/tmp/processed_logs.txt"  # To keep track of processed logs

# Prometheus metrics counters
ssh_brute_force = Counter('snort_ssh_brute_force_total', 'Total number of SSH brute force alerts detected by Snort')
ssh_detected = Counter('snort_ssh_total', 'Total number of ssh alerts detected by Snort')
other_alert_counter = Counter('snort_other_alerts_total', 'Total number of other alerts detected by Snort')

# Flask application
app = Flask(__name__)

def get_processed_logs():
    """
    Reads the file to track which logs have been processed.
    """
    try:
        with open(PROCESSED_LOGS_PATH, 'r') as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        return set()

def update_processed_logs(processed_logs):
    """
    Updates the file with the list of processed logs.
    """
    with open(PROCESSED_LOGS_PATH, 'a') as f:
        for log in processed_logs:
            f.write(log + "\n")

def parse_snort_logs(file_path):
    """
    Parses Snort JSON logs and updates the alert counts in Prometheus counters.
    """
    processed_logs = get_processed_logs()
    new_processed_logs = set()

    try:
        with open(file_path, 'r') as file:
            for line in file:
                log = line.strip()
                if log not in processed_logs:
                    try:
                        log_data = json.loads(log)
                        rule = log_data.get("rule", "unknown")

                        # Map rules to traffic type
                        if rule == "1:1000001:1":  # SSH brute force alert rule
                            ssh_brute_force.inc()
                        elif rule == "1:1000002:1":  # ssh connection detected
                            ssh_detected.inc()
                        else:
                            other_alert_counter.inc()

                        # Add to processed logs
                        new_processed_logs.add(log)
                    except json.JSONDecodeError:
                        # Skip malformed lines
                        continue

    except FileNotFoundError:
        print(f"Log file {file_path} not found.")
    except Exception as e:
        print(f"Error reading log file: {e}")
        
        
    # Update the processed logs file
    update_processed_logs(new_processed_logs)

@app.route('/metrics')
def metrics():
    """
    Expose metrics for Prometheus scraping.
    """
    # Parse Snort logs to update counters
    parse_snort_logs(SNORT_LOG_PATH)

    # Generate and return Prometheus metrics
    return Response(generate_latest(), mimetype="text/plain")

if __name__ == '__main__':
    # Run the Flask application
    app.run(host="0.0.0.0", port=8000)

