import json

# File path for the Snort JSON logs
SNORT_LOG_PATH = "/var/log/snort/alert_json.txt"

# Prometheus metrics counters
icmp_alert_counter = 0
ssh_brute_force_alert_counter = 0
ssh_alert_counter = 0
other_alert_counter = 0

def parse_snort_logs(file_path):
    """
    Parses Snort JSON logs and updates the alert counts, printing the results for debugging.
    """
    global ssh_brute_force_alert_counter, ssh_alert_counter, icmp_alert_counter, other_alert_counter

    try:
        with open(file_path, 'r') as file:
            for line in file:
                try:
                    log = json.loads(line.strip())
                    rule = log.get("rule", "unknown")
                    print(f"Processing log: {rule}")  # Debugging log

                    # Map Snort rules to specific alert counters
                    if rule == "1:1000001:1":  # SSH brute force rule
                        ssh_brute_force_alert_counter += 1
                        print(f"SSH brute force alert detected. Total: {ssh_brute_force_alert_counter}")
                    elif rule == "1:1000002:1" or rule == "1:1000003:3":  # SSH connection rule
                        ssh_alert_counter += 1
                        print(f"SSH connection detected. Total: {ssh_alert_counter}")
                    elif rule == "1:1000004:1":  # ICMP alert rule
                        icmp_alert_counter += 1
                        print(f"ICMP alert detected. Total: {icmp_alert_counter}")
                    else:
                        other_alert_counter += 1
                        print(f"Other alert detected. Total: {other_alert_counter}")
                except json.JSONDecodeError:
                    # Skip malformed lines
                    continue
    except FileNotFoundError:
        print(f"Log file {file_path} not found.")
    except Exception as e:
        print(f"Error reading log file: {e}")

if __name__ == '__main__':
    # Run the function to parse Snort logs and print debug information
    print("Starting to parse Snort logs...")
    parse_snort_logs(SNORT_LOG_PATH)
    print("\nFinished parsing Snort logs.")
    print(f"Total ICMP alerts: {icmp_alert_counter}")
    print(f"Total SSH brute force alerts: {ssh_brute_force_alert_counter}")
    print(f"Total SSH alerts: {ssh_alert_counter}")
    print(f"Total other alerts: {other_alert_counter}")
                                                        
