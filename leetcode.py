import re
import csv
from collections import Counter

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10
LOG_FILE = 'sample.log'
CSV_OUTPUT_FILE = 'log_analysis_results.csv'

def parse_log_file(file_path):
    with open(file_path, 'r') as f:
        log_lines = f.readlines()

    ip_counts = Counter()
    endpoint_counts = Counter()
    failed_login_attempts = Counter()

    for line in log_lines:
        # Extract IP address
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else None

        # Extract HTTP method and endpoint
        endpoint_match = re.search(r'\"[A-Z]+\s([^\s]+)\sHTTP', line)
        endpoint = endpoint_match.group(1) if endpoint_match else None

        # Extract HTTP status code
        status_match = re.search(r'\"\s(\d{3})\s', line)
        status_code = int(status_match.group(1)) if status_match else None

        # Increment counts
        if ip:
            ip_counts[ip] += 1
        if endpoint:
            endpoint_counts[endpoint] += 1
        if status_code == 401:
            failed_login_attempts[ip] += 1

    return ip_counts, endpoint_counts, failed_login_attempts

def save_to_csv(ip_counts, endpoint_counts, suspicious_ips):
    with open(CSV_OUTPUT_FILE, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoint_counts.most_common(1):
            writer.writerow([endpoint, count])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Parse log file
    ip_counts, endpoint_counts, failed_login_attempts = parse_log_file(LOG_FILE)

    # Display Requests per IP
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20} {count:<15}")

    # Display Most Accessed Endpoint
    most_accessed = endpoint_counts.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect Suspicious Activity
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count:<20}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(ip_counts, endpoint_counts, suspicious_ips)
    print(f"\nResults saved to {CSV_OUTPUT_FILE}")

if __name__ == "__main__":
    main()
