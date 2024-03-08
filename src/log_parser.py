import re
from collections import Counter
import logging

# Configure logging
logging.basicConfig(filename='security_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

def parse_apache_log(log_file):
    """
    Parse Apache access log file and extract relevant information.
    """
    log_entries = []
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[([^\]]+)\] "(GET|POST) ([^"]+)" (\d+) (\d+)'
    try:
        with open(log_file, 'r') as file:
            for line in file:
                match = re.match(pattern, line)
                if match:
                    ip_address = match.group(1)
                    timestamp = match.group(2)
                    method = match.group(3)
                    url = match.group(4)
                    status_code = match.group(5)
                    bytes_sent = match.group(6)
                    
                    log_entries.append({
                        'ip_address': ip_address,
                        'timestamp': timestamp,
                        'method': method,
                        'url': url,
                        'status_code': status_code,
                        'bytes_sent': bytes_sent
                    })
    except FileNotFoundError:
        logging.error(f"Log file '{log_file}' not found.")
        raise
    except Exception as e:
        logging.error(f"Error occurred while parsing log file '{log_file}': {e}")
        raise
    
    return log_entries

def analyze_log(log_entries):
    """
    Analyze parsed log entries for security threats.
    """
    security_issues = []
    try:
        for entry in log_entries:
            # Example analysis rules (you can customize these based on your security requirements)
            if entry['status_code'] == '400':
                security_issues.append(f"Bad request: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '401':
                security_issues.append(f"Unauthorized access attempt: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '403':
                security_issues.append(f"Forbidden access: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '404':
                security_issues.append(f"Potential 404 error: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '408':
                security_issues.append(f"Request timeout: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '301':
                security_issues.append(f"Permanent redirection: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '302':
                security_issues.append(f"Temporary redirection: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '500':
                security_issues.append(f"Potential server error: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '502':
                security_issues.append(f"Bad gateway: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '503':
                security_issues.append(f"Service unavailable: {entry['url']} accessed by {entry['ip_address']}")
            elif entry['status_code'] == '504':
                security_issues.append(f"Gateway timeout: {entry['url']} accessed by {entry['ip_address']}")
            
        # Extract IP addresses from log entries
        ip_addresses = [entry['ip_address'] for entry in log_entries]
        # Count occurrences of each IP address
        ip_counts = Counter(ip_addresses)
        # Analyze IP addresses for suspicious activity
        for ip, count in ip_counts.items():
            if count >= 10:
                security_issues.append(f"Suspicious activity detected from IP: {ip}. Access count: {count}")
    except Exception as e:
        logging.error(f"Error occurred while analyzing log entries: {e}")
        raise
        
    return security_issues

def generate_report(security_issues):
    """
    Generate a report summarizing analysis results.
    """
    report = "Security Analysis Report:\n\n"
    
    if security_issues:
        report += "Security issues found:\n"
        for issue in security_issues:
            report += f"- {issue}\n"
    else:
        report += "No security issues found.\n"
    
    # Include actionable insights and recommendations here
    
    return report

# Main function
def main():
    try:
        # Parse log file
        apache_log_file = 'Lumberjack/samples/sample1_access.log'
        parsed_entries = parse_apache_log(apache_log_file)
        
        # Analyze log data
        security_issues = analyze_log(parsed_entries)
        
        # Generate report
        report = generate_report(security_issues)
        print(report)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print("An error occurred. Please check the log file for details.")

if __name__ == "__main__":
    main()


