Security Log Analysis Script

Overview:
This Python script is designed to parse and analyze log files from web servers, such as Apache, to detect potential security threats and generate comprehensive reports with actionable insights. It leverages regular expressions for precise data extraction and customizable analysis rules to flag suspicious activity.

Features:
- Automated log file parsing and analysis for rapid threat detection and response.
- Integration of regular expressions to extract relevant information from log entries efficiently.
- Customizable analysis rules to flag potential security issues, including unauthorized access attempts and server errors.
- Generation of detailed reports summarizing analysis results and security threats.
- Scalability and adaptability to diverse log formats and data sources.

Usage:
1. Ensure Python is installed on your system.
2. Clone the repository or download the script file (`main.py`).
3. Run the script with the following command:
    ```
    python main.py <log_file_path>
    ```
    Replace `<log_file_path>` with the path to your Apache access log file.

Note:
- Since we're not using real locations, geographical analysis on IP addresses is not performed.
- Integration with SIEM (Security Information and Event Management) systems was attempted, but there was an issue when porting over the HEC (HTTP Event Collector) URL. Further investigation is required to resolve this issue.

License:
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
