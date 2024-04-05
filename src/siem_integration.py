import json
import requests

def send_to_splunk(log_data, token, splunk_url):
    """
    Send log data to Splunk using HTTP Event Collector (HEC).
    """
    headers = {
        'Authorization': f'Splunk {token}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'sourcetype': '_json',
        'event': log_data
    }
    
    response = requests.post(splunk_url, headers=headers, data=json.dumps(payload))
    
    if response.status_code == 200:
        print("Log data sent to Splunk successfully.")
    else:
        print(f"Failed to send log data to Splunk. Status code: {response.status_code}")

# Example usage
splunk_token = '874eb878-05ee-479a-9e84-09c57e270903'
splunk_url = 'https://prd-p-it8vg.splunkcloud.com/en-US/manager/launcher/adddatamethods/success'

log_data = {
    'message': 'Sample log message sent to Splunk',
    'source': 'my_script',
    'host': 'localhost'
}

send_to_splunk(log_data, splunk_token, splunk_url)
