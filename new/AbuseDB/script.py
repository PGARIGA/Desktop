import sys
import requests
import pandas as pd

def check_ip_reputation(api_key, ip_address):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    response = requests.get(url, headers=headers)
    data = response.json()

    if response.status_code == 200:
        if data["data"]["abuseConfidenceScore"] > 0:
            return {
                "IP Address": ip_address,
                "Abuse Confidence Score": data['data']['abuseConfidenceScore'],
                "Country": data['data']['countryName'],
                "ISP": data['data']['isp'],
                "Usage Type": data['data']['usageType'],
                "Domain": data['data']['domain'],
                "Total Reports": data['data']['totalReports'],
                "Last Reported At": data['data']['lastReportedAt']
            }
        else:
            return {
                "IP Address": ip_address,
                "Abuse Confidence Score": 0,
                "Country": "",
                "ISP": "",
                "Usage Type": "",
                "Domain": "",
                "Total Reports": 0,
                "Last Reported At": ""
            }
    else:
        return {
            "IP Address": ip_address,
            "Abuse Confidence Score": -1,
            "Country": "",
            "ISP": "",
            "Usage Type": "",
            "Domain": "",
            "Total Reports": 0,
            "Last Reported At": ""
        }

# Read IP addresses from file
def read_ip_addresses(file_path):
    with open(file_path, "r") as file:
        ip_addresses = file.read().splitlines()
    return ip_addresses

# Check reputation for each IP address
def check_reputation_for_ip_addresses(api_key, ip_addresses):
    results = []
    for ip in ip_addresses:
        result = check_ip_reputation(api_key, ip)
        results.append(result)
    
    return results

# Export results to Excel
def export_to_excel(results, output_file):
    df = pd.DataFrame(results)
    df.to_excel(output_file, index=False)

# Get input file path, API key, and output file path from command-line arguments
if len(sys.argv) < 4:
    print("Please provide the input file path, API key, and output file path as command-line arguments.")
    sys.exit(1)

input_file = sys.argv[1]
api_key = sys.argv[2]
output_file = sys.argv[3]

ip_addresses = read_ip_addresses(input_file)
results = check_reputation_for_ip_addresses(api_key, ip_addresses)
export_to_excel(results, output_file)
