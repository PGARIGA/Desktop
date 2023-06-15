import requests
import json

def check_ip_reputation(ip_address, api_key):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.text)
        is_malicious = data['data']['isWhitelisted'] == 0 and data['data']['abuseConfidenceScore'] >= 75
        return is_malicious, data['data']['abuseConfidenceScore']
    else:
        return None

# API Key from AbuseIPDB
api_key = '6a501c5ce5a6cedeac65326b9b8fe38f683633f0d5db4f67a6d6f5810b885eb9d77226221ea665f2'

# List of IP addresses to check
ip_addresses = ['185.224.128.141', '91.179.220.6', '219.140.143.211', '211.107.122.207', '175.97.174.175', '167.172.82.109', '8.219.252.14', '112.167.52.238', '176.166.135.18', '220.78.241.152', '125.139.60.143', '185.44.82.13', '170.64.154.26', '38.60.196.38', '199.76.38.123', '1.212.165.165', '69.50.128.171', '211.224.63.169', '95.255.47.183', '103.50.148.20', '64.62.197.239', '222.251.143.248', '211.60.226.6', '81.68.102.224', '139.59.36.246', '178.215.193.20', '121.187.152.29', '221.155.143.109', '175.214.126.52', '84.54.50.72', '175.210.79.211', '64.62.197.150', '36.139.66.68', '177.32.224.251', '97.97.116.168', '112.172.162.85', '51.75.194.10', '45.66.230.191', '193.35.18.61', '39.123.146.61', '64.62.197.162', '42.51.45.33', '202.90.198.2', '36.139.63.59', '119.206.18.13', '39.164.42.238', '61.174.36.23', '122.116.121.24', '23.94.181.24', '170.64.156.21', '175.205.9.60', '151.52.109.253', '170.210.208.108', '211.185.129.203', '175.195.114.196', '59.120.141.39', '208.124.163.43', '119.193.227.138', '154.117.199.12', '123.235.109.207', '218.156.128.226', '171.15.131.182', '64.62.197.179', '146.59.233.75', '185.5.157.165', '196.218.238.188', '115.22.247.76', '101.89.219.59', '210.99.110.117', '221.150.47.198', '175.209.255.184', '82.157.41.186', '59.0.241.169', '103.36.192.42', '178.128.155.156', '211.250.230.188', '27.130.113.98', '222.186.21.35', '54.183.195.159', '59.2.52.122', '174.96.50.187', '80.94.95.18', '14.40.18.223', '112.165.49.140', '159.223.208.29', '109.195.194.123', '220.135.134.88', '218.147.235.177', '125.135.30.252', '221.165.59.190', '209.38.238.144', '211.57.20.18', '104.182.5.184', '121.187.229.137', '124.223.107.190', '43.130.43.134', '50.250.34.202', '124.222.19.142', '36.91.178.178', '188.171.35.7', '61.80.82.159', '222.117.54.198', '203.132.182.23', '143.198.204.177', '167.99.128.78', '59.25.112.205', '66.183.157.210', '125.134.168.105', '183.146.30.163', '176.96.138.216', '203.199.243.13', '20.219.149.128', '36.7.147.63', '101.206.243.239', '51.222.137.64', '2.38.3.125']

for ip in ip_addresses:
    result = check_ip_reputation(ip, api_key)
    if result is not None:
        is_malicious, confidence_score = result
        if is_malicious:
            print(f'IP address {ip} is potentially malicious with a confidence score of {confidence_score}')
        else:
            print(f'IP address {ip} is not malicious with a confidence score of {confidence_score}')
    else:
        print(f'Failed to check reputation for IP address {ip}')


