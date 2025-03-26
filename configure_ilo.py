import json
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
CONFIG_FILE = "config.json"
IP_LIST_FILE = "ip_list.txt"
TIMEOUT = 2  # 2 seconds timeout
MAX_WORKERS = 10  # Process 10 servers at a time

def load_config():
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def load_ip_list():
    try:
        with open(IP_LIST_FILE, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading IP list: {e}")
        return []

def login_ilo(ip, username, password):
    url = f"https://{ip}/rest/v1/SessionService/Sessions"
    headers = {'Content-Type': 'application/json'}
    payload = {"UserName": username, "Password": password}
    
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code == 201:
            session_id = response.headers.get('X-Auth-Token')
            response_json = response.json()
            session_uri = response_json.get('OdataId', response_json.get('@odata.id'))

            if not session_uri:
                session_uri = response.headers.get('Location', '').replace(f"https://{ip}", "")
            
            if not session_id or not session_uri:
                print(f"Login failed for {ip}: Missing session ID or URI")
                return None, None

            print(f"Login successful for {ip}")
            return session_id, session_uri
        else:
            print(f"Login failed for {ip}: {response.status_code} - {response.text}")
            return None, None
    except Exception as e:
        print(f"Login error for {ip}: {e}")
        return None, None

def logout_ilo(ip, session_id, session_uri):
    if not session_id or not session_uri:
        return
    
    url = f"https://{ip}{session_uri}"
    headers = {'X-Auth-Token': session_id}

    try:
        requests.delete(url, headers=headers, verify=False, timeout=TIMEOUT)
    except Exception as e:
        print(f"Logout error for {ip}: {e}")

def set_sntp_servers_rest(ip, session_id, sntp_server_1, sntp_server_2, enable_sntp=True):
    url = f"https://{ip}/rest/v1/Managers/1/DateTime"
    headers = {
        'X-Auth-Token': session_id,
        'Content-Type': 'application/json'
    }

    payload_modern = {
        "StaticNTPServers": [sntp_server_1, sntp_server_2],
        "NTP": {
            "ProtocolEnabled": enable_sntp
        }
    }

    try:
        response = requests.patch(url, json=payload_modern, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code == 200:
            print(f"Successfully set SNTP servers (modern schema) on {ip}")
            return
        elif response.status_code == 400 and 'PropertyUnknown' in response.text:
            print(f"Modern schema not supported on {ip}, trying fallback...")
            payload_legacy = {
                "StaticNTPServers": [sntp_server_1, sntp_server_2]
            }
            response_fallback = requests.patch(url, json=payload_legacy, headers=headers, verify=False, timeout=TIMEOUT)
            if response_fallback.status_code == 200:
                print(f"Successfully set SNTP servers (legacy schema) on {ip}")
            else:
                print(f"Failed fallback SNTP set on {ip}: {response_fallback.status_code} - {response_fallback.text}")
        else:
            print(f"Failed to set SNTP servers on {ip}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error setting SNTP servers on {ip}: {e}")

def set_timezone(ip, session_id, timezone):
    url = f"https://{ip}/rest/v1/Managers/1/DateTime"
    headers = {
        'X-Auth-Token': session_id,
        'Content-Type': 'application/json'
    }
    payload = {
        "TimeZone": {
            "Name": timezone
        }
    }

    try:
        response = requests.patch(url, json=payload, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code == 200:
            print(f"Successfully set time zone to {timezone} on {ip}")
        else:
            print(f"Failed to set time zone on {ip}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error setting time zone on {ip}: {e}")

def reset_ilo(ip, session_id):
    headers = {
        'X-Auth-Token': session_id,
        'Content-Type': 'application/json'
    }

    url_modern = f"https://{ip}/rest/v1/Managers/1/Actions/Oem/Hp/HpiLO.Reset"
    payload_modern = {"Action": "Reset"}

    try:
        response = requests.post(url_modern, headers=headers, json=payload_modern, verify=False, timeout=TIMEOUT)
        if response.status_code in [200, 202]:
            print(f"iLO reset command (modern) sent successfully to {ip}")
            return
        elif response.status_code == 400 and 'ActionNotSupported' in response.text:
            print(f"Modern reset action not supported on {ip}, trying fallback...")
            url_fallback = f"https://{ip}/rest/v1/Managers/1/Reset"
            payload_fallback = {"ResetType": "ForceRestart"}
            response_fallback = requests.post(url_fallback, headers=headers, json=payload_fallback, verify=False, timeout=TIMEOUT)
            if response_fallback.status_code in [200, 202]:
                print(f"iLO reset command (fallback) sent successfully to {ip}")
                return
            elif response_fallback.status_code == 404:
                print(f"Fallback reset not supported, trying alternate legacy reset for {ip}...")
                url_legacy = f"https://{ip}/rest/v1/Managers/1/Actions/Manager.Reset"
                payload_legacy = {"Action": "Reset"}
                response_legacy = requests.post(url_legacy, headers=headers, json=payload_legacy, verify=False, timeout=TIMEOUT)
                if response_legacy.status_code in [200, 202]:
                    print(f"iLO reset command (legacy) sent successfully to {ip}")
                    return
                else:
                    print(f"Failed legacy reset on {ip}: {response_legacy.status_code} - {response_legacy.text}")
            else:
                print(f"Failed fallback iLO reset on {ip}: {response_fallback.status_code} - {response_fallback.text}")
        else:
            print(f"Failed to reset iLO on {ip}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error resetting iLO on {ip}: {e}")

def process_server(ip, login_username, login_password, sntp_server_1, sntp_server_2, timezone, enable_sntp):
    print(f"Processing {ip}")
    session_id, session_uri = login_ilo(ip, login_username, login_password)
    if session_id:
        try:
            set_sntp_servers_rest(ip, session_id, sntp_server_1, sntp_server_2, enable_sntp)
            set_timezone(ip, session_id, timezone)
            reset_ilo(ip, session_id)
            print(f"Waiting 10 seconds for iLO at {ip} to reboot...")
            time.sleep(10)
        finally:
            logout_ilo(ip, session_id, session_uri)
    else:
        print(f"Skipping configuration for {ip} due to login failure")

def main():
    config = load_config()
    if not config:
        return

    login_username = config.get('login_username')
    login_password = config.get('login_password')
    sntp_server_1 = config.get('sntp_server_1')
    sntp_server_2 = config.get('sntp_server_2')
    timezone = config.get('timezone')
    enable_sntp = config.get('enable_sntp', True)

    if not all([login_username, login_password, sntp_server_1, sntp_server_2, timezone]):
        print("Missing required configuration parameters")
        return

    ip_list = load_ip_list()
    if not ip_list:
        print("No IPs found in list")
        return

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                process_server,
                ip,
                login_username,
                login_password,
                sntp_server_1,
                sntp_server_2,
                timezone,
                enable_sntp
            ) for ip in ip_list
        ]

        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Thread execution error: {e}")

    print("\nProcessing complete")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")
