import requests
import json
import subprocess
from elasticsearch_dsl import Search
from elasticsearch_dsl.connections import connections
from elasticsearch_dsl.aggs import Terms

# --- Configuration: AbuseIPDB API ---
# Replace with your actual API key from https://www.abuseipdb.com/
ABUSEIPDB_API_KEY = 'YOUR_API_KEY_HERE'
ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check'

# --- Elasticsearch Connection ---
# Modify the host if Elasticsearch is not running on localhost.
connections.create_connection(hosts=['localhost'])

def get_ip_reputation(ip_address, api_key):
    """
    Queries the AbuseIPDB API for the reputation of a single IP address.

    Args:
        ip_address (str): The IP address to check.
        api_key (str): Your AbuseIPDB API key.

    Returns:
        dict: The 'data' object from the API response on success,
              or a dictionary with an 'error' key on failure.
    """
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    try:
        response = requests.get(url=ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get('data', {})
        else:
            print(f"    [!] AbuseIPDB API Error: {response.status_code} {response.text}")
            return {"error": response.json().get('errors', [{}])[0].get('detail', 'Unknown API error')}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_top_attacker_ips(size=20):
    """
    Queries Elasticsearch to find the top attacker IPs across all honeypots.

    Args:
        size (int): The number of top attacker IPs to return.

    Returns:
        list: A list of tuples, where each tuple contains an IP address (str)
              and its corresponding attack count (int).
    """
    # Search across all indices matching the 'filebeat-*' pattern.
    s = Search(index="filebeat-*")
    # We only need aggregation results, so set the query size to 0.
    s = s.extra(size=0)

    # Create an aggregation bucket based on the standardized 'source.ip.keyword' field.
    s.aggs.bucket('top_attackers', Terms(field='source.ip.keyword', size=size, order={'_count': 'desc'}))

    # Execute the search query against Elasticsearch.
    response = s.execute()

    # Parse and return the aggregation results.
    return [(bucket.key, bucket.doc_count) for bucket in response.aggregations.top_attackers.buckets]

def block_ip(ip_address):
    """
    Blocks a given IP address using iptables if it's not already blocked.

    This function first checks if a DROP rule for the IP already exists.
    If not, it adds a new rule to the INPUT chain to drop all packets
    from that source IP.

    Args:
        ip_address (str): The IP address to block.
    """
    check_command = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    # Use subprocess.run for a more modern and secure way to execute shell commands.
    check_process = subprocess.run(check_command, capture_output=True, text=True)

    # A non-zero return code means the rule does not yet exist.
    if check_process.returncode != 0:
        print(f"  -> IP {ip_address} is not blocked. Adding to blacklist...")
        block_command = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        block_process = subprocess.run(block_command, capture_output=True, text=True)
        if block_process.returncode == 0:
            print(f"     [SUCCESS] Successfully blocked {ip_address}.")
        else:
            print(f"     [ERROR] Failed to block {ip_address}: {block_process.stderr}")
    else:
        print(f"  -> IP {ip_address} is already blocked. Skipping.")

# --- Main Script Logic ---
if __name__ == "__main__":
    print("Starting intelligent proactive defense script (v2.1)...")

    candidate_data = get_top_attacker_ips(size=20)

    if not candidate_data:
        print("No attacker IPs found in the logs.")
    else:
        print(f"Found {len(candidate_data)} candidates. Checking their reputation and our local threat level...")
        for ip, count in candidate_data:
            print("-" * 60)
            print(f"Analyzing IP: {ip} (Local Attack Count: {count})")

            reputation = get_ip_reputation(ip, ABUSEIPDB_API_KEY)

            if "error" in reputation:
                print(f"  [!] Could not get reputation data: {reputation['error']}")
                continue

            abuse_score = reputation.get('abuseConfidenceScore', 0)
            country = reputation.get('countryCode', 'N/A')

            print(f"  [+] Abuse Score: {abuse_score}%, Country: {country}")

            # Block IPs based on a composite scoring logic: a very high abuse score,
            # or a high score combined with a significant number of local attacks.
            if abuse_score >= 100 or (abuse_score >= 80 and count >= 50):
                print(f"  [!] High threat detected (Abuse Score: {abuse_score}%, Local Count: {count}). EXECUTE BLOCKING!")
                block_ip(ip)
            else:
                print(f"  [INFO] Threat level is below threshold. Sparing IP.")

    print("-" * 60)
    print("Script finished.")