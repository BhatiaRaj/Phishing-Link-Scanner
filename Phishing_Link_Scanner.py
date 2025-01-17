import re
import requests
from urllib.parse import urlparse

# Function to validate URL format
def validate_url(url):
    pattern = re.compile(
        r"^(http|https)://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(:\d+)?"
        r"(?:/?|[/?]\S+)$", re.IGNORECASE
    )
    return re.match(pattern, url) is not None

# Function to check URL against VirusTotal API
def check_url_reputation(url):
    api_key = ""  # Replace with your VirusTotal API key
    vt_url = f"https://www.virustotal.com/api/v3/urls"
    
    headers = {
        "x-apikey": api_key
    }
    
    try:
        # Encode URL to send to VirusTotal
        url_id = requests.utils.quote(url, safe="")
        response = requests.post(vt_url, headers=headers, data={"url": url})
        if response.status_code == 200:
            scan_result = response.json()
            malicious = scan_result['data']['attributes']['last_analysis_stats']['malicious']
            if malicious > 0:
                return "Malicious"
            return "Safe"
        else:
            return "Error: Unable to check URL reputation"
    except Exception as e:
        return f"Error: {e}"

# Function for heuristic analysis
def heuristic_analysis(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path

    # Heuristic checks
    if len(domain) > 50 or len(url) > 100:
        return "Suspicious"
    if re.search(r"(login|secure|bank|account|verify)", path, re.IGNORECASE):
        return "Suspicious"
    if "-" in domain or domain.startswith("www.") and domain.count(".") > 2:
        return "Suspicious"
    return "Safe"

# Main Phishing Link Scanner
def phishing_link_scanner(url):
    if not validate_url(url):
        return "Invalid URL"

    print("[*] Validating URL format... Passed")
    
    print("[*] Checking URL reputation...")
    reputation_result = check_url_reputation(url)
    print(f"Reputation Check Result: {reputation_result}")
    
    print("[*] Performing heuristic analysis...")
    heuristic_result = heuristic_analysis(url)
    print(f"Heuristic Analysis Result: {heuristic_result}")
    
    # Combine results
    if reputation_result == "Malicious" or heuristic_result == "Suspicious":
        return "Warning: The URL is potentially malicious!"
    return "The URL appears safe."

# Test the scanner
if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ").strip()
    result = phishing_link_scanner(test_url)
    print(f"\nFinal Verdict: {result}")
