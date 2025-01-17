# Phishing Link Scanner

## Overview
This Python script is designed to scan and analyze URLs to determine whether they are potentially malicious or safe. The tool combines URL validation, VirusTotal reputation checks, and heuristic analysis to provide a comprehensive assessment of a given URL.

---

## Features
1. **URL Validation**: Checks if the input URL follows a valid format.
2. **VirusTotal API Integration**: Queries VirusTotal to fetch reputation analysis of the URL.
3. **Heuristic Analysis**: Performs basic checks to detect suspicious patterns in the URL structure.
4. **Final Verdict**: Combines results from VirusTotal and heuristic analysis to flag potentially malicious URLs.

---

## Prerequisites
- **Python 3.x**: Make sure you have Python installed on your system.
- **Requests Library**: Install the `requests` library for handling API calls.

```bash
pip install requests
```

---

## How It Works
1. **Input a URL**: The user provides a URL to analyze.
2. **URL Validation**: The script uses regex to validate the format of the URL.
3. **Reputation Check**:
   - Encodes the URL.
   - Sends the URL to VirusTotal’s API.
   - Analyzes the response to determine if the URL is flagged as malicious.
4. **Heuristic Analysis**:
   - Parses the URL to extract the domain and path.
   - Looks for suspicious patterns such as long domains, the use of sensitive keywords (e.g., `login`, `secure`), and other phishing indicators.
5. **Final Verdict**:
   - If either VirusTotal flags the URL as malicious or heuristic analysis identifies suspicious patterns, the URL is deemed potentially malicious.
   - Otherwise, the URL is marked as safe.

---

## Usage

1. **Run the Script**:
   ```bash
   python phishing_link_scanner.py
   ```

2. **Enter a URL**:
   When prompted, enter the URL you want to analyze.

3. **View Results**:
   The script outputs the results of each check and provides a final verdict.

---

## Example Output

### Input:
```
https://example.com/login
```

### Output:
```
[*] Validating URL format... Passed
[*] Checking URL reputation...
Reputation Check Result: Safe
[*] Performing heuristic analysis...
Heuristic Analysis Result: Suspicious

Final Verdict: Warning: The URL is potentially malicious!
```

---

## Configuration
### VirusTotal API Key
Replace the placeholder API key in the script with your own VirusTotal API key:
```python
api_key = "YOUR_VIRUSTOTAL_API_KEY"
```

To obtain an API key, create a free account on VirusTotal and access your API key from the user dashboard.

---

## Limitations
1. **Dependency on VirusTotal**: Requires a valid VirusTotal API key and internet connectivity.
2. **Basic Heuristic Analysis**: May not detect advanced phishing techniques or perfectly legitimate URLs with misleading content.

---

## Contributing
Feel free to submit issues or pull requests to improve the functionality or accuracy of this script.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Disclaimer
This tool is for educational and informational purposes only. Always verify URLs and use caution when clicking on links. The author is not responsible for any misuse of this tool.

