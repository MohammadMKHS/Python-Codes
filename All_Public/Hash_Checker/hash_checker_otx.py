import requests
import json
import time
import re
import sys
import webbrowser
import os
from datetime import datetime

# --- AlienVault OTX API Configuration ---
# IMPORTANT: Your AlienVault OTX API Key
ALIENVAULT_OTX_API_KEY = "079ae73a74f0ff57a408c5137f3bb4b55b17b99051a568daa21af1f33b893c75"
ALIENVAULT_OTX_FILE_BASE_URL = "https://otx.alienvault.com/api/v1/indicators/file/"
ALIENVAULT_OTX_PULSE_BASE_URL = "https://otx.alienvault.com/api/v1/pulses/"

# --- Helper function to determine hash type ---
def get_hash_type(hash_value):
    """Determines the type of hash (MD5, SHA1, SHA256) based on its length."""
    if not isinstance(hash_value, str):
        return None
    hash_len = len(hash_value)
    if not re.fullmatch(r'^[a-fA-F0-9]+$', hash_value):
        return None # Not a valid hex string
    if hash_len == 32:
        return "MD5"
    elif hash_len == 40:
        return "SHA1"
    elif hash_len == 64:
        return "SHA256"
    return None

def check_hash_reputation_otx(hash_value):
    """
    Checks the reputation of a given file hash using the AlienVault OTX API
    and fetches associated indicators from pulses.
    """
    hash_type = get_hash_type(hash_value)
    if not hash_type:
        return {"error": "Invalid hash format. Please enter a valid MD5, SHA1, or SHA256 hash."}

    if not ALIENVAULT_OTX_API_KEY:
        return {"error": "Threat Intelligence API key is not configured. Please open the script and set ALIENVAULT_OTX_API_KEY."}

    headers = {
        "X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY,
        "Accept": "application/json"
    }

    # 1. Get general info about the hash (including associated pulses)
    file_info_url = f"{ALIENVAULT_OTX_FILE_BASE_URL}{hash_value}/general"
    print(f"[*] Querying Threat Intelligence for {hash_type} hash: {hash_value}...")

    file_data = {}
    pulses = []
    
    try:
        response = requests.get(file_info_url, headers=headers, timeout=15)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        file_data = response.json()

        if response.status_code == 404:
            return {"status": "not_found", "message": "Hash not found in the Threat Intelligence database."}
        elif "error" in file_data:
            return {"error": f"Threat Intelligence API error during general lookup: {file_data['error']}"}
        
        pulses = file_data.get("pulse_info", {}).get("pulses", [])

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 401 or status_code == 403:
            return {"error": "Unauthorized: Invalid or missing API key, or access denied."}
        elif status_code == 429:
            return {"error": "Too Many Requests: API rate limit exceeded. Please wait and try again."}
        else:
            return {"error": f"HTTP error {status_code} during general lookup: {e.response.text}"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error: Could not connect to Threat Intelligence. Check your internet connection."}
    except requests.exceptions.Timeout:
        return {"error": "Timeout Error: Request to Threat Intelligence timed out."}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON response from Threat Intelligence API during general lookup."}
    except Exception as e:
        return {"error": f"An unexpected error occurred during general lookup: {e}"}

    verdict = "Unknown"
    if pulses:
        verdict = "MALICIOUS (Associated with known threats)"
    else:
        verdict = "CLEAN (No known malicious association)"
        # If no pulses, we can return early as there will be no IOCs from pulses
        return {
            "status": "success",
            "hash": hash_value,
            "hash_type": hash_type,
            "verdict": verdict,
            "message": "This hash was not found to be associated with any known threat intelligence pulses.",
            "md5": file_data.get("md5", "N/A"),
            "sha1": file_data.get("sha1", "N/A"),
            "sha256": file_data.get("sha256", "N/A"),
            "file_size": file_data.get("file_size", "N/A"),
            "file_type": file_data.get("file_type", "N/A"),
            "malware_family": file_data.get("malware_family", "N/A"),
            "first_submission_date": datetime.fromtimestamp(file_data.get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if file_data.get("first_submission_date") else "N/A",
            "last_analysis_date": datetime.fromtimestamp(file_data.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if file_data.get("last_analysis_date") else "N/A",
            "related_iocs": {
                "ips": [], "domains": [], "hashes": [], "urls": [], "emails": [], "cves": [], "others": []
            }
        }


    # 2. If pulses found, fetch indicators for each pulse
    all_ip_iocs = set()
    all_domain_iocs = set()
    all_hash_iocs = set()
    all_url_iocs = set()
    all_email_iocs = set()
    all_cve_iocs = set()
    all_other_iocs = set()

    detailed_pulse_info = []

    for pulse in pulses:
        pulse_id = pulse.get("id")
        if not pulse_id:
            continue

        pulse_indicators_url = f"{ALIENVAULT_OTX_PULSE_BASE_URL}{pulse_id}/indicators"
        print(f"[*] Fetching indicators for pulse ID: {pulse_id}...")
        try:
            pulse_response = requests.get(pulse_indicators_url, headers=headers, timeout=15)
            pulse_response.raise_for_status()
            pulse_indicator_data = pulse_response.json()

            for indicator in pulse_indicator_data.get("results", []):
                indicator_type = indicator.get("type")
                indicator_value = indicator.get("indicator")

                if not indicator_type or not indicator_value:
                    continue

                if indicator_type in ["IPv4", "IPv6"]:
                    all_ip_iocs.add(indicator_value)
                elif indicator_type in ["Domain", "Hostname"]:
                    all_domain_iocs.add(indicator_value)
                elif indicator_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]:
                    all_hash_iocs.add(indicator_value)
                elif indicator_type == "URL":
                    all_url_iocs.add(indicator_value)
                elif indicator_type == "Email":
                    all_email_iocs.add(indicator_value)
                elif indicator_type == "CVE":
                    all_cve_iocs.add(indicator_value)
                else:
                    all_other_iocs.add(f"{indicator_type}: {indicator_value}")

            detailed_pulse_info.append({
                "name": pulse.get("name", "N/A"),
                "id": pulse.get("id", "N/A"),
                "tlp": pulse.get("tlp", "N/A"),
                "description": pulse.get("description", "N/A"),
                "tags": pulse.get("tags", [])
            })

        except requests.exceptions.HTTPError as e:
            print(f"  [!] HTTP error fetching indicators for pulse {pulse_id}: {e}", file=sys.stderr)
        except requests.exceptions.ConnectionError:
            print(f"  [!] Connection error fetching indicators for pulse {pulse_id}.", file=sys.stderr)
        except requests.exceptions.Timeout:
            print(f"  [!] Timeout fetching indicators for pulse {pulse_id}.", file=sys.stderr)
        except json.JSONDecodeError:
            print(f"  [!] Invalid JSON response for pulse {pulse_id} indicators.", file=sys.stderr)
        except Exception as e:
            print(f"  [!] Unexpected error fetching indicators for pulse {pulse_id}: {e}", file=sys.stderr)
        
        time.sleep(1) # Be kind to the API, especially if fetching many pulses

    return {
        "status": "success",
        "hash": hash_value,
        "hash_type": hash_type,
        "verdict": verdict,
        "pulse_count": len(pulses),
        "pulse_details": detailed_pulse_info,
        "md5": file_data.get("md5", "N/A"),
        "sha1": file_data.get("sha1", "N/A"),
        "sha256": file_data.get("sha256", "N/A"),
        "file_size": file_data.get("file_size", "N/A"),
        "file_type": file_data.get("file_type", "N/A"),
        "malware_family": file_data.get("malware_family", "N/A"),
        "first_submission_date": datetime.fromtimestamp(file_data.get("first_submission_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if file_data.get("first_submission_date") else "N/A",
        "last_analysis_date": datetime.fromtimestamp(file_data.get("last_analysis_date", 0)).strftime('%Y-%m-%d %H:%M:%S') if file_data.get("last_analysis_date") else "N/A",
        "related_iocs": {
            "ips": sorted(list(all_ip_iocs)),
            "domains": sorted(list(all_domain_iocs)),
            "hashes": sorted(list(all_hash_iocs)),
            "urls": sorted(list(all_url_iocs)),
            "emails": sorted(list(all_email_iocs)),
            "cves": sorted(list(all_cve_iocs)),
            "others": sorted(list(all_other_iocs))
        }
    }

def generate_html_report_hash(hash_analysis_result):
    """
    Generates an HTML report for the hash analysis result, using existing CSS.
    """
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    queried_hash = hash_analysis_result.get('hash', 'N/A')
    report_title = f"XenoByte Hash Analysis Report: {queried_hash}"

    # --- CSS Styling (Copied from Apt_Checkout.py) ---
    custom_css = """
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto:wght@400;700&display=swap');

    :root {
      --bg-color: #0a0a0a;
      --box-color: #121212;
      --text-color: #00f5d4; /* Your accent greenish-blue */
      --accent: #00ff88;    /* Your bright green accent */
      --footer-bg: #111;
      --footer-text: #ccc;
      --input-bg: #1e1e1e;
      --input-border: #00f5d4;
      --table-header-bg: #008855; /* Darker accent for table headers */
    }

    body.light-theme {
      --bg-color: #f9f9f9;
      --box-color: #ffffff;
      --text-color: #111;
      --accent: #00c47a;
      --footer-bg: #eaeaea;
      --footer-text: #333;
      --input-bg: #f0f0f0;
      --input-border: #00c47a;
      --table-header-bg: #009966;
    }

    html, body {
      min-height: 100vh;
      margin: 0;
      padding: 0;
      font-family: 'Roboto', sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      display: flex;
      flex-direction: column;
      transition: background-color 0.4s, color 0.4s;
    }
    .header {
        text-align: center;
        padding: 20px;
        background-color: var(--box-color);
        border-bottom: 2px solid var(--accent);
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        z-index: 10;
        position: sticky;
        top: 0;
    }
    h1 {
        margin: 0;
        color: var(--text-color);
        font-family: 'Orbitron', sans-serif;
        font-size: 2.5em;
        text-shadow: 0 0 8px var(--accent);
    }
    .subtitle {
        color: var(--footer-text);
        font-size: 1.1em;
        margin-top: 5px;
    }

    .content-section {
        padding: 20px;
        width: 90%;
        margin: 20px auto;
        background-color: var(--box-color);
        border-radius: 10px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.4);
        line-height: 1.6;
        flex-grow: 1;
        box-sizing: border-box;
    }
    @media (min-width: 1400px) {
        .content-section {
            width: 80%;
        }
    }
    @media (max-width: 768px) {
        .content-section {
            width: 95%;
            padding: 15px;
        }
    }
    .content-section h2, .content-section h3, .content-section h4 {
        color: var(--accent);
        border-bottom: 1px solid var(--text-color);
        padding-bottom: 10px;
        margin-top: 30px;
        margin-bottom: 20px;
        font-family: 'Orbitron', sans-serif;
    }
    .content-section p, .content-section ul, .content-section table {
        margin-bottom: 10px;
        color: var(--footer-text);
    }
    .content-section ul {
        padding-left: 25px;
        list-style: disc;
    }
    .content-section ul li {
        margin-bottom: 8px;
    }
    .content-section a {
        color: var(--text-color);
        text-decoration: none;
    }
    .content-section a:hover {
        color: var(--accent);
        text-decoration: underline;
    }

    .xeno-footer {
      flex-shrink: 0;
      background: var(--footer-bg);
      color: var(--footer-text);
      text-align: center;
      font-family: 'Roboto', sans-serif;
      font-size: 0.95rem;
      border-top: 2px solid var(--accent);
      padding: 20px 10px;
      width: 100%;
      margin-top: 40px;
    }

    .xeno-footer a {
      color: var(--text-color);
      text-decoration: none;
      transition: color 0.3s ease;
    }

    .xeno-footer a:hover {
      color: var(--accent);
    }

    .toggle-theme {
      position: absolute;
      top: 20px;
      right: 20px;
      background-color: var(--box-color);
      color: var(--text-color);
      border: 2px solid var(--text-color);
      border-radius: 30px;
      padding: 6px 16px;
      font-size: 0.9rem;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s ease;
      z-index: 1000;
    }
    .toggle-theme:hover {
      background-color: var(--accent);
      color: #000;
      border-color: var(--accent);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
    }
    th, td {
        border: 1px solid var(--text-color);
        padding: 8px;
        text-align: left;
        word-break: break-all; /* Ensure long hashes/URLs break */
    }
    th {
        background-color: var(--table-header-bg);
        color: var(--box-color);
        font-family: 'Orbitron', sans-serif;
    }
    .verdict-malicious {
        color: #ff6347; /* Red for malicious */
        font-weight: bold;
        font-size: 1.2em;
    }
    .verdict-clean {
        color: #00cc00; /* Green for clean */
        font-weight: bold;
        font-size: 1.2em;
    }
    .error-message {
        color: #ff6347; /* Tomato red for errors */
        font-weight: bold;
    }
    """

    # --- JavaScript for theme toggling (Copied from Apt_Checkout.py) ---
    theme_toggle_js = """
    <script>
        function toggleTheme() {
            document.body.classList.toggle('light-theme');
            let isLight = document.body.classList.contains('light-theme');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
            document.getElementById('theme-toggle-button').textContent = isLight ? 'Dark Mode' : 'Light Mode';
        }

        // Apply theme on load
        document.addEventListener('DOMContentLoaded', (event) => {
            if (localStorage.getItem('theme') === 'light') {
                document.body.classList.add('light-theme');
                document.getElementById('theme-toggle-button').textContent = 'Dark Mode';
            } else {
                document.getElementById('theme-toggle-button').textContent = 'Light Mode';
            }
        });
    </script>
    """

    html_sections = []

    if hash_analysis_result.get("error"):
        html_sections.append(f"<h2 class='error-message'>Error: {hash_analysis_result['error']}</h2>")
    elif hash_analysis_result.get("status") == "not_found":
        html_sections.append(f"<h2>Analysis Result</h2><p>{hash_analysis_result['message']}</p>")
    elif hash_analysis_result.get("status") == "success":
        # Clear verdict at the top
        verdict_class = "verdict-malicious" if "MALICIOUS" in hash_analysis_result['verdict'] else "verdict-clean"
        html_sections.append(f"<h2>Hash Analysis Result</h2>")
        html_sections.append(f"<p><strong>Queried Hash:</strong> {hash_analysis_result['hash']} ({hash_analysis_result['hash_type']})</p>")
        html_sections.append(f"<p><strong>Overall Verdict:</strong> <span class=\"{verdict_class}\">{hash_analysis_result['verdict']}</span></p>")

        # Associated Pulses
        if hash_analysis_result.get("pulse_count", 0) > 0:
            html_sections.append(f"<h3>Associated Threat Intelligence Pulses ({hash_analysis_result['pulse_count']})</h3>")
            for i, pulse in enumerate(hash_analysis_result['pulse_details']):
                html_sections.append(f"<h4>Pulse {i+1}: {pulse['name']}</h4>")
                html_sections.append(f"<ul>")
                html_sections.append(f"<li><strong>ID:</strong> {pulse['id']}</li>")
                html_sections.append(f"<li><strong>TLP:</strong> {pulse['tlp']}</li>")
                if pulse['tags']:
                    html_sections.append(f"<li><strong>Tags:</strong> {', '.join(pulse['tags'])}</li>")
                html_sections.append(f"<li><strong>Description:</strong> {pulse['description']}</li>")
                # Removed direct OTX URL for privacy/simplicity as requested
                html_sections.append(f"<li><strong>View Details:</strong> <a href=\"https://otx.alienvault.com/pulse/{pulse['id']}\" target=\"_blank\">External Link</a></li>")
                html_sections.append(f"</ul>")
        else:
            html_sections.append(f"<p>{hash_analysis_result.get('message', 'No specific details available.')}</p>")


        # Related IOCs from Pulses
        related_iocs = hash_analysis_result.get("related_iocs", {})
        
        if any(related_iocs.values()): # Check if any IOC list is non-empty
            html_sections.append("<h2>Related Indicators of Compromise (IOCs) from Associated Intelligence</h2>")

            # Hashes
            if related_iocs.get('hashes'):
                html_sections.append("<h3>Hashes</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>Hash</th><th>Type</th></tr>")
                for h in related_iocs['hashes']:
                    hash_type_related = get_hash_type(h)
                    html_sections.append(f"<tr><td>{h}</td><td>{hash_type_related if hash_type_related else 'Unknown'}</td></tr>")
                html_sections.append("</table>")

            # IPs
            if related_iocs.get('ips'):
                html_sections.append("<h3>IP Addresses</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>IP Address</th></tr>")
                for ip in related_iocs['ips']:
                    html_sections.append(f"<tr><td>{ip}</td></tr>")
                html_sections.append("</table>")

            # Domains
            if related_iocs.get('domains'):
                html_sections.append("<h3>Domains</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>Domain</th></tr>")
                for domain in related_iocs['domains']:
                    html_sections.append(f"<tr><td>{domain}</td></tr>")
                html_sections.append("</table>")

            # URLs
            if related_iocs.get('urls'):
                html_sections.append("<h3>URLs</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>URL</th></tr>")
                for url in related_iocs['urls']:
                    html_sections.append(f"<tr><td><a href=\"{url}\" target=\"_blank\">{url}</a></td></tr>")
                html_sections.append("</table>")

            # Emails
            if related_iocs.get('emails'):
                html_sections.append("<h3>Email Addresses</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>Email</th></tr>")
                for email in related_iocs['emails']:
                    html_sections.append(f"<tr><td>{email}</td></tr>")
                html_sections.append("</table>")

            # CVEs
            if related_iocs.get('cves'):
                html_sections.append("<h3>CVEs (Common Vulnerabilities and Exposures)</h3>")
                html_sections.append("<table>")
                html_sections.append("<tr><th>CVE ID</th><th>Link</th></tr>")
                for cve in related_iocs['cves']:
                    html_sections.append(f"<tr><td>{cve}</td><td><a href=\"https://nvd.nist.gov/vuln/detail/{cve}\" target=\"_blank\">NVD Link</a></td></tr>")
                html_sections.append("</table>")

            # Other IOCs
            if related_iocs.get('others'):
                html_sections.append("<h3>Other Indicators</h3>")
                html_sections.append("<ul>")
                for other in related_iocs['others']:
                    html_sections.append(f"<li>{other}</li>")
                html_sections.append("</ul>")
        else:
            if "MALICIOUS" in hash_analysis_result['verdict']:
                html_sections.append("<p>No specific related indicators found within the associated threat intelligence pulses, beyond the initial hash association.</p>")


    full_html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        {custom_css}
    </style>
</head>
<body>
    <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Light Mode</button>
    <div class="header">
        <h1>{report_title}</h1>
        <p class="subtitle">Generated by XenoByte Threat Intelligence on {current_time}</p>
    </div>
    <div class="content-section">
        {''.join(html_sections)}
    </div>
    <footer class="xeno-footer">
        <p>&copy; {datetime.now().year} XenoByte Threat Intelligence. All rights reserved.</p>
        <p>Data provided by various threat intelligence sources.</p>
    </footer>
    {theme_toggle_js}
</body>
</html>
    """
    return full_html_content

# --- Main execution logic ---
if __name__ == "__main__":
    print("--- XenoByte Hash Analysis Tool ---")
    print("This script checks the reputation of a file hash (MD5, SHA1, or SHA256).")
    print("Ensure your Threat Intelligence API key is configured in the script.")
    print("-" * 30)

    input_hash = input("Enter the file hash (MD5, SHA1, or SHA256): ").strip()

    if not input_hash:
        print("[!] Hash cannot be empty. Exiting.")
        sys.exit(1)

    result = check_hash_reputation_otx(input_hash)

    # Generate and save HTML report
    print("\n[+] Generating HTML report...")
    html_report_content = generate_html_report_hash(result)

    report_filename = f"XenoByte_Hash_Report_{result.get('hash', 'unknown').replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report_content)
        print(f"[+] Report saved to: {report_filename}")

        # Open report in browser
        print(f"[+] Opening report in browser...")
        webbrowser.open(f"file://{os.path.abspath(report_filename)}")
        print("\n[+] Hash analysis complete. Report opened in browser.")
    except IOError as e:
        print(f"[ERROR] Failed to write report file: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while opening the report: {e}", file=sys.stderr)