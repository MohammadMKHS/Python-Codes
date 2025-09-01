import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timedelta, timezone
from playwright.sync_api import sync_playwright
import re
import sys # Import sys for stderr redirection
import argparse # Import argparse for command-line arguments

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"
BLOCKCHAIN_INFO_API = "https://blockchain.info/rawaddr/{address}?format=json"

API_DELAY_SECONDS = 5  # To respect rate limits for blockchain.info API

# --- Data Caching (to avoid refetching static data repeatedly) ---
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = [] # To store the full data for details like 'family'

# --- Helper Functions ---

def load_local_ransomware_addresses():
    """Loads known ransomware addresses from a local file."""
    global local_ransomware_addresses
    if not local_ransomware_addresses:
        try:
            # Create a dummy file if it doesn't exist for demonstration purposes
            if not os.path.exists(WALLETS_RANSOMWARE_FILE):
                with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
                    f.write("1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo\n")
                    f.write("1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s\n")
                    f.write("bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k\n")
                    f.write("bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p\n")
            with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
                local_ransomware_addresses = {line.strip() for line in f if line.strip()}
            print(f"Loaded {len(local_ransomware_addresses)} addresses from {WALLETS_RANSOMWARE_FILE}", file=sys.stderr)
        except FileNotFoundError:
            print(f"Warning: {WALLETS_RANSOMWARE_FILE} not found. Skipping local ransomware check.", file=sys.stderr)
        except Exception as e:
            print(f"Error loading {WALLETS_RANSOMWARE_FILE}: {e}", file=sys.stderr)
    return local_ransomware_addresses

def fetch_ransomwhere_data():
    """Fetches and parses data from the ransomwhe.re API."""
    global ransomware_api_addresses, ransomware_api_data
    if not ransomware_api_addresses: # Only fetch if not already cached
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...", file=sys.stderr)
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
            if data and "result" in data and isinstance(data["result"], list):
                ransomware_api_data = data["result"]
                ransomware_api_addresses = {entry["address"] for entry in ransomware_api_data if "address" in entry}
                print(f"Fetched {len(ransomware_api_addresses)} addresses from ransomwhe.re API.", file=sys.stderr)
            else:
                print(f"Warning: Unexpected data format from {RANSOMWARE_EXPORT_URL}", file=sys.stderr)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching from {RANSOMWARE_EXPORT_URL}: {e}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {RANSOMWARE_EXPORT_URL}: {e}", file=sys.stderr)
    return ransomware_api_addresses, ransomware_api_data

def get_blockchain_info(address):
    """Fetches blockchain data for a Bitcoin address from blockchain.info."""
    url = BLOCKCHAIN_INFO_API.format(address=address)
    print(f"Fetching blockchain data for {address} from blockchain.info...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS) # Respect API rate limits
        return data
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            print(f"Address {address} not found on blockchain.info.", file=sys.stderr)
        else:
            print(f"HTTP Error fetching blockchain data for {address}: {e}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Network Error fetching blockchain data for {address}: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from blockchain.info for {address}: {e}", file=sys.stderr)
    return None

def analyze_wallet_transactions(address, blockchain_data):
    """Analyzes wallet transactions based on defined rules."""
    analysis_results = {
        "blockchain_type": "Unknown",
        "balance_btc": 0,
        "total_transactions": 0,
        "last_transaction_time_utc": "N/A",
        "wallet_type_inferred": "Uncertain",
        "red_flags": [],
        "automated_transactions_detected": False, # 5s to 1min
        "extremely_rapid_transactions_detected": False, # < 5s
        "rapid_transactions_detected": False, # < 5min
        "frequent_transactions_detected": False, # < 5 days
        "automated_transactions_time_diff": "N/A", # To store the actual time diff if detected
        "dormant_for_over_a_year": False,
        "high_transaction_count": False,
        "large_amount_received": False,
        "dust_attack_pattern": False,
        "high_transaction_fee_detected": False,
    }

    if not blockchain_data:
        analysis_results["red_flags"].append("Could not retrieve blockchain data.")
        return analysis_results

    analysis_results["blockchain_type"] = "Bitcoin" # Assuming Bitcoin if blockchain.info works

    # Balance and Transaction Count (blockchain.info returns balance in satoshis)
    balance_satoshi = blockchain_data.get('final_balance', 0)
    analysis_results["balance_btc"] = balance_satoshi / 100_000_000.0
    
    txs = blockchain_data.get('txs', [])
    analysis_results["total_transactions"] = len(txs)

    if not txs:
        analysis_results["red_flags"].append("No transactions found for this address.")
        return analysis_results

    # Sort transactions by time (most recent first)
    txs.sort(key=lambda x: x.get('time', 0), reverse=True)

    # Last Transaction Time and Dormancy
    last_tx_time = txs[0].get('time')
    if last_tx_time:
        analysis_results["last_transaction_time_utc"] = datetime.fromtimestamp(last_tx_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        one_year_ago = datetime.now(timezone.utc) - timedelta(days=365)
        if datetime.fromtimestamp(last_tx_time, timezone.utc) < one_year_ago:
            analysis_results["dormant_for_over_a_year"] = True
            analysis_results["red_flags"].append("Dormant for over a year.")

    # Rule: High transaction count (exchange or mixer)
    if analysis_results["total_transactions"] > 500: # Threshold can be adjusted
        analysis_results["high_transaction_count"] = True
        analysis_results["wallet_type_inferred"] = "Potentially Exchange or Mixer"
        analysis_results["red_flags"].append(f"High transaction count ({analysis_results['total_transactions']}). Potentially an exchange or mixer.")
    elif analysis_results["total_transactions"] > 100:
        analysis_results["wallet_type_inferred"] = "Active Personal / Minor Service"
    else:
        analysis_results["wallet_type_inferred"] = "Personal Wallet" # Default if not very active

    # Automated Transactions (time between transactions) - Enhanced
    prev_tx_time = None
    for tx in txs:
        current_tx_time = tx.get('time')
        if prev_tx_time is not None and current_tx_time is not None:
            time_diff = abs(prev_tx_time - current_tx_time) # Difference in seconds
            
            if time_diff < 5: # Less than 5 seconds
                analysis_results["extremely_rapid_transactions_detected"] = True
                analysis_results["red_flags"].append(f"Extremely rapid transfers detected (< 5s between transactions), suggesting automation.")
            
            if 5 <= time_diff <= 60: # Between 5 seconds and 1 minute
                analysis_results["automated_transactions_detected"] = True
                analysis_results["automated_transactions_time_diff"] = f"{time_diff}s" # Store first instance
                analysis_results["red_flags"].append(f"Rapid transfers detected (5s-1min between transactions), suggesting automation.")

            if time_diff < 5 * 60: # Less than 5 minutes
                analysis_results["rapid_transactions_detected"] = True
                # No specific red flag message here if covered by more specific ones, but flag is set.
            
            if time_diff < 5 * 24 * 60 * 60: # Less than 5 days
                analysis_results["frequent_transactions_detected"] = True
                # No specific red flag message here.

        prev_tx_time = current_tx_time

    # Rule: Large amount received & High transaction fee & Dust attack pattern
    for tx in txs:
        tx_hash = tx.get('hash')
        outputs = tx.get('outputs', [])
        
        # Calculate received amount for *this* address in this transaction
        for out in outputs:
            if out.get('addr') == address:
                amount = out.get('value', 0)
                if amount > 10 * 100_000_000: # Example: over 10 BTC
                    analysis_results["large_amount_received"] = True
                    analysis_results["red_flags"].append(f"Large amount received ({amount / 100_000_000.0:.8f} BTC) in transaction {tx_hash}.")
                    
                # Dust attack pattern (if the queried address is the sender of dust)
                # This check assumes the queried address is part of the inputs, making it a sender.
                # 'rawaddr' doesn't directly give sender/receiver role per transaction easily.
                # We can check if *this* address has many small outputs *in a transaction it's involved in*.
                # This is a heuristic.
                if len(outputs) > 10: # More than 10 outputs in one transaction
                    small_outputs_count = 0
                    for op in outputs:
                        if op.get('value', 0) < 5000: # E.g., less than 5000 satoshis (0.00005 BTC)
                            small_outputs_count += 1
                    if small_outputs_count / len(outputs) > 0.8: # Over 80% are dust
                        analysis_results["dust_attack_pattern"] = True
                        analysis_results["red_flags"].append(f"Potential dust attack pattern (many tiny outputs) in transaction {tx_hash}.")

        # High transaction fee
        fee = tx.get('fee')
        if fee is not None:
            if fee > 500_000: # Over 0.005 BTC (500,000 satoshis)
                analysis_results["high_transaction_fee_detected"] = True
                analysis_results["red_flags"].append(f"High transaction fee detected (~{fee / 100_000_000.0:.5f} BTC) in transaction {tx_hash}.")

    # Address appears to be reused multiple times (low privacy)
    if analysis_results["total_transactions"] > 50: # Arbitrary threshold
         analysis_results["red_flags"].append("Address appears to be reused multiple times (low privacy).")

    return analysis_results

# --- NEW FUNCTION: Chainabuse Scraper ---
def scrape_chainabuse_address_reports(address: str) -> dict:
    """
    Scrapes all scam reports for a given cryptocurrency address from Chainabuse.

    Args:
        address (str): The cryptocurrency address to scrape.

    Returns:
        dict: A dictionary containing the total number of reports and a list of
              dictionaries, where each inner dictionary represents a scam report.
              Returns an empty dictionary if no reports are found or an error occurs.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed or configured for sync. Please install it: pip install playwright && playwright install", file=sys.stderr)
        return {"total_reports_count": 0, "reports": [], "error": "Playwright not installed/configured"}

    base_url = "https://chainabuse.com/address/"
    url = f"{base_url}{address}"
    
    all_reports_data = {
        "address": address,
        "url_scraped": url,
        "total_reports_count": 0,
        "reports": []
    }

    print(f"Fetching Chainabuse data from: {url}", file=sys.stderr)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) # Keep headless=True for integration
            page = browser.new_page()

            try:
                page.goto(url, timeout=60000)

                # Wait for the main content to load (total reports title or no reports message)
                try:
                    page.wait_for_selector("h3.create-ResultsSection__results-title, p:has-text('No reports found for this address.')", timeout=30000)
                except Exception as e:
                    print(f"Chainabuse: Initial page content wait failed: {e}", file=sys.stderr)
                    browser.close()
                    return all_reports_data

                # Extract Total Reports Count
                try:
                    total_reports_text_element = page.locator("h3.create-ResultsSection__results-title").first
                    if total_reports_text_element.count() > 0:
                        total_reports_text = total_reports_text_element.text_content().strip()
                        match = re.search(r'(\d+)\s+Scam Reports', total_reports_text)
                        if match:
                            all_reports_data["total_reports_count"] = int(match.group(1))
                    elif page.locator("p:has-text('No reports found for this address.')").count() > 0:
                        all_reports_data["total_reports_count"] = 0
                except Exception as e:
                    print(f"Chainabuse: Could not extract total reports count: {e}", file=sys.stderr)

                # Extract Individual Reports
                report_cards = page.locator(".create-ScamReportCard").all()
                
                if not report_cards and all_reports_data["total_reports_count"] > 0:
                    print(f"Chainabuse: Warning: Expected {all_reports_data['total_reports_count']} reports but found no report cards using '.create-ScamReportCard' selector.", file=sys.stderr)
                elif not report_cards and all_reports_data["total_reports_count"] == 0:
                    print(f"Chainabuse: No report cards found, which matches the reported total of 0 reports.", file=sys.stderr)

                for i, card in enumerate(report_cards):
                    report_details = {}

                    # 1. Scam Category
                    try:
                        category_element = card.locator("p.create-Text.type-body-lg-heavy.create-ScamReportCard__category-label").first
                        if category_element.count() > 0:
                            report_details["category"] = category_element.text_content().strip()
                    except Exception as e:
                        print(f"  Chainabuse: Error extracting category for report {i+1}: {e}", file=sys.stderr)
                        report_details["category"] = "N/A"

                    # 2. Description
                    try:
                        description_element = card.locator(".create-ScamReportCard__preview-description .create-LexicalViewer .create-Editor__paragraph span").first
                        if description_element.count() > 0:
                            report_details["description"] = description_element.text_content().strip()
                        else:
                            direct_description_element = card.locator(".create-ScamReportCard__preview-description .create-LexicalViewer .create-Editor__paragraph").first
                            if direct_description_element.count() > 0:
                                report_details["description"] = direct_description_element.text_content().strip()
                    except Exception as e:
                        print(f"  Chainabuse: Error extracting description for report {i+1}: {e}", file=sys.stderr)
                        report_details["description"] = "N/A"

                    # 3. Submitted by & Date
                    try:
                        submitted_info_container = card.locator(".create-ScamReportCard__submitted-info").first
                        if submitted_info_container.count() > 0:
                            full_submitted_text = submitted_info_container.text_content().strip()
                            
                            date_match = re.search(r'on\s+(.+)', full_submitted_text)
                            if date_match:
                                report_details["submitted_date"] = date_match.group(1).strip()
                            else:
                                report_details["submitted_date"] = "N/A"

                            submitter_match = re.search(r'Submitted by\s+([a-zA-Z0-9.-]+)', full_submitted_text)
                            if submitter_match:
                                report_details["submitted_by"] = submitter_match.group(1).strip()
                            else:
                                report_details["submitted_by"] = "chainabuse-system"
                    except Exception as e:
                        print(f"  Chainabuse: Error extracting submitted info for report {i+1}: {e}", file=sys.stderr)
                        report_details["submitted_by"] = "N/A"
                        report_details["submitted_date"] = "N/A"

                    # 4. Reported Addresses within THIS report card
                    reported_addresses_in_card = []
                    try:
                        address_elements = card.locator(".create-ReportedSection .create-ResponsiveAddress__text").all()
                        for addr_elem in address_elements:
                            reported_addresses_in_card.append(addr_elem.text_content().strip())
                    except Exception as e:
                        print(f"  Chainabuse: Error extracting reported addresses for report {i+1}: {e}", file=sys.stderr)
                    report_details["reported_addresses"] = reported_addresses_in_card

                    all_reports_data["reports"].append(report_details)

            except Exception as e:
                print(f"Chainabuse: An unexpected error occurred during scraping for address {address}: {e}", file=sys.stderr)
            finally:
                browser.close()
        
    except Exception as e:
        print(f"Chainabuse: Error initializing Playwright or browser: {e}", file=sys.stderr)
        all_reports_data["error"] = f"Playwright/Browser error: {e}"
    
    return all_reports_data

def generate_html_report(address, reputation_data):
    """Generates an HTML formatted reputation report. (Kept for direct script execution)"""
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    overall_reputation_class = "clean"
    overall_reputation_text = "🟢 LIKELY CLEAN / LOW RISK"

    if reputation_data['is_ransomware_local'] or reputation_data['is_ransomware_api'] or reputation_data['chainabuse_reports']['total_reports_count'] > 0:
        overall_reputation_class = "malicious"
        overall_reputation_text = "🔴 MALICIOUS / HIGH RISK"
    elif reputation_data['red_flags']:
        overall_reputation_class = "suspicious"
        overall_reputation_text = "🟠 SUSPICIOUS / MODERATE RISK"
    
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
    .content-section h2, .content-section h3 {
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
        margin-top: 0;
        margin-bottom: 0;
    }
    .content-section ul li {
        margin-bottom: 8px;
        padding-top: 2px;
        padding-bottom: 2px;
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
    }
    th {
        background-color: var(--accent);
        color: var(--box-color);
        font-family: 'Orbitron', sans-serif;
    }
    .error-message {
        color: #ff6347;
        font-weight: bold;
    }

    .reputation-score {
        font-size: 1.8em;
        font-weight: bold;
        text-align: center;
        padding: 15px;
        margin-bottom: 20px;
        border-radius: 5px;
        font-family: 'Orbitron', sans-serif;
    }
    .reputation-score.malicious {
        background-color: #3d0000;
        color: #ff4747;
        border: 2px solid #ff4747;
        box-shadow: 0 0 15px rgba(255, 71, 71, 0.5);
    }
    .reputation-score.suspicious {
        background-color: #3d3d00;
        color: #ffff47;
        border: 2px solid #ffff47;
        box-shadow: 0 0 15px rgba(255, 255, 71, 0.5);
    }
    .reputation-score.clean {
        background-color: #003d00;
        color: #47ff47;
        border: 2px solid #47ff47;
        box-shadow: 0 0 15px rgba(71, 255, 71, 0.5);
    }
    .info-item strong {
        color: var(--text-color);
    }
    .threat-detected {
        color: #ff4747;
        font-weight: bold;
    }
    .analysis-flag {
        color: #ffff47;
    }
    .analysis-clean {
        color: #47ff47;
    }
    .section-content {
        background-color: var(--box-color);
        border: 1px solid var(--accent);
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .chainabuse-report-card {
        background-color: #1a1a1a;
        border: 1px solid #00f5d4;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    .chainabuse-report-card h4 {
        color: #00ff88;
        margin-top: 0;
        margin-bottom: 10px;
        font-family: 'Orbitron', sans-serif;
        font-size: 1.2em;
    }
    .chainabuse-report-card p {
        margin-bottom: 5px;
        color: #ccc;
    }
    .chainabuse-report-card strong {
        color: #00f5d4;
    }
    .chainabuse-report-card ul {
        list-style: none;
        padding-left: 0;
    }
    .chainabuse-report-card ul li {
        margin-bottom: 3px;
    }
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Wallet Reputation Report - {address}</title>
        <style>
            {custom_css}
        </style>
    </head>
    <body>
        <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Light Mode</button>
        <div class="header">
            <h1>XenoByte Wallet Reputation Report</h1>
            <p class="subtitle">Analysis for Wallet Address: <strong>{address}</strong></p>
            <p class="subtitle">Generated: {current_time}</p>
        </div>
        <div class="content-section">

            <div class="reputation-score {overall_reputation_class}">
                Overall Reputation: {overall_reputation_text}
            </div>

            <h2>Basic Information</h2>
            <div class="section-content">
                <p class="info-item"><strong>Current Balance:</strong> {reputation_data['balance_btc']:.8f} BTC</p>
                <p class="info-item"><strong>Total Transactions:</strong> {reputation_data['total_transactions']}</p>
                <p class="info-item"><strong>Last Transaction:</strong> {reputation_data['last_transaction_time_utc']}</p>
                <p class="info-item"><strong>Blockchain Type:</strong> {reputation_data['blockchain_type']}</p>
                <p class="info-item"><strong>Inferred Wallet Type:</strong> {reputation_data['wallet_type_inferred']}</p>
            </div>

            <h2>Threat Intelligence Insights</h2>
            <div class="section-content">
                {
                    f'<p class="threat-detected">This cryptocurrency wallet has been identified as being involved in malicious cyber activities, including its use in ransomware attacks, malware operations, and the collection of illicit funds from victims, making it a critical indicator in threat intelligence investigations.' +
                    (f' Associated Family: <strong>{", ".join(reputation_data["ransomware_family_api"])}</strong>.' if reputation_data["ransomware_family_api"] else '') +
                    '</p>'
                    if reputation_data['is_ransomware_local'] or reputation_data['is_ransomware_api']
                    else '<p class="analysis-clean">This wallet has no known associations with ransomware or malware addresses in our current intelligence feeds.</p>'
                }
            </div>

            <h2>Behavioral & Pattern Analysis</h2>
            <div class="section-content">
                <ul>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Dormancy:</strong> Wallet has been dormant for over a year.' if reputation_data['dormant_for_over_a_year'] else '<span class="analysis-clean">✔</span> Wallet has been active within the last year.'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected extremely rapid transfers (< 5 seconds between transactions), highly suggestive of automation.' if reputation_data['extremely_rapid_transactions_detected'] else '<span class="analysis-clean">✔</span> No extremely rapid transaction patterns detected.'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected rapid transfers (< 5 minutes between transactions), suggesting automated or high-frequency activity.' if reputation_data['rapid_transactions_detected'] else '<span class="analysis-clean">✔</span> No rapid transaction patterns detected (within 5 minutes).'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Activity:</strong> Detected frequent transactions (< 5 days between transactions), indicating consistent activity.' if reputation_data['frequent_transactions_detected'] else '<span class="analysis-clean">✔</span> Transaction frequency appears normal (no consistent activity within 5 days).'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected very short time difference ({reputation_data["automated_transactions_time_diff"]}) between transactions (5s-1min range), suggesting automation.' if reputation_data['automated_transactions_detected'] else '<span class="analysis-clean">✔</span> No specifically identified automated transaction patterns (5s-1min).'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Activity:</strong> High transaction count detected ({reputation_data["total_transactions"]}). This wallet is potentially an exchange or mixer.' if reputation_data['high_transaction_count'] else f'<span class="analysis-clean">✔</span> Moderate transaction count ({reputation_data["total_transactions"]}).'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Activity:</strong> Large amount received detected in one or more transactions.' if reputation_data['large_amount_received'] else '<span class="analysis-clean">✔</span> No unusually large amounts received.'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Potential dust attack pattern (many tiny outputs) detected.' if reputation_data['dust_attack_pattern'] else '<span class="analysis-clean">✔</span> No dust attack patterns detected.'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> High transaction fee detected in one or more transactions.' if reputation_data['high_transaction_fee_detected'] else '<span class="analysis-clean">✔</span> Transaction fees appear normal.'}</li>
                    <li>{f'<span class="analysis-flag">⚠</span> <strong>Privacy:</strong> Address appears to be reused multiple times (low privacy).' if "Address appears to be reused multiple times (low privacy)." in reputation_data['red_flags'] else '<span class="analysis-clean">✔</span> Address reuse for privacy is not a significant concern based on current data.'}</li>
                </ul>
            </div>

            <h2>Chainabuse Reports</h2>
            <div class="section-content">
                <p><strong>Total Reports on Chainabuse:</strong> <a href="{reputation_data['chainabuse_reports']['url_scraped']}" target="_blank">{reputation_data['chainabuse_reports']['total_reports_count']}</a></p>
                {"<p>No reports found on Chainabuse for this address.</p>" if reputation_data['chainabuse_reports']['total_reports_count'] == 0 else ""}
                
                {"".join([
                    f"""
                    <div class="chainabuse-report-card">
                        <h4>Report {idx + 1}: {report.get('category', 'N/A')}</h4>
                        <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                        <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                        <p><strong>Reported Addresses in this report:</strong> {', '.join(report.get('reported_addresses', [])) if report.get('reported_addresses') else 'N/A'}</p>
                    </div>
                    """
                    for idx, report in enumerate(reputation_data['chainabuse_reports']['reports'])
                ])}
            </div>

        </div>
        <footer class="xeno-footer">
            <p>&copy; {datetime.now().year} XenoByte Threat Intelligence. All rights reserved.</p>
            <p>Data from various public and open-source intelligence feeds.</p>
        </footer>
        <script>
            function toggleTheme() {{
                document.body.classList.toggle('light-theme');
                let isLight = document.body.classList.contains('light-theme');
                localStorage.setItem('theme', isLight ? 'light' : 'dark');
                document.getElementById('theme-toggle-button').textContent = isLight ? 'Dark Mode' : 'Light Mode';
            }}

            document.addEventListener('DOMContentLoaded', (event) => {{
                if (localStorage.getItem('theme') === 'light') {{
                    document.body.classList.add('light-theme');
                    document.getElementById('theme-toggle-button').textContent = 'Dark Mode';
                }} else {{
                    document.getElementById('theme-toggle-button').textContent = 'Light Mode';
                }}
            }});
        </script>
    </body>
    </html>
    """
    return html_content

def run_analysis(address_to_check: str) -> dict:
    """
    Performs the wallet analysis and returns the results as a dictionary.
    This function replaces the main block when run via API.
    """
    # Initialize results
    reputation_data = {
        "blockchain_type": "Unknown",
        "balance_btc": 0,
        "total_transactions": 0,
        "last_transaction_time_utc": "N/A",
        "wallet_type_inferred": "Uncertain",
        "is_ransomware_local": False,
        "is_ransomware_api": False,
        "ransomware_family_api": [],
        "automated_transactions_detected": False,
        "extremely_rapid_transactions_detected": False,
        "rapid_transactions_detected": False,
        "frequent_transactions_detected": False,
        "automated_transactions_time_diff": "N/A",
        "dormant_for_over_a_year": False,
        "high_transaction_count": False,
        "large_amount_received": False,
        "dust_attack_pattern": False,
        "high_transaction_fee_detected": False,
        "red_flags": [],
        "chainabuse_reports": {
            "address": address_to_check,
            "url_scraped": "",
            "total_reports_count": 0,
            "reports": []
        }
    }

    # 1. Local Ransomware File Check
    local_wallets = load_local_ransomware_addresses()
    if address_to_check in local_wallets:
        reputation_data["is_ransomware_local"] = True
        reputation_data["red_flags"].append("Address found in local ransomware database.")

    # 2. Ransomware.re API Check
    api_wallets, full_api_data = fetch_ransomwhere_data()
    if address_to_check in api_wallets:
        reputation_data["is_ransomware_api"] = True
        reputation_data["red_flags"].append("Address found in Ransomwhere.re API.")
        for entry in full_api_data:
            if entry.get("address") == address_to_check:
                family = entry.get("family", "Unknown")
                if family and family != "Unknown" and family not in reputation_data["ransomware_family_api"]:
                    reputation_data["ransomware_family_api"].append(family)
    
    # 3. Blockchain Info Data (Transactions, Balance)
    blockchain_data = get_blockchain_info(address_to_check)
    if blockchain_data:
        reputation_data["blockchain_type"] = "Bitcoin"
        analysis_results = analyze_wallet_transactions(address_to_check, blockchain_data)
        for key, value in analysis_results.items():
            if key == "red_flags":
                reputation_data["red_flags"].extend(value)
            else:
                reputation_data[key] = value

    # 4. Chainabuse Reports
    print(f"\n[+] Starting Chainabuse report scraping for {address_to_check}...", file=sys.stderr)
    chainabuse_data = scrape_chainabuse_address_reports(address_to_check)
    reputation_data["chainabuse_reports"] = chainabuse_data
    if chainabuse_data["total_reports_count"] > 0:
        reputation_data["red_flags"].append(f"Found {chainabuse_data['total_reports_count']} scam report(s) on Chainabuse.")
        for report in chainabuse_data["reports"]:
            if "ransomware" in report.get("category", "").lower():
                reputation_data["red_flags"].append(f"Chainabuse report indicates Ransomware activity (Category: {report.get('category')}).")
    
    return reputation_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XenoByte Bitcoin Wallet Reputation Checker Tool")
    parser.add_argument("wallet_address", help="The Bitcoin wallet address to check.")
    parser.add_argument("--json-output", action="store_true", help="Output results as JSON to stdout.")

    args = parser.parse_args()

    address_to_check = args.wallet_address
    if not address_to_check:
        print("No address entered. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[+] Starting reputation analysis for {address_to_check}...", file=sys.stderr)

    reputation_data = run_analysis(address_to_check)

    if args.json_output:
        print(json.dumps(reputation_data, indent=2))
        sys.exit(0)
    else:
        report_filename = f"XenoByte_Wallet_Report_{address_to_check}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_html_report(address_to_check, reputation_data)
        
        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Report saved to: {report_filename}", file=sys.stderr)
            print(f"[+] Opening report in browser...", file=sys.stderr)
            webbrowser.open(f"file://{os.path.abspath(report_filename)}")
        except Exception as e:
            print(f"Error generating or opening HTML report: {e}", file=sys.stderr)
            sys.exit(1)

