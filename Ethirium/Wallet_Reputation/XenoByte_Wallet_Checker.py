import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timezone, timedelta
from playwright.sync_api import sync_playwright # Added for Chainabuse scraping
import re # Added for regex in Chainabuse scraping
import argparse # Added for command line argument parsing
import sys # Added for sys.stdout/stderr

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Etherscan APIs for Ethereum
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF" # Your provided API key

API_DELAY_SECONDS = 1 # Reduced delay for Etherscan to avoid hitting rate limits too quickly
MAX_RETRIES = 5
INITIAL_BACKOFF_DELAY = 2 # seconds

# --- Global Data Caching for Ransomware Data ---
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = [] # To store the full data for details like 'family'

# --- Helper Functions ---

def load_local_ransomware_addresses():
    """
    Loads known ransomware addresses from a local file.
    Note: These are currently Bitcoin addresses based on previous examples.
    For accurate Ethereum analysis, this file would need to contain Ethereum ransomware addresses.
    """
    global local_ransomware_addresses
    if not local_ransomware_addresses:
        try:
            # Create a dummy file if it doesn't exist for demonstration purposes
            if not os.path.exists(WALLETS_RANSOMWARE_FILE):
                with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
                    # Add example Bitcoin addresses from the user's desired report
                    # For a real ETH tool, these should be ETH addresses.
                    f.write("1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo\n")
                    f.write("1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s\n")
                    f.write("bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k\n")
                    f.write("bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p\n")
                    # Add some dummy ETH addresses for testing if needed
                    f.write("0xYourDummyETHAddress1Here\n") 
                    f.write("0xYourDummyETHAddress2Here\n")
            
            with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
                local_ransomware_addresses = {line.strip() for line in f if line.strip()}
            print(f"Loaded {len(local_ransomware_addresses)} addresses from {WALLETS_RANSOMWARE_FILE}", file=sys.stderr) # Print to stderr
        except FileNotFoundError:
            print(f"Warning: {WALLETS_RANSOMWARE_FILE} not found. Skipping local ransomware check.", file=sys.stderr)
        except Exception as e:
            print(f"Error loading {WALLETS_RANSOMWARE_FILE}: {e}", file=sys.stderr)
    return local_ransomware_addresses

def fetch_ransomwhere_data():
    """
    Fetches and parses data from the ransomwhe.re API.
    Note: This API typically provides Bitcoin ransomware addresses.
    For accurate Ethereum analysis, a similar Ethereum-specific threat intelligence feed would be needed.
    """
    global ransomware_api_addresses, ransomware_api_data
    if not ransomware_api_addresses: # Only fetch if not already cached
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...", file=sys.stderr) # Print to stderr
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=10)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
            if data and "result" in data and isinstance(data["result"], list):
                ransomware_api_data = data["result"]
                ransomware_api_addresses = {entry["address"] for entry in ransomware_api_data if "address" in entry}
                print(f"Fetched {len(ransomware_api_addresses)} addresses from ransomwhe.re API.", file=sys.stderr) # Print to stderr
            else:
                print(f"Warning: Unexpected data format from {RANSOMWARE_EXPORT_URL}", file=sys.stderr)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching from {RANSOMWARE_EXPORT_URL}: {e}", file=sys.stderr)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {RANSOMWARE_EXPORT_URL}: {e}", file=sys.stderr)
    return ransomware_api_addresses, ransomware_api_data

def make_etherscan_request(url, retries=MAX_RETRIES, backoff_delay=INITIAL_BACKOFF_DELAY):
    """Makes a request to Etherscan API with exponential backoff."""
    for i in range(retries):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            # Check Etherscan specific error status
            if data.get('status') == '0':
                error_message = data.get('message', 'Unknown Etherscan API error.')
                # Only print error message if it's not the last retry
                if i < retries - 1:
                    print(f"  Etherscan API returned error (attempt {i+1}/{retries}): {error_message}", file=sys.stderr)
                    time.sleep(backoff_delay * (2 ** i)) # Exponential backoff
                else:
                    print(f"  Etherscan API returned error after {retries} attempts: {error_message}", file=sys.stderr)
                continue # Retry
            
            time.sleep(API_DELAY_SECONDS) # Respect API rate limits
            return data
        except requests.exceptions.RequestException as e:
            # Only print error message if it's not the last retry
            if i < retries - 1:
                print(f"  Network error during Etherscan request (attempt {i+1}/{retries}): {e}", file=sys.stderr)
                time.sleep(backoff_delay * (2 ** i)) # Exponential backoff
            else:
                print(f"  Network error after {retries} attempts for {url}: {e}", file=sys.stderr)
                return None # Return None on final failure
        except json.JSONDecodeError as e:
            # Only print error message if it's not the last retry
            if i < retries - 1:
                print(f"  JSON decode error from Etherscan (attempt {i+1}/{retries}): {e}", file=sys.stderr)
                time.sleep(backoff_delay * (2 ** i)) # Exponential backoff
            else:
                print(f"  JSON decode error after {retries} attempts for {url}: {e}", file=sys.stderr)
                return None # Return None on final failure
    return None # Should only be reached if all retries fail and return None

def get_ethereum_address_info(address):
    """
    Fetches comprehensive blockchain data for an Ethereum address from Etherscan.
    Combines balance, normal transactions, and internal transactions.
    """
    print(f"Fetching Ethereum blockchain data for {address} from Etherscan...", file=sys.stderr) # Print to stderr
    address_data = {
        "balance": 0,
        "normal_transactions": [],
        "internal_transactions": [],
        "all_transactions": [] # To store combined and sorted transactions
    }

    try:
        # 1. Get Balance
        balance_url = f"{ETHERSCAN_BASE_URL}?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
        balance_data = make_etherscan_request(balance_url)
        if balance_data and balance_data.get('status') == '1' and balance_data.get('result') is not None:
            address_data["balance"] = int(balance_data['result']) # Balance in Wei

        # 2. Get Normal Transactions
        normal_tx_url = f"{ETHERSCAN_BASE_URL}?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
        normal_tx_data = make_etherscan_request(normal_tx_url)
        if normal_tx_data and normal_tx_data.get('status') == '1' and isinstance(normal_tx_data.get('result'), list):
            address_data["normal_transactions"] = normal_tx_data['result']

        # 3. Get Internal Transactions
        internal_tx_url = f"{ETHERSCAN_BASE_URL}?module=account&action=txlistinternal&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
        internal_tx_data = make_etherscan_request(internal_tx_url)
        if internal_tx_data and internal_tx_data.get('status') == '1' and isinstance(internal_tx_data.get('result'), list):
            address_data["internal_transactions"] = internal_tx_data['result']

        # Combine and sort all transactions by timestamp
        all_txs = []
        for tx in address_data["normal_transactions"]:
            tx['type'] = 'normal'
            all_txs.append(tx)
        for tx in address_data["internal_transactions"]:
            tx['type'] = 'internal'
            all_txs.append(tx)
        
        # Sort by 'timeStamp' (which is a string, convert to int for sorting)
        address_data["all_transactions"] = sorted(all_txs, key=lambda x: int(x.get('timeStamp', '0')), reverse=True)

    except Exception as e:
        print(f"An unexpected error occurred fetching Ethereum data for {address}: {e}", file=sys.stderr)
        return None
    
    return address_data

def analyze_ethereum_wallet_behavior(address: str, blockchain_data: dict = None, tx_timestamp: int = None):
    """
    Analyzes specific behavioral flags for an Ethereum address.
    Generates messages similar to the Bitcoin wallet report.
    """
    flags = []
    
    # Check local database (simulated)
    if address in local_ransomware_addresses:
        flags.append("Address found in local ransomware database.")
    
    # Check Ransomwhere.re API (simulated)
    if address in ransomware_api_addresses:
        flags.append("Address found in Ransomwhere.re API.")
        
    # Dormancy: If analyzing a specific transaction, check its timestamp.
    # If analyzing overall wallet, check the latest transaction timestamp from blockchain_data.
    effective_timestamp = tx_timestamp
    if not effective_timestamp and blockchain_data and blockchain_data.get('all_transactions'):
        # Get the latest transaction timestamp from the wallet's history
        latest_tx = blockchain_data['all_transactions'][0]
        effective_timestamp = int(latest_tx.get('timeStamp', '0'))

    one_year_ago = datetime.now(timezone.utc) - timedelta(days=365)
    if effective_timestamp and datetime.fromtimestamp(effective_timestamp, timezone.utc) < one_year_ago:
        flags.append("Dormant for over a year.")

    # In Ethereum, address reuse is common and not necessarily a red flag for illicit activity,
    # but it does imply lower privacy.
    # This flag will always be present for ETH wallets with > 1 transaction
    if blockchain_data and len(blockchain_data.get('all_transactions', [])) > 1:
        flags.append("Address appears to be reused (common for Ethereum, implies lower privacy).")

    # Behavioral flags if full blockchain_data for the address is available
    if blockchain_data:
        total_transactions = len(blockchain_data.get('all_transactions', []))
        
        # High transaction count
        if total_transactions > 1000: # High threshold for ETH contracts/exchanges
            flags.append("High transaction count detected (potentially exchange, smart contract, or high-frequency DApp user).")
        # No "Moderate transaction count" flag needed as it's the default if not high.

        # Automated/Rapid transactions (requires iterating through transactions)
        prev_tx_time = None
        extremely_rapid_detected = False # < 5s
        automated_detected = False       # 5s to 1min
        rapid_detected = False           # < 5min
        frequent_detected = False        # < 5 days
        automated_time_diff = "N/A"

        for tx in blockchain_data.get('all_transactions', []):
            current_tx_time = int(tx.get('timeStamp', '0'))
            if prev_tx_time is not None and current_tx_time is not None:
                time_diff = abs(prev_tx_time - current_tx_time) # Difference in seconds
                
                if time_diff < 5: 
                    extremely_rapid_detected = True
                elif 5 <= time_diff <= 60:
                    automated_detected = True
                    automated_time_diff = f"{time_diff}s"
                elif time_diff < 5 * 60:
                    rapid_detected = True
                elif time_diff < 5 * 24 * 60 * 60:
                    frequent_detected = True

            prev_tx_time = current_tx_time
        
        if extremely_rapid_detected:
            flags.append("Extremely rapid transfers detected (< 5s between transactions), suggesting automation.")
        if automated_detected:
            flags.append(f"Rapid transfers detected (5s-1min between transactions, e.g., {automated_time_diff}), suggesting automation.")
        if rapid_detected and not automated_detected and not extremely_rapid_detected:
            flags.append("Rapid transactions detected (< 5 minutes between transactions).")
        if frequent_detected and not rapid_detected and not automated_detected and not extremely_rapid_detected:
            flags.append("Frequent transactions detected (< 5 days between transactions).")

        # Large amount received & High transaction fee & Dust attack pattern (requires iterating through transactions)
        large_amount_received = False
        dust_attack_pattern = False
        high_transaction_fee_detected = False

        for tx in blockchain_data.get('all_transactions', []):
            tx_value_wei = int(tx.get('value', '0'), 10) # Value transferred in Wei
            gas_used = int(tx.get('gasUsed', '0'), 10) if 'gasUsed' in tx else 0 # From normal tx
            gas_price = int(tx.get('gasPrice', '0'), 10) if 'gasPrice' in tx else 0 # From normal tx
            
            # Check for large amount received (if the address is the 'to' address)
            if tx.get('to', '').lower() == address.lower():
                if tx_value_wei > 10 * 1e18: # Example: over 10 ETH
                    large_amount_received = True
            
            # High transaction fee (only for normal transactions, internal txs don't have direct fees)
            if tx.get('type') == 'normal' and gas_used and gas_price:
                actual_fee_wei = gas_used * gas_price
                if actual_fee_wei > 0.05 * 1e18: # Example: over 0.05 ETH for fee
                    high_transaction_fee_detected = True

            # Dust attack pattern (if the queried address is the sender of dust)
            if tx.get('from', '').lower() == address.lower() and tx_value_wei > 0 and tx_value_wei < 1e12: # Less than 0.000001 ETH (1 Gwei)
                dust_attack_pattern = True

        if large_amount_received:
            flags.append("Large amount received detected in one or more transactions.")
        if high_transaction_fee_detected:
            flags.append("High transaction fee detected in one or more transactions.")
        if dust_attack_pattern:
            flags.append("Potential dust attack pattern (very small outgoing transaction) detected.")

    return flags

def scrape_chainabuse_address_reports(address: str) -> dict:
    """
    Scrapes all scam reports for a given cryptocurrency address from Chainabuse
    using Playwright's synchronous API.
    """
    base_url = "https://chainabuse.com/address/"
    url = f"{base_url}{address}"
    
    all_reports_data = {
        "address": address,
        "url_scraped": url,
        "total_reports_count": 0,
        "reports": []
    }

    print(f"Fetching Chainabuse data from: {url}", file=sys.stderr) # Print to stderr

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True) # Keep headless=True for integration
            page = browser.new_page()

            page.goto(url, timeout=60000)

            # Wait for the main content to load (total reports title or no reports message)
            try:
                page.wait_for_selector("h3.create-ResultsSection__results-title, p:has-text('No reports found for this address.')", timeout=30000)
            except Exception as e:
                print(f"Chainabuse: Initial page content wait failed or no reports section: {e}", file=sys.stderr)
                # It's okay if no reports element found, it just means no reports
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
            
    return all_reports_data


def generate_ethereum_wallet_report(wallet_address, wallet_data):
    """
    Generates an HTML report for a given Ethereum wallet address,
    using the original Bitcoin wallet report's template and styling.
    """
    
    # Load ransomware data once for all checks
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    report_time_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # Overall wallet analysis
    overall_wallet_flags = analyze_ethereum_wallet_behavior(wallet_address, wallet_data)
    # Important: When generate_ethereum_wallet_report is called from the API, scrape_chainabuse_address_reports
    # will be called synchronously here. This is fine because the API handler will
    # execute the entire HTML generation in a separate thread/process if it's called
    # with generate_html_report=True.
    overall_wallet_chainabuse_info = scrape_chainabuse_address_reports(wallet_address)


    # Determine overall reputation for the wallet
    overall_reputation_class = "clean" # Default to clean
    overall_reputation_text = "🟢 LIKELY CLEAN / LOW RISK"

    is_ransomware_local = wallet_address in local_ransomware_addresses
    is_ransomware_api = wallet_address in ransomware_api_addresses
    ransomware_family_api = []
    if is_ransomware_api:
        for entry in ransomware_api_data:
            if entry.get("address") == wallet_address and entry.get("family"):
                ransomware_family_api.append(entry['family'])
        ransomware_family_api = list(set(ransomware_family_api)) # Remove duplicates

    if is_ransomware_local or is_ransomware_api or overall_wallet_chainabuse_info['total_reports_count'] > 0:
        overall_reputation_class = "malicious"
        overall_reputation_text = "🔴 MALICIOUS / HIGH RISK"
    elif overall_wallet_flags and len([flag for flag in overall_wallet_flags if "Dormant" not in flag and "reused" not in flag]) > 0:
        # Consider suspicious if there are other flags beyond just dormancy or reuse
        overall_reputation_class = "suspicious"
        overall_reputation_text = "🟠 SUSPICIOUS / MODERATE RISK"
    
    # Basic Wallet Info
    balance_eth = wallet_data.get('balance', 0) / 1e18
    total_transactions = len(wallet_data.get('all_transactions', []))
    last_tx_time_utc = "N/A"
    if wallet_data.get('all_transactions'):
        latest_tx_timestamp = int(wallet_data['all_transactions'][0].get('timeStamp', '0'))
        if latest_tx_timestamp:
            last_tx_time_utc = datetime.fromtimestamp(latest_tx_timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    inferred_wallet_type = "Uncertain" # Default to match Bitcoin report
    if total_transactions > 1000:
        inferred_wallet_type = "Potentially Exchange, Smart Contract, or High-Frequency DApp User"
    elif total_transactions > 200:
        inferred_wallet_type = "Active Personal / Service Wallet"
    elif total_transactions > 0:
         inferred_wallet_type = "Personal Wallet" # If there are some transactions, but not high.


    # --- Original Bitcoin Wallet Report CSS ---
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
    }
    th {
        background-color: var(--accent);
        color: var(--box-color);
        font-family: 'Orbitron', sans-serif;
    }
    .error-message {
        color: #ff6347; /* Tomato red for errors */
        font-weight: bold;
    }

    /* Specific styles for report items */
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
        color: #ff4747; /* Bright red for threats */
        font-weight: bold;
    }
    .analysis-flag {
        color: #ffff47; /* Bright yellow for warnings */
    }
    .analysis-clean {
        color: #47ff47; /* Bright green for positive checks */
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
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Wallet Reputation Report - {wallet_address[:10]}...</title>
        <style>
            {custom_css}
        </style>
    </head>
    <body class="light-theme">
        <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Dark Mode</button>
        <div class="header">
            <h1>XenoByte Wallet Reputation Report</h1>
            <p class="subtitle">Analysis for Wallet Address: <strong>{wallet_address}</strong></p>
            <p class="subtitle">Generated: {report_time_utc}</p>
        </div>
        <div class="content-section">

            <div class="reputation-score {overall_reputation_class}">
                Overall Reputation: {overall_reputation_text}
            </div>

            <h2>Basic Information</h2>
            <div class="section-content">
                <p class="info-item"><strong>Current Balance:</strong> {balance_eth:.8f} ETH</p>
                <p class="info-item"><strong>Total Transactions:</strong> {total_transactions}</p>
                <p class="info-item"><strong>Last Transaction:</strong> {last_tx_time_utc}</p>
                <p class="info-item"><strong>Blockchain Type:</strong> Ethereum</p>
                <p class="info-item"><strong>Inferred Wallet Type:</strong> {inferred_wallet_type}</p>
            </div>

            <h2>Threat Intelligence Insights</h2>
            <div class="section-content">
                {
                    f'<p class="threat-detected">This cryptocurrency wallet has been identified as being involved in malicious cyber activities, including its use in ransomware attacks, malware operations, and the collection of illicit funds from victims, making it a critical indicator in threat intelligence investigations.' +
                    (f' Associated Family: <strong>{", ".join(ransomware_family_api)}</strong>.' if ransomware_family_api else '') +
                    '</p>'
                    if is_ransomware_local or is_ransomware_api
                    else '<p class="analysis-clean">This wallet has no known associations with ransomware or malware addresses in our current intelligence feeds.</p>'
                }
            </div>

            <h2>Behavioral & Pattern Analysis</h2>
            <div class="section-content">
                <ul>
                    {
                        # Generate the list items based on analysis results
                        # These are designed to match the Bitcoin report's phrasing
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Dormancy:</strong> Wallet has been dormant for over a year.</li>' if "Dormant for over a year." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> Wallet has been active within the last year.</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected extremely rapid transfers (< 5 seconds between transactions), highly suggestive of automation.</li>' if "Extremely rapid transfers detected (< 5s between transactions), suggesting automation." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> No extremely rapid transaction patterns detected.</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected rapid transfers (< 5 minutes between transactions), suggesting automated or high-frequency activity.</li>' if "Rapid transactions detected (< 5 minutes between transactions)." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> No rapid transaction patterns detected (within 5 minutes).</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> Detected frequent transactions (< 5 days between transactions), indicating consistent activity.</li>' if "Frequent transactions detected (< 5 days between transactions)." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> Transaction frequency appears normal (no consistent activity within 5 days).</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected very short time difference ({[f.split("e.g., ")[1][:-2] for f in overall_wallet_flags if "Rapid transfers detected (5s-1min between transactions" in f][0]}) between transactions (5s-1min range), suggesting automation.</li>' if any("Rapid transfers detected (5s-1min between transactions" in f for f in overall_wallet_flags) else '<li><span class="analysis-clean">✔</span> No specifically identified automated transaction patterns (5s-1min).</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> High transaction count detected ({total_transactions}). This wallet is potentially an exchange, smart contract, or high-frequency DApp user.</li>' if "High transaction count detected (potentially exchange, smart contract, or high-frequency DApp user)." in overall_wallet_flags else f'<li><span class="analysis-clean">✔</span> Moderate transaction count ({total_transactions}).</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> Large amount received detected in one or more transactions.</li>' if "Large amount received detected in one or more transactions." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> No unusually large amounts received.</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Potential dust attack pattern (very small outgoing transaction) detected.</li>' if "Potential dust attack pattern (very small outgoing transaction) detected." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> No dust attack patterns detected.</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> High transaction fee detected in one or more transactions.</li>' if "High transaction fee detected in one or more transactions." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> Transaction fees appear normal.</li>') +
                        (f'<li><span class="analysis-flag">⚠</span> <strong>Privacy:</strong> Address appears to be reused (common for Ethereum, implies lower privacy).</li>' if "Address appears to be reused (common for Ethereum, implies lower privacy)." in overall_wallet_flags else '<li><span class="analysis-clean">✔</span> Address reuse for privacy is not a significant concern based on current data.</li>')
                    }
                </ul>
            </div>

            <h2>Chainabuse Reports</h2>
            <div class="section-content">
                <p><strong>Total Reports on Chainabuse:</strong> <a href="{overall_wallet_chainabuse_info['url_scraped']}" target="_blank">{overall_wallet_chainabuse_info['total_reports_count']}</a></p>
                {"<p>No reports found on Chainabuse for this address.</p>" if overall_wallet_chainabuse_info['total_reports_count'] == 0 else ""}
                
                {"".join([
                    f"""
                    <div class="chainabuse-report-card">
                        <h4>Report {idx + 1}: {report.get('category', 'N/A')}</h4>
                        <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                        <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                        <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                        <p><strong>Reported Addresses in this report:</strong> {', '.join(report.get('reported_addresses', [])) if report.get('reported_addresses') else 'N/A'}</p>
                    </div>
                    """
                    for idx, report in enumerate(overall_wallet_chainabuse_info['reports'])
                ])}
            </div>

            <h2>Recent Transactions ({total_transactions} total)</h2>
            <div class="section-content">
    """
    
    # Categorize transactions into incoming and outgoing
    incoming_transactions = []
    outgoing_transactions = []

    if wallet_data.get('all_transactions'):
        for tx in wallet_data['all_transactions'][:20]: # Limit to top 20 transactions for brevity
            tx_from = tx.get('from', '').lower()
            tx_to = tx.get('to', '').lower()
            
            if tx_to == wallet_address.lower():
                incoming_transactions.append(tx)
            elif tx_from == wallet_address.lower():
                outgoing_transactions.append(tx)

    # --- Incoming Transactions Section ---
    html_content += f"""
                <h3>Incoming Transactions ({len(incoming_transactions)} total)</h3>
                {"<p>No incoming transactions found for this wallet.</p>" if not incoming_transactions else ""}
    """
    for tx in incoming_transactions:
        tx_hash = tx.get('hash')
        tx_time = datetime.fromtimestamp(int(tx.get('timeStamp', '0')), timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        tx_value_eth = int(tx.get('value', '0'), 10) / 1e18
        counterparty_address = tx.get('from')
        tx_type = tx.get('type') # 'normal' or 'internal'

        html_content += f"""
                <h4>Transaction Hash: <a href="https://etherscan.io/tx/{tx_hash}" target="_blank">{tx_hash[:10]}...</a> ({tx_type} transaction)</h4>
                <p><strong>Time:</strong> {tx_time}</p>
                <p><strong>Value:</strong> {tx_value_eth:.8f} ETH</p>
                <h5>Sender to this Wallet:</h5>
        """
        # Call analyze_ethereum_wallet_behavior and scrape_chainabuse_address_reports for counterparty
        # Note: These calls within generate_ethereum_wallet_report will still be synchronous.
        # This is fine because the API handler for generate_html_report will run this entire function
        # in a separate thread.
        counterparty_flags = analyze_ethereum_wallet_behavior(counterparty_address, tx_timestamp=int(tx.get('timeStamp', '0')))
        counterparty_chainabuse_info = scrape_chainabuse_address_reports(counterparty_address)
        
        # Combine flags and Chainabuse reports for display
        counterparty_display_flags = []
        if "Address found in local ransomware database." in counterparty_flags:
            counterparty_display_flags.append('<li class="red-flag">Address found in local ransomware database.</li>')
        if "Address found in Ransomwhere.re API." in counterparty_flags:
            counterparty_display_flags.append('<li class="red-flag">Address found in Ransomwhere.re API.</li>')
        if counterparty_chainabuse_info['total_reports_count'] > 0:
            counterparty_display_flags.append(f'<li class="red-flag">Found {counterparty_chainabuse_info["total_reports_count"]} scam report(s) on Chainabuse.</li>')
        
        # General Ethereum flags for counterparty (always present if applicable)
        if "Address appears to be reused (common for Ethereum, implies lower privacy)." in counterparty_flags:
            counterparty_display_flags.append('<li>Address appears to be reused (common for Ethereum, implies lower privacy).</li>')
        if "Dormant for over a year." in counterparty_flags:
            counterparty_display_flags.append('<li>Dormant for over a year.</li>')

        counterparty_flags_html = "".join(counterparty_display_flags)

        counterparty_detailed_chainabuse_html = ""
        if counterparty_chainabuse_info.get('detailed_chainabuse_reports'):
            counterparty_detailed_chainabuse_html += "<h6>Chainabuse Reports for this Address:</h6>"
            for i, report in enumerate(counterparty_chainabuse_info['detailed_chainabuse_reports']):
                counterparty_detailed_chainabuse_html += f"""
                            <div class="chainabuse-report-card">
                                <p><strong>Report {i+1}:</strong> {report.get('category', 'N/A')}</p>
                                <p><strong>Description:</b> {report.get('description', 'N/A')}</p>
                                <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                                <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', ['N/A']))}</p>
                            </div>
                """

        html_content += f"""
                <div class="wallet-summary-card">
                    <p><strong>Address:</strong> <a href="https://etherscan.io/address/{counterparty_address}" target="_blank">{counterparty_address}</a></p>
                    <p><strong>Chainabuse Reports:</strong> <a href="https://chainabuse.com/address/{counterparty_address}" target="_blank">{counterparty_chainabuse_info['total_reports_count']} reports</a></p>
                    <p><strong>Reputation Flags:</strong></p>
                    <ul>
                        {counterparty_flags_html if counterparty_flags_html else '<li>No known reputation flags.</li>'}
                    </ul>
                    {counterparty_detailed_chainabuse_html}
                </div>
                <hr style="border-top: 1px dashed var(--text-color); margin: 20px 0;">
        """

    # --- Outgoing Transactions Section ---
    html_content += f"""
                <h3>Outgoing Transactions ({len(outgoing_transactions)} total)</h3>
                {"<p>No outgoing transactions found for this wallet.</p>" if not outgoing_transactions else ""}
    """
    for tx in outgoing_transactions:
        tx_hash = tx.get('hash')
        tx_time = datetime.fromtimestamp(int(tx.get('timeStamp', '0')), timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        tx_value_eth = int(tx.get('value', '0'), 10) / 1e18
        counterparty_address = tx.get('to')
        tx_type = tx.get('type') # 'normal' or 'internal'

        html_content += f"""
                <h4>Transaction Hash: <a href="https://etherscan.io/tx/{tx_hash}" target="_blank">{tx_hash[:10]}...</a> ({tx_type} transaction)</h4>
                <p><strong>Time:</strong> {tx_time}</p>
                <p><strong>Value:</strong> {tx_value_eth:.8f} ETH</p>
                <h5>Receiver from this Wallet:</h5>
        """
        # Call analyze_ethereum_wallet_behavior and scrape_chainabuse_address_reports for counterparty
        counterparty_flags = analyze_ethereum_wallet_behavior(counterparty_address, tx_timestamp=int(tx.get('timeStamp', '0')))
        counterparty_chainabuse_info = scrape_chainabuse_address_reports(counterparty_address)
        
        # Combine flags and Chainabuse reports for display
        counterparty_display_flags = []
        if "Address found in local ransomware database." in counterparty_flags:
            counterparty_display_flags.append('<li class="red-flag">Address found in local ransomware database.</li>')
        if "Address found in Ransomwhere.re API." in counterparty_flags:
            counterparty_display_flags.append('<li class="red-flag">Address found in Ransomwhere.re API.</li>')
        if counterparty_chainabuse_info['total_reports_count'] > 0:
            counterparty_display_flags.append(f'<li class="red-flag">Found {counterparty_chainabuse_info["total_reports_count"]} scam report(s) on Chainabuse.</li>')

        # General Ethereum flags for counterparty (always present if applicable)
        if "Address appears to be reused (common for Ethereum, implies lower privacy)." in counterparty_flags:
            counterparty_display_flags.append('<li>Address appears to be reused (common for Ethereum, implies lower privacy).</li>')
        if "Dormant for over a year." in counterparty_flags:
            counterparty_display_flags.append('<li>Dormant for over a year.</li>')

        counterparty_flags_html = "".join(counterparty_display_flags)

        counterparty_detailed_chainabuse_html = ""
        if counterparty_chainabuse_info.get('detailed_chainabuse_reports'):
            counterparty_detailed_chainabuse_html += "<h6>Chainabuse Reports for this Address:</h6>"
            for i, report in enumerate(counterparty_chainabuse_info['detailed_chainabuse_reports']):
                counterparty_detailed_chainabuse_html += f"""
                            <div class="chainabuse-report-card">
                                <p><strong>Report {i+1}:</strong> {report.get('category', 'N/A')}</p>
                                <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                                <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                                <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', ['N/A']))}</p>
                            </div>
                """

        html_content += f"""
                <div class="wallet-summary-card">
                    <p><strong>Address:</strong> <a href="https://etherscan.io/address/{counterparty_address}" target="_blank">{counterparty_address}</a></p>
                    <p><strong>Chainabuse Reports:</strong> <a href="https://chainabuse.com/address/{counterparty_address}" target="_blank">{counterparty_chainabuse_info['total_reports_count']} reports</a></p>
                    <p><strong>Reputation Flags:</strong></p>
                    <ul>
                        {counterparty_flags_html if counterparty_flags_html else '<li>No known reputation flags.</li>'}
                    </ul>
                    {counterparty_detailed_chainabuse_html}
                </div>
                <hr style="border-top: 1px dashed var(--text-color); margin: 20px 0;">
        """

    if not incoming_transactions and not outgoing_transactions:
        html_content += "<p>No recent transactions found for this wallet.</p>"

    html_content += """
            </div>
        </div>
        <footer class="xeno-footer">
            <p>&copy; 2025 XenoByte Threat Intelligence. All rights reserved.</p>
            <p>Data from various public and open-source intelligence feeds.</p>
        </footer>
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
    </body>
    </html>
    """
    return html_content

# --- Main Execution Block (Modified for CLI JSON output) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XenoByte Ethereum Wallet Checker and Reporter.")
    parser.add_argument("wallet_address", help="The Ethereum wallet address to analyze.")
    parser.add_argument("--json-output", action="store_true", help="Output results as JSON to stdout.")
    
    args = parser.parse_args()

    # Load ransomware data once for this script's execution
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    print(f"\n[+] Starting forensic analysis for Ethereum wallet {args.wallet_address}...", file=sys.stderr)
    
    wallet_details = get_ethereum_address_info(args.wallet_address)

    if not wallet_details:
        error_message = f"Failed to retrieve details for wallet {args.wallet_address}. Please check the address and try again."
        if args.json_output:
            print(json.dumps({"error": error_message, "address": args.wallet_address}))
        else:
            print(error_message)
        sys.exit(1)

    # Perform behavioral analysis
    overall_wallet_flags = analyze_ethereum_wallet_behavior(args.wallet_address, wallet_details)
    chainabuse_info = scrape_chainabuse_address_reports(args.wallet_address) # Synchronous call, as this is the main script's execution context

    # Determine overall reputation (similar logic as in the report generation)
    overall_reputation_class = "clean"
    overall_reputation_text = "LIKELY CLEAN / LOW RISK"

    is_ransomware_local = args.wallet_address in local_ransomware_addresses
    is_ransomware_api = args.wallet_address in ransomware_api_addresses
    ransomware_family_api = []
    if is_ransomware_api:
        for entry in ransomware_api_data:
            if entry.get("address") == args.wallet_address and entry.get("family"):
                ransomware_family_api.append(entry['family'])
        ransomware_family_api = list(set(ransomware_family_api))

    if is_ransomware_local or is_ransomware_api or chainabuse_info['total_reports_count'] > 0:
        overall_reputation_class = "malicious"
        overall_reputation_text = "MALICIOUS / HIGH RISK"
    elif overall_wallet_flags and len([flag for flag in overall_wallet_flags if "Dormant" not in flag and "reused" not in flag]) > 0:
        overall_reputation_class = "suspicious"
        overall_reputation_text = "SUSPICIOUS / MODERATE RISK"
    
    # Prepare basic wallet info for API response
    balance_eth = wallet_details.get('balance', 0) / 1e18
    total_transactions = len(wallet_details.get('all_transactions', []))
    last_tx_time_utc = None
    if wallet_details.get('all_transactions'):
        latest_tx_timestamp = int(wallet_details['all_transactions'][0].get('timeStamp', '0'))
        if latest_tx_timestamp:
            last_tx_time_utc = datetime.fromtimestamp(latest_tx_timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    inferred_wallet_type = "Uncertain"
    if total_transactions > 1000:
        inferred_wallet_type = "Potentially Exchange, Smart Contract, or High-Frequency DApp User"
    elif total_transactions > 200:
        inferred_wallet_type = "Active Personal / Service Wallet"
    elif total_transactions > 0:
         inferred_wallet_type = "Personal Wallet"

    response_data = {
        "requested_address": args.wallet_address,
        "overall_reputation": {
            "class": overall_reputation_class,
            "text": overall_reputation_text
        },
        "basic_info": {
            "current_balance_eth": balance_eth,
            "total_transactions": total_transactions,
            "last_transaction_time_utc": last_tx_time_utc,
            "blockchain_type": "Ethereum",
            "inferred_wallet_type": inferred_wallet_type
        },
        "threat_intelligence": {
            "is_known_ransomware_address_local_db": is_ransomware_local,
            "is_known_ransomware_address_api": is_ransomware_api,
            "ransomware_families_identified": ransomware_family_api if ransomware_family_api else "N/A"
        },
        "behavioral_patterns": overall_wallet_flags,
        "chainabuse_reports": chainabuse_info,
        "disclaimer": "This data is aggregated from various open-source intelligence feeds and blockchain explorers. Always verify critical information from multiple trusted sources."
    }

    if args.json_output:
        # If --json-output is specified, print JSON to stdout
        print(json.dumps(response_data, indent=4))
    else:
        # Otherwise, generate and open the HTML report (original behavior)
        report_filename = f"XenoByte_ETH_Wallet_Report_{args.wallet_address[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_ethereum_wallet_report(args.wallet_address, wallet_details)

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Report generated successfully: {report_filename}", file=sys.stderr)
            webbrowser.open(f"file://{os.path.abspath(report_filename)}")
        except Exception as e:
            print(f"Error saving or opening report: {e}", file=sys.stderr)

