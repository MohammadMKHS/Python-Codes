import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timedelta, timezone
from playwright.sync_api import sync_playwright
import re
from collections import defaultdict
import urllib.parse # Import for URL encoding
import subprocess # New: Import for running external commands (Graphviz)
import base64     # New: Import for base64 encoding SVG
import argparse   # New: Import for command line argument parsing
import sys        # New: Import for sys.stdout/stderr

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Path to Graphviz dot executable (ensure this is correct for your system)
# You might need to install Graphviz: https://graphviz.org/download/
DOT_EXECUTABLE_PATH = r"C:\Program Files\Graphviz\bin\dot.exe" # Default for Windows, adjust as needed

# Etherscan APIs for Ethereum
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF" # IMPORTANT: Replace with your actual Etherscan API Key

API_DELAY_SECONDS = 1  # To respect Etherscan rate limits (5 calls/sec for free tier)
MAX_RETRIES = 5
INITIAL_BACKOFF_DELAY = 2 # seconds

# --- Global Data Caching for Forensic Tool ---
GLOBAL_ANALYZED_WALLETS = {} # Stores comprehensive data for each wallet, keyed by address
GLOBAL_TRANSACTION_GRAPH = defaultdict(lambda: {'sent_to': defaultdict(float), 'received_from': defaultdict(float)}) # Stores flow: wallet -> {target: amount}
GLOBAL_VISITED_TXS = set() # To prevent re-processing the same transaction
GLOBAL_QUEUE = [] # For BFS-like traversal (address, depth)
GLOBAL_MAX_DEPTH = 2 # Default max depth for tracing (can be user-defined)

# Initialize global variables for caching ransomware data
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
                    # Add some dummy ETH addresses for testing if needed
                    f.write("0xYourDummyETHAddress1Here\n") 
                    f.write("0xYourDummyETHAddress2Here\n")
            
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
                
                # If "No transactions found", return None immediately without retries
                if "No transactions found" in error_message:
                    print(f"  Etherscan API returned 'No transactions found'. Skipping further retries for this query.", file=sys.stderr)
                    return None 
                
                # For other errors, retry
                if i < retries - 1:
                    print(f"  Etherscan API returned error (attempt {i+1}/{retries}): {error_message}. Retrying...", file=sys.stderr)
                else:
                    print(f"  Etherscan API returned error after {retries} attempts: {error_message}", file=sys.stderr)
                time.sleep(backoff_delay * (2 ** i))
                continue
            
            time.sleep(API_DELAY_SECONDS)
            return data
        except requests.exceptions.RequestException as e:
            if i < retries - 1:
                print(f"  Network error during Etherscan request (attempt {i+1}/{retries}): {e}. Retrying...", file=sys.stderr)
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"  Network error after {retries} attempts for {url}: {e}", file=sys.stderr)
                return None
        except json.JSONDecodeError as e:
            if i < retries - 1:
                print(f"  JSON decode error from Etherscan (attempt {i+1}/{retries}): {e}. Retrying...", file=sys.stderr)
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"  JSON decode error after {retries} attempts for {url}: {e}", file=sys.stderr)
                return None
    return None

def get_ethereum_address_info(address):
    """
    Fetches comprehensive blockchain data for an Ethereum address from Etherscan.
    Combines balance, normal transactions, and internal transactions.
    """
    print(f"Fetching Ethereum blockchain data for {address} from Etherscan...", file=sys.stderr)
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

def get_ethereum_transaction_details(tx_hash):
    """
    Fetches details for a specific Ethereum transaction hash from Etherscan.
    Includes transaction details, receipt (for gasUsed), and block details (for timestamp).
    """
    print(f"  Trying Etherscan for transaction {tx_hash}...", file=sys.stderr)
    try:
        # 1. Get Transaction details
        tx_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        tx_data = make_etherscan_request(tx_url)

        if not tx_data or tx_data.get('result') is None:
            print(f"  Etherscan transaction details not found for {tx_hash}. It might be an invalid hash or not yet indexed.", file=sys.stderr)
            return None
        
        tx_result = tx_data['result']

        # 2. Get Transaction Receipt for gasUsed (actual fee calculation)
        receipt_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        receipt_data = make_etherscan_request(receipt_url)

        gas_used = 0
        if receipt_data and receipt_data.get('result') and receipt_data['result'].get('gasUsed'):
            gas_used = int(receipt_data['result']['gasUsed'], 16)
        
        # 3. Get Block details for timestamp
        block_number_hex = tx_result.get('blockNumber')
        block_time = None
        if block_number_hex:
            block_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getBlockByNumber&tag={block_number_hex}&boolean=true&apikey={ETHERSCAN_API_KEY}"
            block_data = make_etherscan_request(block_url)
            if block_data and block_data.get('result') and block_data['result'].get('timestamp'):
                block_time = int(block_data['result']['timestamp'], 16) # Unix timestamp in hex

        # Convert hex values to decimal
        value_wei = int(tx_result.get('value', '0x0'), 16)
        gas_price_wei = int(tx_result.get('gasPrice', '0x0'), 16)

        # Calculate fee (gasUsed * gasPrice) in Wei
        actual_fee_wei = gas_used * gas_price_wei

        normalized_data = {
            "hash": tx_result.get("hash"),
            "timeStamp": str(block_time), # Etherscan's format
            "blockNumber": str(int(block_number_hex, 16)) if block_number_hex else 'N/A',
            "gasUsed": str(gas_used),
            "gasPrice": str(gas_price_wei),
            "value": str(value_wei),
            "from": tx_result.get('from'),
            "to": tx_result.get('to'),
            "type": "normal" # Default to normal, internal txs are handled by txlistinternal
        }
        
        return normalized_data
    except Exception as e:
        print(f"  An error occurred while processing Etherscan data for {tx_hash}: {e}", file=sys.stderr)
    return None


def analyze_ethereum_wallet_behavioral(address, blockchain_data):
    """
    Analyzes wallet transactions based on defined rules for behavioral patterns.
    This is extracted to be called after initial data fetching.
    """
    analysis_results = {
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

    txs = blockchain_data.get('all_transactions', [])
    total_transactions = len(txs)

    if not txs:
        # Don't add a red flag for 'no transactions' in forensic behavioral analysis,
        # as it's already implicitly handled by other flags.
        return analysis_results

    # Sort transactions by time (most recent first)
    txs_with_time = [tx for tx in txs if tx.get('timeStamp') is not None]
    txs_with_time.sort(key=lambda x: int(x.get('timeStamp', '0')), reverse=True)

    # Last Transaction Time and Dormancy
    if txs_with_time:
        last_tx_time = int(txs_with_time[0].get('timeStamp', '0'))
        if last_tx_time:
            one_year_ago = datetime.now(timezone.utc) - timedelta(days=365)
            if datetime.fromtimestamp(last_tx_time, timezone.utc) < one_year_ago:
                analysis_results["dormant_for_over_a_year"] = True
                analysis_results["red_flags"].append("Dormant for over a year.")

    # Rule: High transaction count (exchange or mixer)
    if total_transactions > 500: # Threshold can be adjusted for ETH contracts/exchanges
        analysis_results["high_transaction_count"] = True
        analysis_results["wallet_type_inferred"] = "Potentially Exchange, Smart Contract, or High-Frequency DApp User"
        analysis_results["red_flags"].append(f"High transaction count ({total_transactions}). Potentially an exchange, smart contract, or high-frequency DApp user.")
    elif total_transactions > 100:
        analysis_results["wallet_type_inferred"] = "Active Personal / Minor Service"
    else:
        analysis_results["wallet_type_inferred"] = "Personal Wallet" # Default if not very active

    # Automated Transactions (time between transactions) - Enhanced
    prev_tx_time = None
    for tx in txs_with_time: # Use sorted list
        current_tx_time = int(tx.get('timeStamp', '0'))
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
            
            if time_diff < 5 * 24 * 60 * 60: # Less than 5 days
                analysis_results["frequent_transactions_detected"] = True

        prev_tx_time = current_tx_time

    # Rule: Large amount received & High transaction fee & Dust attack pattern
    for tx in txs:
        # For Ethereum, value is directly in the transaction object (in Wei)
        value_wei = int(tx.get('value', '0'), 10)
        
        # Check for large amounts received by this address
        if tx.get('to', '').lower() == address.lower():
            if value_wei > 10 * 1e18: # Example: over 10 ETH
                analysis_results["large_amount_received"] = True
                analysis_results["red_flags"].append(f"Large amount received ({value_wei / 1e18:.8f} ETH) in transaction {tx.get('hash')}.")
                
        # Dust attack pattern (if the queried address is the sender of dust)
        # In Ethereum, this means sending many tiny amounts.
        if tx.get('from', '').lower() == address.lower() and value_wei > 0 and value_wei < 1e12: # Less than 0.000001 ETH (1 Gwei)
            analysis_results["dust_attack_pattern"] = True
            analysis_results["red_flags"].append(f"Potential dust attack pattern (very small outgoing transaction) detected in transaction {tx.get('hash')}.")

        # High transaction fee (only for normal transactions)
        if tx.get('type') == 'normal':
            gas_used = int(tx.get('gasUsed', '0'), 10)
            gas_price = int(tx.get('gasPrice', '0'), 10)
            actual_fee_wei = gas_used * gas_price
            if actual_fee_wei > 0.05 * 1e18: # Over 0.05 ETH for fee
                analysis_results["high_transaction_fee_detected"] = True
                analysis_results["red_flags"].append(f"High transaction fee detected (~{actual_fee_wei / 1e18:.5f} ETH) in transaction {tx.get('hash')}.")

    # Address appears to be reused multiple times (low privacy)
    if total_transactions > 50: # Arbitrary threshold
           analysis_results["red_flags"].append("Address appears to be reused multiple times (low privacy).")

    return analysis_results

def scrape_chainabuse_address_reports(address: str) -> dict:
    """
    Scrapes all scam reports for a given cryptocurrency address from Chainabuse.
    This function is kept as is, as Chainabuse supports both BTC and ETH addresses.
    """
    base_url = "https://chainabuse.com/address/"
    url = f"{base_url}{address}"
    
    all_reports_data = {
        "address": address,
        "url_scraped": url,
        "total_reports_count": 0,
        "reports": []
    }

    print(f"Fetching Chainabuse data for {address} from: {url}", file=sys.stderr)

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
            # Ensure browser is closed even on unexpected errors
            if 'browser' in locals() and browser.is_connected():
                browser.close()
            
    return all_reports_data

# --- Core Forensic Tracing Logic ---
def trace_wallet_transactions_recursive(wallet_address: str, current_depth: int, is_target_wallet: bool = False):
    """
    Recursively traces transactions for a given wallet address up to a maximum depth.
    Populates GLOBAL_ANALYZED_WALLETS and GLOBAL_TRANSACTION_GRAPH.
    """
    if GLOBAL_MAX_DEPTH != -1 and current_depth > GLOBAL_MAX_DEPTH:
        print(f"  [DEBUG] Max depth ({GLOBAL_MAX_DEPTH}) reached for {wallet_address}. Skipping further trace.", file=sys.stderr)
        return
    if wallet_address in GLOBAL_ANALYZED_WALLETS:
        if current_depth < GLOBAL_ANALYZED_WALLETS[wallet_address].get('depth', float('inf')):
            GLOBAL_ANALYZED_WALLETS[wallet_address]['depth'] = current_depth
            print(f"  [DEBUG] Wallet {wallet_address} already analyzed, updating depth to {current_depth}.", file=sys.stderr)
        else:
            print(f"  [DEBUG] Wallet {wallet_address} already analyzed at equal or shallower depth. Skipping.", file=sys.stderr)
        return

    depth_display = "Full" if GLOBAL_MAX_DEPTH == -1 else f"{current_depth}/{GLOBAL_MAX_DEPTH}"
    print(f"\n[+] Analyzing wallet: {wallet_address} (Depth: {depth_display})", file=sys.stderr)

    # Initialize wallet data in global store
    wallet_data = {
        "address": wallet_address,
        "depth": current_depth,
        "is_ransomware_local": False,
        "is_ransomware_api": False,
        "ransomware_family_api": [],
        "blockchain_type": "Ethereum", # Fixed for Ethereum
        "balance_eth": 0,
        "total_transactions": 0,
        "last_transaction_time_utc": "N/A",
        "wallet_type_inferred": "Uncertain",
        "red_flags": [],
        "chainabuse_reports": {},
        "incoming_tx_value_sum_traced": 0.0, # Sum of ETH received from traced wallets
        "outgoing_tx_value_sum_traced": 0.0, # Sum of ETH sent to traced wallets
        "tx_hashes_involved": set(), # Store hashes of transactions directly involving this wallet
        "directly_sent_to_target": 0.0, # Amount sent directly to target
        "directly_received_from_target": 0.0 # Amount received directly from target
    }
    GLOBAL_ANALYZED_WALLETS[wallet_address] = wallet_data

    # --- Perform basic reputation checks for ALL wallets (target and non-target) ---
    local_wallets = load_local_ransomware_addresses()
    if wallet_address in local_wallets:
        wallet_data["is_ransomware_local"] = True
        wallet_data["red_flags"].append("Address found in local ransomware database.")

    api_wallets, full_api_data = fetch_ransomwhere_data()
    if wallet_address in api_wallets:
        wallet_data["is_ransomware_api"] = True
        wallet_data["red_flags"].append("Address found in Ransomwhere.re API.")
        for entry in full_api_data:
            if entry.get("address") == wallet_address:
                family = entry.get("family", "Unknown")
                if family and family != "Unknown" and family not in wallet_data["ransomware_family_api"]:
                    wallet_data["ransomware_family_api"].append(family)

    chainabuse_data = scrape_chainabuse_address_reports(wallet_address)
    if isinstance(chainabuse_data, dict):
        wallet_data["chainabuse_reports"] = chainabuse_data
        if chainabuse_data.get('total_reports_count', 0) > 0:
            wallet_data["red_flags"].append(f"Found {chainabuse_data['total_reports_count']} scam report(s) on Chainabuse.")
            for report in chainabuse_data['reports']:
                if "ransomware" in report.get("category", "").lower():
                    wallet_data["red_flags"].append(f"Chainabuse report indicates Ransomware activity (Category: {report['category']}).")

    # Fetch comprehensive Ethereum data for the current wallet
    etherscan_wallet_data = get_ethereum_address_info(wallet_address)
    if not etherscan_wallet_data:
        print(f"  Failed to retrieve Etherscan data for {wallet_address}. Skipping transaction analysis for this wallet.", file=sys.stderr)
        return

    wallet_data["balance_eth"] = etherscan_wallet_data.get('balance', 0) / 1e18
    wallet_data["total_transactions"] = len(etherscan_wallet_data.get('all_transactions', []))
    
    if etherscan_wallet_data.get('all_transactions'):
        latest_tx_timestamp = int(etherscan_wallet_data['all_transactions'][0].get('timeStamp', '0'))
        wallet_data["last_transaction_time_utc"] = datetime.fromtimestamp(latest_tx_timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    # Perform behavioral analysis using the fetched Etherscan data
    behavioral_analysis_flags = analyze_ethereum_wallet_behavioral(wallet_address, etherscan_wallet_data)
    wallet_data["red_flags"].extend([flag for flag in behavioral_analysis_flags["red_flags"] if flag not in wallet_data["red_flags"]])
    
    # Update inferred wallet type from behavioral analysis
    if "wallet_type_inferred" in behavioral_analysis_flags: # This field is directly set by the behavioral analysis
        wallet_data["wallet_type_inferred"] = behavioral_analysis_flags["wallet_type_inferred"]
    elif wallet_data["total_transactions"] > 1000:
        wallet_data["wallet_type_inferred"] = "Potentially Exchange, Smart Contract, or High-Frequency DApp User"
    elif wallet_data["total_transactions"] > 200:
        wallet_data["wallet_type_inferred"] = "Active Personal / Minor Service"
    elif wallet_data["total_transactions"] > 0:
        wallet_data["wallet_type_inferred"] = "Personal Wallet"


    # Process transactions for tracing
    for tx in etherscan_wallet_data.get('all_transactions', []):
        tx_hash = tx.get('hash')
        if tx_hash in GLOBAL_VISITED_TXS:
            continue # Skip if transaction already processed

        GLOBAL_VISITED_TXS.add(tx_hash)
        wallet_data["tx_hashes_involved"].add(tx_hash)

        tx_from = tx.get('from', '').lower()
        tx_to = tx.get('to', '').lower()
        tx_value_wei = int(tx.get('value', '0'), 10)
        tx_value_eth = tx_value_wei / 1e18

        # Add to graph and queue for next depth
        # Only add to queue if current_depth is less than GLOBAL_MAX_DEPTH
        if current_depth < GLOBAL_MAX_DEPTH or GLOBAL_MAX_DEPTH == -1:
            if tx_from == wallet_address.lower(): # This wallet sent money
                if tx_to and tx_to != "0x" + "0" * 40: # Exclude zero address
                    GLOBAL_TRANSACTION_GRAPH[wallet_address]['sent_to'][tx_to] += tx_value_eth
                    wallet_data['outgoing_tx_value_sum_traced'] += tx_value_eth
                    if is_target_wallet:
                        wallet_data['directly_sent_to_target'] += tx_value_eth
                    if tx_to not in GLOBAL_ANALYZED_WALLETS:
                        GLOBAL_QUEUE.append((tx_to, current_depth + 1))

            elif tx_to == wallet_address.lower(): # This wallet received money
                if tx_from and tx_from != "0x" + "0" * 40: # Exclude zero address
                    GLOBAL_TRANSACTION_GRAPH[tx_from]['sent_to'][wallet_address] += tx_value_eth
                    wallet_data['incoming_tx_value_sum_traced'] += tx_value_eth
                    if is_target_wallet:
                        wallet_data['directly_received_from_target'] += tx_value_eth
                    if tx_from not in GLOBAL_ANALYZED_WALLETS:
                        GLOBAL_QUEUE.append((tx_from, current_depth + 1))

def perform_forensic_analysis(target_address: str, max_depth: int = 2):
    """
    Performs a BFS-like forensic analysis of an Ethereum wallet address.
    """
    global GLOBAL_MAX_DEPTH, GLOBAL_QUEUE, GLOBAL_ANALYZED_WALLETS, GLOBAL_TRANSACTION_GRAPH, GLOBAL_VISITED_TXS
    
    GLOBAL_MAX_DEPTH = max_depth
    GLOBAL_QUEUE = [(target_address, 0)] # (address, depth)
    GLOBAL_ANALYZED_WALLETS = {}
    GLOBAL_TRANSACTION_GRAPH = defaultdict(lambda: {'sent_to': defaultdict(float), 'received_from': defaultdict(float)})
    GLOBAL_VISITED_TXS = set()

    # Load ransomware data once at the start
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    head = 0
    while head < len(GLOBAL_QUEUE):
        current_address, current_depth = GLOBAL_QUEUE[head]
        head += 1
        
        # Pass is_target_wallet=True only for the initial call
        trace_wallet_transactions_recursive(current_address, current_depth, is_target_wallet=(current_address == target_address))

    # After tracing, ensure all wallets in the graph are also in ANALYZED_WALLETS
    # This handles cases where a wallet is only an intermediary but not directly traced
    for addr in list(GLOBAL_TRANSACTION_GRAPH.keys()):
        if addr not in GLOBAL_ANALYZED_WALLETS:
            print(f"\n[+] Analyzing intermediary wallet: {addr} (Depth: N/A - Graph Node)", file=sys.stderr)
            # Fetch minimal info for graph nodes that weren't fully traced
            etherscan_wallet_data = get_ethereum_address_info(addr)
            wallet_data = {
                "address": addr,
                "depth": -1, # Mark as not fully traced
                "is_ransomware_local": addr in local_ransomware_addresses,
                "is_ransomware_api": addr in ransomware_api_addresses,
                "ransomware_family_api": [entry['family'] for entry in ransomware_api_data if entry.get("address") == addr and entry.get("family")],
                "blockchain_type": "Ethereum",
                "balance_eth": etherscan_wallet_data.get('balance', 0) / 1e18 if etherscan_wallet_data else 0,
                "total_transactions": len(etherscan_wallet_data.get('all_transactions', [])) if etherscan_wallet_data else 0,
                "last_transaction_time_utc": "N/A",
                "wallet_type_inferred": "Uncertain",
                "red_flags": [],
                "chainabuse_reports": scrape_chainabuse_address_reports(addr),
                "incoming_tx_value_sum_traced": 0.0,
                "outgoing_tx_value_sum_traced": 0.0,
                "tx_hashes_involved": list(GLOBAL_ANALYZED_WALLETS.get(addr, {}).get('tx_hashes_involved', set())), # Convert set to list for JSON
                "directly_sent_to_target": 0.0,
                "directly_received_from_target": 0.0
            }
            if wallet_data["is_ransomware_local"]:
                wallet_data["red_flags"].append("Address found in local ransomware database.")
            if wallet_data["is_ransomware_api"]:
                wallet_data["red_flags"].append("Address found in Ransomwhere.re API.")
            if wallet_data["chainabuse_reports"].get('total_reports_count', 0) > 0:
                wallet_data["red_flags"].append(f"Found {wallet_data['chainabuse_reports']['total_reports_count']} scam report(s) on Chainabuse.")
            GLOBAL_ANALYZED_WALLETS[addr] = wallet_data

    # --- Post-processing and Aggregation for Summary Data ---
    summary_data = {
        "total_wallets_analyzed": len(GLOBAL_ANALYZED_WALLETS),
        "total_malicious_wallets": 0,
        "total_suspicious_wallets": 0,
        "wallets_with_chainabuse_reports": 0,
        "cold_wallets_identified": [],
        "top_receivers_in_flow": [], # Wallets that received most within the traced network
        "top_senders_in_flow": [] # Wallets that sent most within the traced network
    }

    # Identify cold wallets and count malicious/suspicious, and categorize flagged/unflagged
    flagged_wallets = []
    unflagged_wallets = []
    directly_connected_wallets = []

    for addr, data in GLOBAL_ANALYZED_WALLETS.items():
        has_flags = False
        if data.get('is_ransomware_local') or data.get('is_ransomware_api'):
            summary_data["total_malicious_wallets"] += 1
            has_flags = True
        
        # Count suspicious only if there are red flags other than just "Address appears to be reused"
        other_red_flags = [flag for flag in data.get('red_flags', []) if "Address appears to be reused" not in flag]
        if other_red_flags:
            summary_data["total_suspicious_wallets"] += 1
            has_flags = True

        if data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
            summary_data["wallets_with_chainabuse_reports"] += 1
            has_flags = True

        # Simple cold wallet heuristic: high balance and dormant
        if data.get('balance_eth', 0) > 1.0 and data.get('dormant_for_over_a_year', False): # More than 1 ETH and dormant
            summary_data["cold_wallets_identified"].append(addr)

        if has_flags:
            flagged_wallets.append(addr)
        else:
            unflagged_wallets.append(addr)

        # Directly connected wallets
        if data.get('directly_sent_to_target') > 0 or data.get('directly_received_from_target') > 0:
            directly_connected_wallets.append(addr)

    # Sort top senders and receivers
    for addr, data in GLOBAL_ANALYZED_WALLETS.items():
        if data.get('outgoing_tx_value_sum_traced', 0) > 0:
            summary_data["top_senders_in_flow"].append({
                "address": addr,
                "amount_eth": data['outgoing_tx_value_sum_traced']
            })
        if data.get('incoming_tx_value_sum_traced', 0) > 0:
            summary_data["top_receivers_in_flow"].append({
                "address": addr,
                "amount_eth": data['incoming_tx_value_sum_traced']
            })
    
    summary_data["top_senders_in_flow"].sort(key=lambda x: x['amount_eth'], reverse=True)
    summary_data["top_receivers_in_flow"].sort(key=lambda x: x['amount_eth'], reverse=True)

    # Convert sets to lists for JSON serialization
    for wallet_addr, wallet_info in GLOBAL_ANALYZED_WALLETS.items():
        if isinstance(wallet_info.get("tx_hashes_involved"), set):
            wallet_info["tx_hashes_involved"] = list(wallet_info["tx_hashes_involved"])

    report_data = {
        "target_address": target_address,
        "max_tracing_depth": "Full" if max_depth == -1 else max_depth,
        "analyzed_wallets": GLOBAL_ANALYZED_WALLETS,
        "transaction_graph": GLOBAL_TRANSACTION_GRAPH, # This needs custom serialization or conversion
        "summary_data": summary_data,
        "flagged_wallets": flagged_wallets,
        "unflagged_wallets": unflagged_wallets,
        "directly_connected_wallets": directly_connected_wallets
    }

    # Convert transaction_graph defaultdict to regular dict for JSON serialization
    # Also convert inner defaultdicts to regular dicts
    report_data["transaction_graph"] = {
        sender: {
            "sent_to": dict(connections["sent_to"]),
            "received_from": dict(connections["received_from"])
        }
        for sender, connections in report_data["transaction_graph"].items()
    }


    # Generate the transaction flow graph SVG and include it as base64
    graph_svg_base64 = ""
    dot_graph_code = ""
    try:
        dot_source = []
        dot_source.append('digraph G {')
        dot_source.append('    rankdir=LR;')
        dot_source.append('    overlap=false;')
        dot_source.append('    splines=true;')
        dot_source.append('    node [shape=box, style="filled,rounded", fontname="Roboto", fontsize=10];')
        dot_source.append('    edge [fontname="Roboto", fontsize=8];')

        graph_addresses = set()
        for address, data in report_data['analyzed_wallets'].items():
            label_addr = f"{address[:8]}...{address[-6:]}"
            node_color = "#00ff88" # Default clean green
            fill_color = "#1a1a1a"
            font_color = "#00f5d4"
            prefix = ""

            if address == report_data['target_address']:
                label_addr = f"TARGET\\n{label_addr}"
                node_color = "#6999FC" # Blue for target
                fill_color = "#002040"
                font_color = "#ffffff"
            elif data.get('is_ransomware_local') or data.get('is_ransomware_api') or data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
                node_color = "#e53935" # Red for malicious/reported
                fill_color = "#330a0a"
                font_color = "#ffffff"
                if data.get('is_ransomware_local') or data.get('is_ransomware_api'):
                    prefix = "MALICIOUS\\n"
                elif data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
                    prefix = "REPORTED\\n"
                label_addr = f"{prefix}{label_addr}"
            elif data.get('red_flags'): # Suspicious but not directly malicious
                node_color = "#ffeb3b" # Yellow for suspicious
                fill_color = "#33330a"
                font_color = "#000000" # Black text on yellow for contrast
                prefix = "SUSPICIOUS\\n"
                label_addr = f"{prefix}{label_addr}"
            else:
                node_color = "#47ff47" # Clean green
                fill_color = "#003d00"
                font_color = "#ffffff"
                
            dot_source.append(f'    "{address}" [label="{label_addr}", URL="https://etherscan.io/address/{address}", target="_blank", color="{node_color}", fillcolor="{fill_color}", fontcolor="{font_color}"];')
            graph_addresses.add(address)

        has_edges = False
        for sender, connections in forensic_report_data['transaction_graph'].items():
            for receiver, amount in connections['sent_to'].items():
                if sender in graph_addresses and receiver in graph_addresses:
                    edge_label = f"{amount:.4f} ETH"
                    edge_color = "#00f5d4"

                    sender_data = report_data['analyzed_wallets'].get(sender, {})
                    receiver_data = report_data['analyzed_wallets'].get(receiver, {})

                    sender_is_bad = sender_data.get('is_ransomware_local', False) or sender_data.get('is_ransomware_api', False) or sender_data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0
                    receiver_is_bad = receiver_data.get('is_ransomware_local', False) or receiver_data.get('is_ransomware_api', False) or receiver_data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0

                    if sender_is_bad or receiver_is_bad:
                        edge_color = "#ff4747"
                    elif sender_data.get('red_flags') or receiver_data.get('red_flags'):
                        edge_color = "#ffff47"

                    dot_source.append(f'    "{sender}" -> "{receiver}" [label="{edge_label}", color="{edge_color}", fontcolor="{edge_color}", penwidth=2];')
                    has_edges = True

        dot_source.append('}')
        dot_graph_code = "\n".join(dot_source) # Store the DOT code itself

        if not graph_addresses and not has_edges:
            print(f"No transaction flow graph could be generated for {target_address}. This might mean no transactions were found or the depth was too shallow.", file=sys.stderr)
        else:
            process = subprocess.run(
                [DOT_EXECUTABLE_PATH, "-Tsvg"],
                input=dot_graph_code.encode('utf-8'),
                capture_output=True,
                check=True
            )
            svg_data = process.stdout
            graph_svg_base64 = base64.b64encode(svg_data).decode('utf-8')
            print(f"Generated graph SVG (base64) for {target_address}.", file=sys.stderr)

    except FileNotFoundError:
        print(f"ERROR: Graphviz 'dot' executable not found at '{DOT_EXECUTABLE_PATH}'. Graph will not be generated.", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Graphviz subprocess failed: {e.stderr.decode('utf-8')}. Graph will not be generated.", file=sys.stderr)
    except Exception as e:
        print(f"ERROR: An unexpected error occurred during graph SVG generation: {e}", file=sys.stderr)

    report_data["graph_svg_base64"] = graph_svg_base64
    report_data["graph_dot_code"] = dot_graph_code # Include DOT code for debugging/manual rendering

    return report_data


# --- Main Execution Block (Modified for CLI JSON output) ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XenoByte Ethereum Wallet Forensic Analysis Tool.")
    parser.add_argument("wallet_address", help="The Ethereum wallet address for forensic analysis.")
    parser.add_argument("--depth", type=int, default=2, help="Max tracing depth (e.g., 1, 2, 3, or -1 for full depth). Default is 2.")
    parser.add_argument("--json-output", action="store_true", help="Output results as JSON to stdout.")
    
    args = parser.parse_args()

    # Load ransomware data once for this script's execution
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    print(f"\n[+] Starting forensic analysis for Ethereum wallet {args.wallet_address} up to depth {args.depth}...", file=sys.stderr)
    
    # Perform the forensic analysis
    forensic_report_data = perform_forensic_analysis(args.wallet_address, args.depth)

    if args.json_output:
        # If --json-output is specified, print JSON to stdout
        # Ensure all sets are converted to lists for JSON serialization
        json_output_data = json.dumps(forensic_report_data, indent=4)
        print(json_output_data)
    else:
        # Otherwise, generate and open the HTML report (original behavior)
        report_filename = f"XenoByte_ETH_Forensic_Report_{args.wallet_address[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_forensic_report_html(forensic_report_data) # Use new HTML generator

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Report generated successfully: {report_filename}", file=sys.stderr)
            webbrowser.open(f"file://{os.path.abspath(report_filename)}") # Automatically open the report
        except Exception as e:
            print(f"Error saving or opening report: {e}", file=sys.stderr)

# A separate function for HTML generation, which will use the same forensic_report_data
# This prevents circular imports if generate_forensic_report was imported by the API.
def generate_forensic_report_html(forensic_report_data: dict) -> str:
    """
    Generates an HTML formatted forensic report for the target Ethereum wallet.
    This function expects the full forensic_report_data dictionary.
    """
    target_address = forensic_report_data['target_address']
    analyzed_wallets = forensic_report_data['analyzed_wallets']
    summary = forensic_report_data['summary_data']
    graph_svg_base64 = forensic_report_data.get('graph_svg_base64', '')
    graph_dot_code = forensic_report_data.get('graph_dot_code', '')
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Determine overall reputation for the target wallet
    overall_reputation_class = "clean" # Default to clean
    overall_reputation_text = "🟢 LIKELY CLEAN / LOW RISK"

    target_wallet_data = analyzed_wallets.get(target_address, {})

    is_ransomware_local = target_wallet_data.get('is_ransomware_local', False)
    is_ransomware_api = target_wallet_data.get('is_ransomware_api', False)
    chainabuse_reports_count = target_wallet_data.get('chainabuse_reports', {}).get('total_reports_count', 0)

    if is_ransomware_local or is_ransomware_api or chainabuse_reports_count > 0:
        overall_reputation_class = "malicious"
        overall_reputation_text = "🔴 MALICIOUS / HIGH RISK"
    elif target_wallet_data.get('red_flags') and len([flag for flag in target_wallet_data['red_flags'] if "Dormant" not in flag and "reused" not in flag]) > 0:
        overall_reputation_class = "suspicious"
        overall_reputation_text = "🟠 SUSPICIOUS / MODERATE RISK"

    # --- Build Behavioral Analysis HTML (pre-process to avoid f-string nesting issues) ---
    behavioral_analysis_list_items = []
    if target_wallet_data.get('dormant_for_over_a_year'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Dormancy:</strong> Wallet has been dormant for over a year.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> Wallet has been active within the last year.</li>')

    if target_wallet_data.get('extremely_rapid_transactions_detected'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected extremely rapid transfers (< 5s between transactions), highly suggestive of automation.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> No extremely rapid transaction patterns detected.</li>')

    if target_wallet_data.get('rapid_transactions_detected'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected rapid transfers (< 5 minutes between transactions), suggesting automated or high-frequency activity.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> No rapid transaction patterns detected (within 5 minutes).</li>')
    
    if target_wallet_data.get('frequent_transactions_detected'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> Detected frequent transactions (< 5 days between transactions), indicating consistent activity.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> Transaction frequency appears normal (no consistent activity within 5 days).</li>')

    if target_wallet_data.get('automated_transactions_detected'):
        behavioral_analysis_list_items.append(f'<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Detected very short time difference ({target_wallet_data.get("automated_transactions_time_diff")}) between transactions (5s-1min range), suggesting automation.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> No specifically identified automated transaction patterns (5s-1min).</li>')

    if target_wallet_data.get('high_transaction_count'):
        behavioral_analysis_list_items.append(f'<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> High transaction count detected ({target_wallet_data.get("total_transactions")}). This wallet is potentially an exchange, smart contract, or high-frequency DApp user.</li>')
    else:
        behavioral_analysis_list_items.append(f'<li><span class="analysis-clean">✔</span> Moderate transaction count ({target_wallet_data.get("total_transactions")}).</li>')

    if target_wallet_data.get('large_amount_received'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Activity:</strong> Large amount received detected in one or more transactions.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> No unusually large amounts received.</li>')

    if target_wallet_data.get('dust_attack_pattern'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> Potential dust attack pattern (very small outgoing transaction) detected.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> No dust attack patterns detected.</li>')

    if target_wallet_data.get('high_transaction_fee_detected'):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Anomaly:</strong> High transaction fee detected in one or more transactions.</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> Transaction fees appear normal.</li>')

    if "Address appears to be reused multiple times (low privacy)." in target_wallet_data.get('red_flags', []):
        behavioral_analysis_list_items.append('<li><span class="analysis-flag">⚠</span> <strong>Privacy:</strong> Address appears to be reused multiple times (low privacy).</li>')
    else:
        behavioral_analysis_list_items.append('<li><span class="analysis-clean">✔</span> Address reuse for privacy is not a significant concern based on current data.</li>')

    behavioral_analysis_html = '\n'.join(behavioral_analysis_list_items)


    # --- Build Chainabuse Reports HTML separately ---
    chainabuse_reports_html = ""
    if target_wallet_data.get('chainabuse_reports', {}).get('total_reports_count', 0) == 0:
        chainabuse_reports_html = "<p>No reports found on Chainabuse for this address.</p>"
    else:
        for idx, report in enumerate(target_wallet_data.get('chainabuse_reports', {}).get('reports', [])):
            chainabuse_reports_html += f"""
                    <div class="chainabuse-report-card">
                        <h4>Report {idx + 1}: {report.get('category', 'N/A')}</h4>
                        <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                        <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                        <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                        <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', [])) if report.get('reported_addresses') else 'N/A'}</p>
                    </div>
                    """
    # --- Build Detailed Wallet Information HTML separately ---
    detailed_wallets_html = ""
    for addr, data in analyzed_wallets.items():
        # Build reputation flags for each wallet
        wallet_flags_html = ""
        if data.get('red_flags'):
            for flag in data['red_flags']:
                wallet_flags_html += f'<li class="red-flag">{flag}</li>'
        else:
            wallet_flags_html = '<li>No known reputation flags.</li>'

        # Build Chainabuse reports for each wallet in detailed view
        single_wallet_chainabuse_html = ""
        if data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
            for idx, report in enumerate(data.get('chainabuse_reports', {}).get('reports', [])):
                single_wallet_chainabuse_html += f"""
                        <div class="chainabuse-report-card">
                            <h4>Report {idx + 1}: {report.get('category', 'N/A')}</h4>
                            <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                            <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                            <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                            <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', [])) if report.get('reported_addresses') else 'N/A'}</p>
                        </div>
                        """

        detailed_wallets_html += f"""
                    <h3>Wallet Address: <a href="https://etherscan.io/address/{addr}" target="_blank">{addr}</a></h3>
                    <p><strong>Depth from Target:</strong> {data.get('depth', 'N/A')}</p>
                    <p><strong>Current Balance:</strong> {data.get('balance_eth', 0):.8f} ETH</p>
                    <p><strong>Total Transactions:</strong> {data.get('total_transactions', 0)}</p>
                    <p><strong>Last Transaction:</strong> {data.get('last_transaction_time_utc', 'N/A')}</p>
                    <p><strong>Inferred Type:</strong> {data.get('wallet_type_inferred', 'Uncertain')}</p>
                    <p><strong>Reputation Flags:</strong></p>
                    <ul>
                        {wallet_flags_html}
                    </ul>
                    <p><strong>Chainabuse Reports:</strong> <a href="{data.get('chainabuse_reports', {}).get('url_scraped', '#')}" target="_blank">{data.get('chainabuse_reports', {}).get('total_reports_count', 0)} reports</a></p>
                    {single_wallet_chainabuse_html}
                    <hr style="border-top: 1px dashed var(--text-color); margin: 20px 0;">
                    """

    # --- CSS Styling (Copied directly from user's provided Bitcoin wallet report HTML) ---
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
    /* Adjusted ul for behavioral analysis to remove extra spacing */
    .content-section ul {
        padding-left: 25px;
        list-style: disc;
        margin-top: 0; /* Remove top margin from ul */
        margin-bottom: 0; /* Remove bottom margin from ul */
    }
    .content-section ul li {
        margin-bottom: 8px; /* Standard spacing between list items */
        padding-top: 2px; /* Small padding for visual separation */
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
    
        /* Added styles for Chainabuse report cards based on your provided HTML */
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
    .graph-container {
        overflow-x: auto; /* Enable horizontal scrolling if graph is too wide */
        padding: 10px;
        border: 1px solid var(--accent);
        border-radius: 8px;
        background-color: var(--box-color);
        margin-top: 20px;
        min-height: 200px; /* Give some initial height */
        display: flex;
        flex-direction: column; /* Changed to column for text area */
        justify-content: center;
        align-items: center;
        width: 100%; /* Ensure it takes full width of its parent */
        box-sizing: border-box;
    }
    .graph-container img {
        width: 100%; /* Force image to fill container width */
        height: auto;
        border: 1px solid var(--input-border); /* Use input border for consistency */
        border-radius: 4px;
        max-width: 100%; /* Ensure it doesn't overflow */
        height: auto; /* Maintain aspect ratio */
    }
    .wallet-summary-card {
        background-color: #1a1a1a;
        border: 1px solid var(--text-color);
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 15px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        width: 100%; /* Ensure it takes full width of its parent */
        box-sizing: border-box;
    }
    .wallet-summary-card h4 {
        color: var(--accent);
        margin-top: 0;
        margin-bottom: 10px;
        font-family: 'Orbitron', sans-serif;
        font-size: 1.1em;
    }
    .wallet-summary-card p {
        margin-bottom: 5px;
        color: var(--footer-text);
    }
    .wallet-summary-card strong {
        color: var(--text-color);
    }
    .wallet-list-summary {
        list-style: none;
        padding: 0;
    }
    .wallet-list-summary li {
        background-color: var(--input-bg);
        border: 1px solid var(--input-border);
        border-radius: 5px;
        padding: 10px 15px;
        margin-bottom: 8px;
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
    }
    .wallet-list-summary li .address {
        font-weight: bold;
        color: var(--accent);
        margin-right: 15px;
        word-break: break-all;
        flex-basis: 60%;
    }
    .wallet-list-summary li .flags {
        font-size: 0.9em;
        color: var(--footer-text);
        flex-basis: 35%;
        text-align: right;
    }
    @media (max-width: 768px) {
        .wallet-list-summary li {
            flex-direction: column;
            align-items: flex-start;
        }
        .wallet-list-summary li .address {
            margin-right: 0;
            margin-bottom: 5px;
            flex-basis: 100%;
        }
        .wallet-list-summary li .flags {
            text-align: left;
            flex-basis: 100%;
        }
    }
    """

    # If the graph SVG is available, embed it as a data URI
    graph_embed_html = ""
    if graph_svg_base64:
        graph_embed_html = f"""
        <p>Below is a visualization of the transaction flow generated using Graphviz.</p>
        <div class="graph-container">
            <img src="data:image/svg+xml;base64,{graph_svg_base64}" alt="Transaction Flow Graph">
        </div>
        """
    else:
        graph_embed_html = f"""
        <p class='error-message'>Transaction flow graph could not be generated. This might be due to Graphviz not being installed or an error during graph generation.</p>
        <p><strong>Graphviz 'dot' executable path:</strong> {DOT_EXECUTABLE_PATH}</p>
        {"<p><strong>Raw DOT Graph Code (for manual viewing):</strong></p><textarea style='width:100%; height:200px; background-color:var(--input-bg); color:var(--text-color); border:1px solid var(--input-border); border-radius:5px; padding:10px;'>"+ graph_dot_code +"</textarea>" if graph_dot_code else ""}
        """


    html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Wallet Reputation Report - {target_address[:10]}...</title>
        <style>
            {custom_css}
        </style>
    </head>
    <body>
        <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Light Mode</button>
        <div class="header">
            <h1>XenoByte Wallet Forensic Report</h1>
            <p class="subtitle">Analysis for Target Wallet: <strong>{target_address}</strong> (Tracing Depth: {forensic_report_data['max_tracing_depth']})</p>
            <p class="subtitle">Generated: {current_time}</p>
        </div>
        <div class="content-section">

            <div class="reputation-score {overall_reputation_class}">
                Overall Reputation: {overall_reputation_text}
            </div>

            <h2>Basic Information</h2>
            <div class="section-content">
                <p class="info-item"><strong>Current Balance:</strong> {target_wallet_data.get('balance_eth', 0):.8f} ETH</p>
                <p class="info-item"><strong>Total Transactions:</strong> {target_wallet_data.get('total_transactions', 0)}</p>
                <p class="info-item"><strong>Last Transaction:</strong> {target_wallet_data.get('last_transaction_time_utc', 'N/A')}</p>
                <p class="info-item"><strong>Blockchain Type:</strong> Ethereum</p>
                <p class="info-item"><strong>Inferred Wallet Type:</strong> {target_wallet_data.get('wallet_type_inferred', 'Uncertain')}</p>
            </div>

            <h2>Threat Intelligence Insights</h2>
            <div class="section-content">
                {
                    f'<p class="threat-detected">This cryptocurrency wallet has been identified as being involved in malicious cyber activities, including its use in ransomware attacks, malware operations, and the collection of illicit funds from victims, making it a critical indicator in threat intelligence investigations.' +
                    (f' Associated Family: <strong>{", ".join(target_wallet_data["ransomware_family_api"])}</strong>.' if target_wallet_data["ransomware_family_api"] else '') +
                    '</p>'
                    if is_ransomware_local or is_ransomware_api
                    else '<p class="analysis-clean">This wallet has no known associations with ransomware or malware addresses in our current intelligence feeds.</p>'
                }
            </div>

            <h2>Behavioral & Pattern Analysis</h2>
            <div class="section-content">
                <ul>
                    {behavioral_analysis_html}
                </ul>
            </div>

            <h2>Chainabuse Reports</h2>
            <div class="section-content">
                <p><strong>Total Reports on Chainabuse:</strong> <a href="{target_wallet_data.get('chainabuse_reports', {}).get('url_scraped', '#')}" target="_blank">{target_wallet_data.get('chainabuse_reports', {}).get('total_reports_count', 0)}</a></p>
                {chainabuse_reports_html}
            </div>

            <h2>Transaction Flow Graph</h2>
            <div class="section-content">
                {graph_embed_html}
                <p>Nodes represent wallet addresses. Edges represent transactions, with labels indicating the amount of ETH transferred. Colors indicate reputation:</p>
                <ul>
                    <li><span style="color: #6999FC; font-weight: bold;">&#9632;</span> Target Wallet</li>
                    <li><span style="color: #e53935; font-weight: bold;">&#9632;</span> Malicious / High Risk Wallet</li>
                    <li><span style="color: #ffeb3b; font-weight: bold;">&#9632;</span> Suspicious / Moderate Risk Wallet</li>
                    <li><span style="color: #47ff47; font-weight: bold;">;">&#9632;</span> Clean / Low Risk Wallet</li>
                </ul>
            </div>

            <h2>Detailed Wallet Information ({len(analyzed_wallets)} wallets analyzed)</h2>
            <div class="section-content">
                {detailed_wallets_html}
            </div>

        </div>
        <footer class="xeno-footer">
            <p>&copy; 2025 XenoByte Threat Intelligence. All rights reserved.</p>
            <p>Data from various public and open-source intelligence feeds.</p>
        </footer>
        <script>
            function toggleTheme() {{
                document.body.classList.toggle('light-theme');
                let isLight = document.body.classList.contains('light-theme');
                localStorage.setItem('theme', isLight ? 'light' : 'dark');
                document.getElementById('theme-toggle-button').textContent = isLight ? 'Dark Mode' : 'Light Mode';
            }}

            // Apply theme on load
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

