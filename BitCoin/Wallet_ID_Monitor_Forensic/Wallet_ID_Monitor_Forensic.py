import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timedelta, timezone
from playwright.sync_api import sync_playwright
import re
from collections import defaultdict
import urllib.parse
import subprocess
import base64
import sys # Import sys for command-line arguments and stderr redirection
import argparse # Import argparse for robust argument parsing

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

DOT_EXECUTABLE_PATH = r"C:\Program Files\Graphviz\bin\dot.exe"

# Blockchain.info APIs
BLOCKCHAIN_INFO_API = "https://blockchain.info/rawaddr/{address}?format=json"
BLOCKCHAIN_INFO_RAW_TX_API = "https://blockchain.info/rawtx/{tx_hash}?format=json"

# BlockCypher APIs (Public API, no token needed for basic usage, but limits apply)
BLOCKCYPHER_API_BASE = "https://api.blockcypher.com/v1/btc/main"
BLOCKCYPHER_ADDR_API = f"{BLOCKCYPHER_API_BASE}/addrs/{{address}}/full?limit=2000"
BLOCKCYPHER_TX_API = f"{BLOCKCYPHER_API_BASE}/txs/{{tx_hash}}"

# Blockchair APIs (Public API, no token needed for basic usage, but limits apply)
BLOCKCHAIR_API_BASE = "https://api.blockchair.com/bitcoin"
BLOCKCHAIR_ADDR_API = f"{BLOCKCHAIR_API_BASE}/dashboards/address/{{address}}"
BLOCKCHAIR_TX_API = f"{BLOCKCHAIR_API_BASE}/dashboards/transaction/{{tx_hash}}"

API_DELAY_SECONDS = 5

# --- Global Data Caching for Forensic Tool ---
GLOBAL_ANALYZED_WALLETS = {}
GLOBAL_TRANSACTION_GRAPH = defaultdict(lambda: {'sent_to': defaultdict(float), 'received_from': defaultdict(float)})
GLOBAL_VISITED_TXS = set()
GLOBAL_QUEUE = []
GLOBAL_MAX_DEPTH = 2

# Initialize global variables for caching
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = []

# --- Helper Functions (All helper functions defined before their first call) ---

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
    if not ransomware_api_addresses:
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...", file=sys.stderr)
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=10)
            response.raise_for_status()
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

def scrape_chainabuse_address_reports(address: str) -> dict:
    """
    Scrapes all scam reports for a given cryptocurrency address from Chainabuse.
    Uses Playwright's synchronous API.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed. Please install it: pip install playwright && playwright install", file=sys.stderr)
        return {"total_reports_count": 0, "reports": [], "error": "Playwright not installed"}

    base_url = "https://chainabuse.com/address/"
    url = f"{base_url}{address}"
    
    all_reports_data = {
        "address": address,
        "url_scraped": url,
        "total_reports_count": 0,
        "reports": []
    }

    print(f"Fetching Chainabuse data for {address} from: {url}", file=sys.stderr)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            try:
                page.goto(url, timeout=60000)

                try:
                    total_reports_text_element = page.locator("h3.create-ResultsSection__results-title, p:has-text('No reports found for this address.')").first
                    if total_reports_text_element.count() > 0:
                        total_reports_text = total_reports_text_element.text_content().strip()
                        match = re.search(r'(\d+)\s+Scam Reports', total_reports_text)
                        if match:
                            all_reports_data["total_reports_count"] = int(match.group(1))
                    else:
                        no_reports_element = page.locator("p:has-text('No reports found for this address.')").first
                        if no_reports_element.count() > 0:
                            all_reports_data["total_reports_count"] = 0
                except Exception as e:
                    print(f"Chainabuse: Could not extract total reports count: {e}", file=sys.stderr)

                report_cards = page.locator(".create-ScamReportCard").all()
                
                for i, card in enumerate(report_cards):
                    report_details = {}
                    try:
                        category_element = card.locator("p.create-Text.type-body-lg-heavy.create-ScamReportCard__category-label").first
                        if category_element.count() > 0:
                            report_details["category"] = category_element.text_content().strip()
                    except Exception:
                        report_details["category"] = "N/A"

                    try:
                        description_element = card.locator(".create-ScamReportCard__preview-description .create-LexicalViewer .create-Editor__paragraph span").first
                        if description_element.count() > 0:
                            report_details["description"] = description_element.text_content().strip()
                        else:
                            direct_description_element = card.locator(".create-ScamReportCard__preview-description .create-LexicalViewer .create-Editor__paragraph").first
                            if direct_description_element.count() > 0:
                                report_details["description"] = direct_description_element.text_content().strip()
                    except Exception:
                        report_details["description"] = "N/A"

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
                    except Exception:
                        report_details["submitted_by"] = "N/A"
                        report_details["submitted_date"] = "N/A"

                    reported_addresses_in_card = []
                    try:
                        address_elements = card.locator(".create-ReportedSection .create-ResponsiveAddress__text").all()
                        for addr_elem in address_elements:
                            reported_addresses_in_card.append(addr_elem.text_content().strip())
                    except Exception:
                        pass
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

def get_blockchain_info_blockchain_info(address):
    """Fetches blockchain data for a Bitcoin address from blockchain.info."""
    url = BLOCKCHAIN_INFO_API.format(address=address)
    print(f"  Trying blockchain.info for address {address}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        return data
    except requests.exceptions.RequestException as e:
        print(f"  blockchain.info failed for {address}: {e}", file=sys.stderr)
    return None

def get_blockchain_info_blockcypher(address):
    """
    Fetches blockchain data for a Bitcoin address from BlockCypher.
    Normalizes the output to be similar to blockchain.info's rawaddr format.
    """
    url = BLOCKCYPHER_ADDR_API.format(address=address)
    print(f"  Trying BlockCypher for address {address}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)

        normalized_data = {
            "address": data.get("address"),
            "final_balance": data.get("final_balance", 0), # in satoshis
            "n_tx": data.get("n_tx", 0), # total transactions
            "total_received": data.get("total_received", 0), # in satoshis
            "total_sent": data.get("total_sent", 0), # in satoshis
            "txs": [] # List of transactions
        }
        
        if 'txs' in data and isinstance(data['txs'], list):
            for tx in data['txs']:
                normalized_data['txs'].append({
                    'hash': tx.get('hash'),
                    'time': datetime.strptime(tx['confirmed'], '%Y-%m-%dT%H:%M:%SZ').timestamp() if 'confirmed' in tx else None,
                    'fee': tx.get('fees', 0),
                    'inputs': [{'prev_out': {'addr': inp['addresses'][0], 'value': inp['output_value']}} for inp in tx['inputs'] if inp.get('addresses') and inp.get('output_value') is not None],
                    'out': [{'addr': out['addresses'][0], 'value': out['value']} for out in tx['outputs'] if out.get('addresses') and out.get('value') is not None]
                })

        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  BlockCypher failed for {address}: {e}", file=sys.stderr)
    except ValueError as e:
        print(f"  BlockCypher data parsing error for {address}: {e}", file=sys.stderr)
    return None

def get_blockchain_info_blockchair(address):
    """
    Fetches blockchain data for a Bitcoin address from Blockchair.
    Normalizes the output to be similar to blockchain.info's rawaddr format.
    """
    url = BLOCKCHAIR_ADDR_API.format(address=address)
    print(f"  Trying Blockchair for address {address}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)

        address_data = data.get('data', {}).get(address, {}).get('address', {})
        transactions_data = data.get('data', {}).get(address, {}).get('transactions', [])

        normalized_data = {
            "address": address_data.get("address"),
            "final_balance": address_data.get("balance", 0),
            "n_tx": address_data.get("transaction_count", 0),
            "total_received": address_data.get("received", 0),
            "total_sent": address_data.get("spent", 0),
            "txs": []
        }
        
        for tx_hash_item in transactions_data:
            normalized_data['txs'].append({'hash': tx_hash_item})

        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  Blockchair failed for {address}: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"  Blockchair JSON decoding error for {address}: {e}", file=sys.stderr)
    return None

def get_blockchain_info_multi_source(address):
    """
    Attempts to fetch blockchain data for an address from multiple sources.
    Returns the first successful result.
    """
    data = get_blockchain_info_blockchain_info(address)
    if data and data.get('txs'):
        return data
    
    data = get_blockchain_info_blockcypher(address)
    if data and data.get('txs'):
        return data

    data = get_blockchain_info_blockchair(address)
    if data and data.get('txs'):
        return data
    
    print(f"  Failed to get comprehensive blockchain info for {address} from all sources.", file=sys.stderr)
    return None

def analyze_wallet_transactions_behavioral(address, blockchain_data):
    """
    Analyzes wallet transactions based on defined rules for behavioral patterns.
    """
    analysis_results = {
        "wallet_type_inferred": "Uncertain",
        "red_flags": [],
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
    }

    txs = blockchain_data.get('txs', [])
    total_transactions = len(txs)

    if not txs:
        analysis_results["red_flags"].append("No transactions found for this address for behavioral analysis.")
        return analysis_results

    txs_with_time = [tx for tx in txs if tx.get('time') is not None]
    txs_with_time.sort(key=lambda x: x.get('time', 0), reverse=True)

    if txs_with_time:
        last_tx_time = txs_with_time[0].get('time')
        if last_tx_time:
            one_year_ago = datetime.now(timezone.utc) - timedelta(days=365)
            if datetime.fromtimestamp(last_tx_time, timezone.utc) < one_year_ago:
                analysis_results["dormant_for_over_a_year"] = True
                analysis_results["red_flags"].append("Dormant for over a year.")

    if total_transactions > 500:
        analysis_results["high_transaction_count"] = True
        analysis_results["wallet_type_inferred"] = "Potentially Exchange or Mixer"
        analysis_results["red_flags"].append(f"High transaction count ({total_transactions}). Potentially an exchange or mixer.")
    elif total_transactions > 100:
        analysis_results["wallet_type_inferred"] = "Active Personal / Minor Service"
    else:
        analysis_results["wallet_type_inferred"] = "Personal Wallet"

    prev_tx_time = None
    for tx in txs_with_time:
        current_tx_time = tx.get('time')
        if prev_tx_time is not None and current_tx_time is not None:
            time_diff = abs(prev_tx_time - current_tx_time)
            
            if time_diff < 5:
                analysis_results["extremely_rapid_transactions_detected"] = True
                analysis_results["red_flags"].append(f"Extremely rapid transfers detected (< 5s between transactions), suggesting automation.")
            
            if 5 <= time_diff <= 60:
                analysis_results["automated_transactions_detected"] = True
                analysis_results["automated_transactions_time_diff"] = f"{time_diff}s"
                analysis_results["red_flags"].append(f"Rapid transfers detected (5s-1min between transactions), suggesting automation.")

            if time_diff < 5 * 60:
                analysis_results["rapid_transactions_detected"] = True
            
            if time_diff < 5 * 24 * 60 * 60:
                analysis_results["frequent_transactions_detected"] = True

        prev_tx_time = current_tx_time

    for tx in txs:
        tx_hash = tx.get('hash')
        outputs = tx.get('out', [])
        inputs = tx.get('inputs', [])

        if not outputs or not inputs:
            full_tx_details = get_transaction_details_multi_source(tx_hash)
            if full_tx_details:
                outputs = full_tx_details.get('out', [])
                inputs = full_tx_details.get('inputs', [])

        if not outputs and not inputs:
            continue

        for out in outputs:
            if out.get('addr') == address:
                amount = out.get('value', 0)
                if amount > 10 * 100_000_000:
                    analysis_results["large_amount_received"] = True
                    analysis_results["red_flags"].append(f"Large amount received ({amount / 100_000_000.0:.8f} BTC) in transaction {tx_hash}.")
                    
                is_sender_in_this_tx = any(inp.get('prev_out', {}).get('addr') == address for inp in inputs)
                if is_sender_in_this_tx and len(outputs) > 10:
                    small_outputs_count = 0
                    for op in outputs:
                        if op.get('value', 0) < 5000:
                            small_outputs_count += 1
                    if small_outputs_count / len(outputs) > 0.8:
                        analysis_results["dust_attack_pattern"] = True
                        analysis_results["red_flags"].append(f"Potential dust attack pattern (many tiny outputs) in transaction {tx_hash}.")

        fee = tx.get('fee')
        if fee is None:
            full_tx_details = get_transaction_details_multi_source(tx_hash)
            if full_tx_details:
                fee = full_tx_details.get('fee')

        if fee is not None:
            if fee > 500_000:
                analysis_results["high_transaction_fee_detected"] = True
                analysis_results["red_flags"].append(f"High transaction fee detected (~{fee / 100_000_000.0:.5f} BTC) in transaction {tx_hash}.")

    if total_transactions > 50:
         analysis_results["red_flags"].append("Address appears to be reused multiple times (low privacy).")

    return analysis_results

def get_transaction_details_blockchain_info(tx_hash: str) -> dict:
    """
    Fetches detailed transaction data for a Bitcoin transaction hash from blockchain.info.
    """
    url = BLOCKCHAIN_INFO_RAW_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying blockchain.info for transaction {tx_hash}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        return data
    except requests.exceptions.RequestException as e:
        print(f"  blockchain.info failed for transaction {tx_hash}: {e}", file=sys.stderr)
    return None

def get_transaction_details_blockcypher(tx_hash: str) -> dict:
    """
    Fetches detailed transaction data for a Bitcoin transaction hash from BlockCypher.
    Normalizes the output to be similar to blockchain.info's rawtx format.
    """
    url = BLOCKCYPHER_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying BlockCypher for transaction {tx_hash}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)

        normalized_data = {
            "hash": data.get("hash"),
            "time": datetime.strptime(data['confirmed'], '%Y-%m-%dT%H:%M:%SZ').timestamp() if 'confirmed' in data else None,
            "block_height": data.get("block_height"),
            "fee": data.get("fees", 0),
            "size": data.get("size", 0),
            "inputs": [],
            "out": []
        }

        for inp in data.get("inputs", []):
            if inp.get('addresses') and inp.get('output_value') is not None:
                normalized_data['inputs'].append({
                    'prev_out': {
                        'addr': inp['addresses'][0],
                        'value': inp['output_value']
                    }
                })
        
        for out in data.get("outputs", []):
            if out.get('addresses') and out.get('value') is not None:
                normalized_data['out'].append({
                    'addr': out['addresses'][0],
                    'value': out['value']
                })
        
        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  BlockCypher failed for transaction {tx_hash}: {e}", file=sys.stderr)
    except ValueError as e:
        print(f"  BlockCypher data parsing error for {tx_hash}: {e}", file=sys.stderr)
    return None

def get_transaction_details_blockchair(tx_hash: str) -> dict:
    """
    Fetches detailed transaction data for a Bitcoin transaction hash from Blockchair.
    Normalizes the output to be similar to blockchain.info's rawtx format.
    """
    url = BLOCKCHAIR_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying Blockchair for transaction {tx_hash}...", file=sys.stderr)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)

        tx_info = data.get('data', {}).get(tx_hash, {}).get('transaction', {})
        inputs_info = data.get('data', {}).get(tx_hash, {}).get('inputs', [])
        outputs_info = data.get('data', {}).get(tx_hash, {}).get('outputs', [])

        normalized_data = {
            "hash": tx_info.get("hash"),
            "time": tx_info.get("time"),
            "block_height": tx_info.get("block_id"),
            "fee": tx_info.get("fee", 0),
            "size": tx_info.get("size", 0),
            "inputs": [],
            "out": []
        }

        for inp in inputs_info:
            if inp.get('recipient') and inp.get('value') is not None:
                normalized_data['inputs'].append({
                    'prev_out': {
                        'addr': inp['recipient'],
                        'value': inp['value']
                    }
                })
        
        for out in outputs_info:
            if out.get('recipient') and out.get('value') is not None:
                normalized_data['out'].append({
                    'addr': out['recipient'],
                    'value': out['value']
                })
        
        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  Blockchair failed for transaction {tx_hash}: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"  Blockchair JSON decoding error for transaction {tx_hash}: {e}", file=sys.stderr)
    return None

def get_transaction_details_multi_source(tx_hash: str) -> dict:
    """
    Attempts to fetch transaction details from multiple sources.
    Returns the first successful result.
    """
    data = get_transaction_details_blockchain_info(tx_hash)
    if data and data.get('hash'):
        return data
    
    data = get_transaction_details_blockcypher(tx_hash)
    if data and data.get('hash'):
        return data

    data = get_transaction_details_blockchair(tx_hash)
    if data and data.get('hash'):
        return data
    
    print(f"  Failed to get comprehensive transaction details for {tx_hash} from all sources.", file=sys.stderr)
    return None

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

    wallet_data = {
        "address": wallet_address,
        "depth": current_depth,
        "is_ransomware_local": False,
        "is_ransomware_api": False,
        "ransomware_family_api": [],
        "blockchain_type": "Unknown",
        "balance_btc": 0,
        "total_transactions": 0,
        "last_transaction_time_utc": "N/A",
        "wallet_type_inferred": "Uncertain",
        "red_flags": [],
        "chainabuse_reports": {},
        "incoming_tx_value_sum_traced": 0.0,
        "outgoing_tx_value_sum_traced": 0.0,
        "tx_hashes_involved": set(),
        "directly_sent_to_target": 0.0,
        "directly_received_from_target": 0.0
    }
    GLOBAL_ANALYZED_WALLETS[wallet_address] = wallet_data

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
    if not isinstance(chainabuse_data, dict):
        chainabuse_data = {"total_reports_count": 0, "reports": [], "url_scraped": f"https://chainabuse.com/address/{wallet_address}"}
    
    wallet_data["chainabuse_reports"] = chainabuse_data
    if chainabuse_data.get("total_reports_count", 0) > 0:
        wallet_data["red_flags"].append(f"Found {chainabuse_data.get('total_reports_count', 0)} scam report(s) on Chainabuse.")
        for report in chainabuse_data.get("reports", []):
            if "ransomware" in report.get("category", "").lower():
                wallet_data["red_flags"].append(f"Chainabuse report indicates Ransomware activity (Category: {report.get('category')}).")

    blockchain_data = None
    if is_target_wallet:
        blockchain_data = get_blockchain_info_multi_source(wallet_address)
        if blockchain_data:
            wallet_data["blockchain_type"] = "Bitcoin"
            wallet_data["balance_btc"] = blockchain_data.get('final_balance', 0) / 100_000_000.0
            wallet_data["total_transactions"] = blockchain_data.get('n_tx', 0)

            behavioral_analysis_results = analyze_wallet_transactions_behavioral(wallet_address, blockchain_data)
            for key, value in behavioral_analysis_results.items():
                if key == "red_flags":
                    wallet_data["red_flags"].extend(value)
                else:
                    wallet_data[key] = value
    else:
        minimal_blockchain_data = get_blockchain_info_multi_source(wallet_address)
        if minimal_blockchain_data:
            wallet_data["blockchain_type"] = "Bitcoin"
            wallet_data["balance_btc"] = minimal_blockchain_data.get('final_balance', 0) / 100_000_000.0
            wallet_data["total_transactions"] = minimal_blockchain_data.get('n_tx', 0)
            if minimal_blockchain_data.get('txs'):
                txs_with_time = [tx for tx in minimal_blockchain_data['txs'] if tx.get('time') is not None]
                if txs_with_time:
                    last_tx_time = sorted(txs_with_time, key=lambda x: x.get('time', 0), reverse=True)[0].get('time')
                    if last_tx_time:
                        wallet_data["last_transaction_time_utc"] = datetime.fromtimestamp(last_tx_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    if blockchain_data or minimal_blockchain_data:
        current_txs_list = blockchain_data.get('txs', []) if blockchain_data else minimal_blockchain_data.get('txs', [])
        
        txs_to_process = current_txs_list
        if GLOBAL_MAX_DEPTH != -1 and not is_target_wallet and len(txs_to_process) > 10:
            print(f"  [DEBUG] Limiting transaction processing for {wallet_address} to 10 most recent transactions for graph building.", file=sys.stderr)
            txs_to_process = txs_to_process[:10]

        for tx_item in txs_to_process:
            tx_hash = tx_item.get('hash')
            if not tx_hash:
                print(f"  [DEBUG] Skipping transaction with no hash.", file=sys.stderr)
                continue
            if tx_hash in GLOBAL_VISITED_TXS:
                print(f"  [DEBUG] Transaction {tx_hash[:10]}... already visited. Skipping.", file=sys.stderr)
                continue
            GLOBAL_VISITED_TXS.add(tx_hash)
            wallet_data["tx_hashes_involved"].add(tx_hash)

            tx_details = get_transaction_details_multi_source(tx_hash)
            if not tx_details:
                print(f"  [DEBUG] Could not get details for transaction {tx_hash[:10]}... Skipping.", file=sys.stderr)
                continue

            current_tx_senders = set()
            for vin in tx_details.get("inputs", []):
                prev_out = vin.get("prev_out", {})
                sender_addr = prev_out.get("addr")
                if sender_addr:
                    current_tx_senders.add(sender_addr)

            current_tx_receivers = set()
            for vout in tx_details.get("out", []):
                receiver_addr = vout.get("addr")
                value = vout.get("value", 0)
                if receiver_addr:
                    current_tx_receivers.add(receiver_addr)
                    amount_btc = value / 100_000_000.0

                    for sender_addr in current_tx_senders:
                        if sender_addr != receiver_addr:
                            GLOBAL_TRANSACTION_GRAPH[sender_addr]['sent_to'][receiver_addr] += amount_btc
                            GLOBAL_TRANSACTION_GRAPH[receiver_addr]['received_from'][sender_addr] += amount_btc

                            def ensure_wallet_initialized(addr):
                                if addr not in GLOBAL_ANALYZED_WALLETS:
                                    GLOBAL_ANALYZED_WALLETS[addr] = {
                                        "address": addr,
                                        "incoming_tx_value_sum_traced": 0.0,
                                        "outgoing_tx_value_sum_traced": 0.0,
                                        "depth": float('inf'),
                                        "red_flags": [],
                                        "chainabuse_reports": {},
                                        "directly_sent_to_target": 0.0,
                                        "directly_received_from_target": 0.0,
                                        "tx_hashes_involved": set() # Initialized as a set
                                    }
                            ensure_wallet_initialized(sender_addr)
                            ensure_wallet_initialized(receiver_addr)

                            if hasattr(perform_forensic_analysis, 'target_address') and sender_addr == perform_forensic_analysis.target_address:
                                GLOBAL_ANALYZED_WALLETS[receiver_addr]['directly_received_from_target'] += amount_btc
                            if hasattr(perform_forensic_analysis, 'target_address') and receiver_addr == perform_forensic_analysis.target_address:
                                GLOBAL_ANALYZED_WALLETS[sender_addr]['directly_sent_to_target'] += amount_btc
                            
                            GLOBAL_ANALYZED_WALLETS[receiver_addr]['incoming_tx_value_sum_traced'] += amount_btc
                            GLOBAL_ANALYZED_WALLETS[sender_addr]['outgoing_tx_value_sum_traced'] += amount_btc

            all_involved_addresses = current_tx_senders.union(current_tx_receivers)
            for new_addr in all_involved_addresses:
                if new_addr != wallet_address and new_addr not in GLOBAL_ANALYZED_WALLETS:
                    if GLOBAL_MAX_DEPTH == -1 or (GLOBAL_MAX_DEPTH != -1 and current_depth + 1 <= GLOBAL_MAX_DEPTH):
                        print(f"  [DEBUG] Queuing new address {new_addr[:10]}... for depth {current_depth + 1}.", file=sys.stderr)
                    else:
                        print(f"  [DEBUG] Address {new_addr[:10]}... found, but max depth ({GLOBAL_MAX_DEPTH}) would be exceeded. Skipping queueing.", file=sys.stderr)
                    GLOBAL_QUEUE.append((new_addr, current_depth + 1)) # Still add to queue regardless of depth limit for processing in main loop
                else:
                    if new_addr != wallet_address:
                        print(f"  [DEBUG] Address {new_addr[:10]}... already in GLOBAL_ANALYZED_WALLETS. Skipping queueing.", file=sys.stderr)

def perform_forensic_analysis(target_address: str, max_depth: int = 2) -> dict:
    """
    Performs a forensic analysis on a target Bitcoin wallet address, tracing its transactions and analyzing connected wallets.
    """
    global GLOBAL_ANALYZED_WALLETS, GLOBAL_TRANSACTION_GRAPH, GLOBAL_VISITED_TXS, GLOBAL_QUEUE, GLOBAL_MAX_DEPTH

    perform_forensic_analysis.target_address = target_address

    # Reset global states for a new analysis
    GLOBAL_ANALYZED_WALLETS = {}
    GLOBAL_TRANSACTION_GRAPH = defaultdict(lambda: {'sent_to': defaultdict(float), 'received_from': defaultdict(float)})
    GLOBAL_VISITED_TXS = set()
    GLOBAL_QUEUE = []
    GLOBAL_MAX_DEPTH = max_depth

    # Start tracing from the target address
    GLOBAL_QUEUE.append((target_address, 0))

    print(f"\n[DEBUG] Initial GLOBAL_QUEUE: {GLOBAL_QUEUE}", file=sys.stderr)

    while GLOBAL_QUEUE:
        current_addr, current_depth = GLOBAL_QUEUE.pop(0)
        print(f"[DEBUG] Processing from queue: {current_addr[:10]}... at depth {current_depth}", file=sys.stderr)
        is_target = (current_addr == target_address)
        trace_wallet_transactions_recursive(current_addr, current_depth, is_target_wallet=is_target)
        print(f"[DEBUG] GLOBAL_QUEUE after processing {current_addr[:10]}...: {len(GLOBAL_QUEUE)} items remaining.", file=sys.stderr)

    forensic_results = {
        "target_address": target_address,
        "max_tracing_depth": "Full" if max_depth == -1 else max_depth,
        "analyzed_wallets": {},
        "transaction_graph_edges": [],
        "transaction_graph_svg_base64": None,
        "summary_data": {
            "total_wallets_analyzed": len(GLOBAL_ANALYZED_WALLETS),
            "total_malicious_wallets": 0,
            "total_suspicious_wallets": 0,
            "wallets_with_chainabuse_reports": 0,
            "cold_wallets_identified": [],
            "top_receivers_in_flow": [],
            "top_senders_in_flow": []
        },
        "flagged_wallets": [],
        "unflagged_wallets": [],
        "directly_connected_wallets": []
    }

    for addr, data in GLOBAL_ANALYZED_WALLETS.items():
        if isinstance(data.get('tx_hashes_involved'), set):
            data['tx_hashes_involved'] = list(data['tx_hashes_involved'])
        else:
            data['tx_hashes_involved'] = data.get('tx_hashes_involved', [])

        forensic_results['analyzed_wallets'][addr] = data

        has_flags = False
        if data.get('is_ransomware_local') or data.get('is_ransomware_api'):
            forensic_results["summary_data"]["total_malicious_wallets"] += 1
            has_flags = True
        
        other_red_flags = [flag for flag in data.get('red_flags', []) if "Address appears to be reused" not in flag]
        if other_red_flags:
            forensic_results["summary_data"]["total_suspicious_wallets"] += 1
            has_flags = True

        if data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
            forensic_results["summary_data"]["wallets_with_chainabuse_reports"] += 1
            has_flags = True

        if data.get('balance_btc', 0) > 1.0 and data.get('dormant_for_over_a_year', False):
            forensic_results["summary_data"]["cold_wallets_identified"].append(addr)

        if has_flags:
            forensic_results["flagged_wallets"].append(addr)
        else:
            if not data.get('is_ransomware_local') and \
               not data.get('is_ransomware_api') and \
               not data.get('red_flags') and \
               data.get('chainabuse_reports', {}).get('total_reports_count', 0) == 0:
                forensic_results["unflagged_wallets"].append(addr)

        if data.get('directly_sent_to_target') > 0 or data.get('directly_received_from_target') > 0:
            forensic_results["directly_connected_wallets"].append(addr)

    for sender, connections in GLOBAL_TRANSACTION_GRAPH.items():
        for receiver, amount in connections['sent_to'].items():
            if sender in forensic_results['analyzed_wallets'] and receiver in forensic_results['analyzed_wallets']:
                forensic_results['transaction_graph_edges'].append({
                    "sender": sender,
                    "receiver": receiver,
                    "amount_btc": amount
                })
    
    # Generate Graphviz SVG Base64 string
    dot_graph_code_raw = """digraph G {
  rankdir=LR;
  node [shape=box, style="rounded,filled", fillcolor="#1a1a1a", fontcolor="#00f5d4", color="#00ff88"];
  edge [color="#00f5d4", fontcolor="#ccc"];
"""
    graph_addresses = set()
    has_edges = False

    for addr, data in forensic_results['analyzed_wallets'].items():
        label_addr = addr[:10] + "..." + addr[-4:]
        node_color = "#00ff88"
        fill_color = "#1a1a1a"
        prefix = ""

        if addr == forensic_results['target_address']:
            label_addr = f"TARGET\\n{label_addr}"
            node_color = "#6999FC"
            fill_color = "#002040"
        elif data.get('is_ransomware_local') or data.get('is_ransomware_api') or data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
            node_color = "#e53935"
            fill_color = "#330a0a"
            if data.get('is_ransomware_local') or data.get('is_ransomware_api'):
                prefix = "MALICIOUS\\n"
            elif data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
                prefix = "REPORTED\\n"
            label_addr = f"{prefix}{label_addr}"
        elif data.get('red_flags'):
            node_color = "#ffeb3b"
            fill_color = "#33330a"
            prefix = "SUSPICIOUS\\n"
            label_addr = f"{prefix}{label_addr}"

        dot_graph_code_raw += f'  "{addr}" [label="{label_addr}", color="{node_color}", fillcolor="{fill_color}"];\n'
        graph_addresses.add(addr)

    for sender, connections in GLOBAL_TRANSACTION_GRAPH.items():
        for receiver, amount in connections['sent_to'].items():
            if sender in graph_addresses and receiver in graph_addresses:
                dot_graph_code_raw += f'  "{sender}" -> "{receiver}" [label="{amount:.4f} BTC"];\n'
                has_edges = True
    
    dot_graph_code_raw += "}"

    if graph_addresses and has_edges:
        try:
            process = subprocess.run(
                [DOT_EXECUTABLE_PATH, "-Tsvg"],
                input=dot_graph_code_raw.encode('utf-8'),
                capture_output=True,
                check=True
            )
            svg_data = process.stdout
            encoded_svg = base64.b64encode(svg_data).decode('utf-8')
            forensic_results['transaction_graph_svg_base64'] = f"data:image/svg+xml;base64,{encoded_svg}"
        except FileNotFoundError:
            print(f"Error: Graphviz 'dot' executable not found at '{DOT_EXECUTABLE_PATH}'. Graph SVG will not be generated.", file=sys.stderr)
            forensic_results['transaction_graph_svg_base64'] = f"ERROR: Graphviz 'dot' executable not found at '{DOT_EXECUTABLE_PATH}'. Please ensure Graphviz is installed and the path is correct."
        except subprocess.CalledProcessError as e:
            print(f"Error generating graph with Graphviz: {e.stderr.decode('utf-8')}", file=sys.stderr)
            forensic_results['transaction_graph_svg_base64'] = f"ERROR: Graphviz generation failed: {e.stderr.decode('utf-8')}"
        except Exception as e:
            print(f"An unexpected error occurred during graph generation: {e}", file=sys.stderr)
            forensic_results['transaction_graph_svg_base64'] = f"ERROR: Unexpected error during graph generation: {e}"
    else:
        forensic_results['transaction_graph_svg_base64'] = "No sufficient data to generate a transaction graph."


    forensic_results["summary_data"]["top_senders_in_flow"].sort(key=lambda x: x['amount_btc'], reverse=True)
    forensic_results["summary_data"]["top_receivers_in_flow"].sort(key=lambda x: x['amount_btc'], reverse=True)

    return forensic_results


# --- HTML Report Generation (kept for direct script use) ---
# (This function remains unchanged, but won't be called if --json-output is used)
def generate_forensic_report(forensic_data: dict) -> str:
    """
    Generates an HTML report from the forensic analysis data.
    """
    target_address = forensic_data['target_address']
    analyzed_wallets = forensic_data['analyzed_wallets']
    summary = forensic_data['summary_data']

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Forensic Report - {target_address[:10]}...</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto:wght@400;700&display=swap');
            :root {{
                --bg-color: #0a0a0a;
                --box-color: #121212;
                --text-color: #00f5d4;
                --accent: #00ff88;
                --footer-bg: #111;
                --footer-text: #ccc;
                --input-bg: #1e1e1e;
                --input-border: #00f5d4;
            }}
            body.light-theme {{
                --bg-color: #f9f9f9;
                --box-color: #ffffff;
                --text-color: #111;
                --accent: #00c47a;
                --footer-bg: #eaeaea;
                --footer-text: #333;
                --input-bg: #f0f0f0;
                --input-border: #00c47a;
            }}
            html, body {{
                min-height: 100vh;
                margin: 0;
                padding: 0;
                font-family: 'Roboto', sans-serif;
                background-color: var(--bg-color);
                color: var(--text-color);
                display: flex;
                flex-direction: column;
                transition: background-color 0.4s, color 0.4s;
            }}
            .header {{
                text-align: center;
                padding: 20px;
                background-color: var(--box-color);
                border-bottom: 2px solid var(--accent);
                box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                z-index: 10;
                position: sticky;
                top: 0;
            }}
            h1 {{
                margin: 0;
                color: var(--text-color);
                font-family: 'Orbitron', sans-serif;
                font-size: 2.5em;
                text-shadow: 0 0 8px var(--accent);
            }}
            .subtitle {{
                color: var(--footer-text);
                font-size: 1.1em;
                margin-top: 5px;
            }}
            .content-section {{
                padding: 20px;
                width: 95%;
                margin: 20px auto;
                background-color: var(--box-color);
                border-radius: 10px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.4);
                line-height: 1.6;
                flex-grow: 1;
                box-sizing: border-box;
            }}
            @media (max-width: 768px) {{
                .content-section {{
                    width: 95%;
                    padding: 15px;
                }}
            }}
            .content-section h2, .content-section h3 {{
                color: var(--accent);
                border-bottom: 1px solid var(--text-color);
                padding-bottom: 10px;
                margin-top: 30px;
                margin-bottom: 20px;
                font-family: 'Orbitron', sans-serif;
            }}
            .content-section p, .content-section table {{
                margin-bottom: 10px;
                color: var(--footer-text);
            }}
            .content-section ul {{
                padding-left: 25px;
                list-style: disc;
                margin-top: 0;
                margin-bottom: 0;
            }}
            .content-section ul li {{
                margin-bottom: 8px;
                padding-top: 2px;
                padding-bottom: 2px;
            }}
            .content-section a {{
                color: var(--text-color);
                text-decoration: none;
            }}
            .content-section a:hover {{
                color: var(--accent);
                text-decoration: underline;
            }}
            .xeno-footer {{
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
            }}
            .xeno-footer a {{
                color: var(--text-color);
                text-decoration: none;
                transition: color 0.3s ease;
            }}
            .xeno-footer a:hover {{
                color: var(--accent);
            }}
            .toggle-theme {{
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
            }}
            .toggle-theme:hover {{
                background-color: var(--accent);
                color: #000;
                border-color: var(--accent);
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }}
            th, td {{
                border: 1px solid var(--text-color);
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: var(--accent);
                color: var(--box-color);
                font-family: 'Orbitron', sans-serif;
            }}
            .error-message {{
                color: #ff6347;
                font-weight: bold;
            }}
            .reputation-score {{
                font-size: 1.8em;
                font-weight: bold;
                text-align: center;
                padding: 15px;
                margin-bottom: 20px;
                border-radius: 5px;
                font-family: 'Orbitron', sans-serif;
            }}
            .reputation-score.malicious {{
                background-color: #3d0000;
                color: #ff4747;
                border: 2px solid #ff4747;
                box-shadow: 0 0 15px rgba(255, 71, 71, 0.5);
            }}
            .reputation-score.suspicious {{
                background-color: #3d3d00;
                color: #ffff47;
                border: 2px solid #ffff47;
                box-shadow: 0 0 15px rgba(255, 255, 71, 0.5);
            }}
            .reputation-score.clean {{
                background-color: #003d00;
                color: #47ff47;
                border: 2px solid #47ff47;
                box-shadow: 0 0 15px rgba(71, 255, 71, 0.5);
            }}

            .section-content {{
                background-color: var(--box-color);
                border: 1px solid var(--accent);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                width: 100%;
                box-sizing: border-box;
            }}
            .chainabuse-report-card {{
                background-color: #1a1a1a;
                border: 1px solid #00f5d4;
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            }}
            .chainabuse-report-card h4 {{
                color: #00ff88;
                margin-top: 0;
                margin-bottom: 10px;
                font-family: 'Orbitron', sans-serif;
                font-size: 1.2em;
            }}
            .chainabuse-report-card p {{
                margin-bottom: 5px;
                color: #ccc;
            }}
            .chainabuse-report-card strong {{
                color: #00f5d4;
            }}
            .chainabuse-report-card ul {{
                list-style: none;
                padding-left: 0;
            }}
            .chainabuse-report-card ul li {{
                margin-bottom: 3px;
            }}
            .wallet-summary-card {{
                background-color: #1a1a1a;
                border: 1px solid var(--text-color);
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                width: 100%;
                box-sizing: border-box;
            }}
            .wallet-summary-card h4 {{
                color: var(--accent);
                margin-top: 0;
                margin-bottom: 10px;
                font-family: 'Orbitron', sans-serif;
                font-size: 1.1em;
            }}
            .wallet-summary-card p {{
                margin-bottom: 5px;
                color: var(--footer-text);
            }}
            .wallet-summary-card strong {{
                color: var(--text-color);
            }}

            .graph-container {{
                overflow-x: auto;
                padding: 10px;
                border: 1px solid var(--accent);
                border-radius: 8px;
                background-color: var(--box-color);
                margin-top: 20px;
                min-height: 200px;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                width: 100%;
                box-sizing: border-box;
            }}
            .graph-container img {{
                width: 100%;
                height: auto;
                border: 1px solid var(--border-color);
                border-radius: 4px;
            }}
            .badge {{
                display: inline-block;
                padding: 5px 10px;
                border-radius: 4px;
                font-size: 0.85em;
                margin-right: 5px;
                margin-bottom: 5px;
                font-weight: bold;
            }}
            .badge-malicious {{ background-color: #e53935; color: white; }}
            .badge-suspicious {{ background-color: #ffeb3b; color: #333; }}
            .badge-info {{ background-color: var(--text-color); color: var(--box-color); }}
            .badge-success {{ background-color: var(--accent); color: var(--box-color); }}
            .badge-cold {{ background-color: #6a0dad; color: white; }}
            .wallet-detail-card {{
                margin-bottom: 10px;
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 15px;
                background-color: var(--box-color);
                box-shadow: 0 2px 5px rgba(0,0,0,0.2);
                width: 100%;
                box-sizing: border-box;
            }}
            .wallet-detail-card h3 {{
                margin-top: 0;
                margin-bottom: 10px;
                color: var(--text-color);
                border-bottom: none;
                padding-bottom: 0;
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            .wallet-detail-card h3 .address-text {{
                flex-grow: 1;
            }}
            .wallet-detail-item {{
                margin-bottom: 8px;
                color: var(--footer-text);
            }}
            .wallet-detail-item strong {{
                color: var(--text-color);
            }}
            .wallet-detail-item ul {{
                padding-left: 20px;
                margin-top: 5px;
                list-style: disc;
            }}
            .wallet-detail-item ul li {{
                margin-bottom: 3px;
            }}
            .wallet-list-summary {{
                list-style: none;
                padding: 0;
            }}
            .wallet-list-summary li {{
                background-color: var(--input-bg);
                border: 1px solid var(--input-border);
                border-radius: 5px;
                padding: 10px 15px;
                margin-bottom: 8px;
                display: flex;
                flex-wrap: wrap;
                align-items: center;
                justify-content: space-between;
            }}
            .wallet-list-summary li .address {{
                font-weight: bold;
                color: var(--accent);
                margin-right: 15px;
                word-break: break-all;
                flex-basis: 60%;
            }}
            .wallet-list-summary li .flags {{
                font-size: 0.9em;
                color: var(--footer-text);
                flex-basis: 35%;
                text-align: right;
            }}
            @media (max-width: 768px) {{
                .wallet-list-summary li {{
                    flex-direction: column;
                    align-items: flex-start;
                }}
                .wallet-list-summary li .address {{
                    margin-right: 0;
                    margin-bottom: 5px;
                    flex-basis: 100%;
                }}
                .wallet-list-summary li .flags {{
                    text-align: left;
                    flex-basis: 100%;
                }}
            }}
        </style>
    </head>
    <body>
        <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Light Mode</button>
        <div class="header">
            <h1>XenoByte Wallet Forensic Report</h1>
            <p class="subtitle">Analysis for Target Wallet: <strong>{target_address}</strong> (Tracing Depth: {forensic_data['max_tracing_depth']})</p>
            <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        <div class="content-section">
            <div class="reputation-score {'malicious' if analyzed_wallets[target_address].get('is_ransomware_local') or analyzed_wallets[target_address].get('is_ransomware_api') or analyzed_wallets[target_address].get('chainabuse_reports', {}).get('total_reports_count', 0) > 0 else 'clean'}">
                Target Wallet Reputation: {'🔴 MALICIOUS / HIGH RISK' if analyzed_wallets[target_address].get('is_ransomware_local') or analyzed_wallets[target_address].get('is_ransomware_api') or analyzed_wallets[target_address].get('chainabuse_reports', {}).get('total_reports_count', 0) > 0 else '🟢 CLEAN / LOW RISK'}
            </div>

            <h2>Overall Summary</h2>
            <div class="section-content">
                <p><strong>Total Wallets Analyzed:</strong> {summary['total_wallets_analyzed']}</p>
                <p><strong>Total Malicious Wallets Identified:</strong> {summary['total_malicious_wallets']}</p>
                <p><strong>Total Suspicious Wallets Identified:</strong> {summary['total_suspicious_wallets']}</p>
                <p><strong>Wallets with Chainabuse Reports:</strong> {summary['wallets_with_chainabuse_reports']}</p>
                
                <h3>Cold Wallets Identified (High Balance & Dormant)</h3>
                {'<p>No cold wallets identified in the traced network.</p>' if not summary['cold_wallets_identified'] else '<ul>' + ''.join([f"<li>{addr}</li>" for addr in summary['cold_wallets_identified']]) + '</ul>'}

                <h3>Top Receivers in Traced Flow (Potential Accumulation Points)</h3>
                <p>These wallets received the largest net amounts within the traced transaction network, indicating potential accumulation points for funds.</p>
                {'<p>No top receivers identified.</p>' if not summary['top_receivers_in_flow'] else '<ul>' + ''.join([f"<li>{d['address']}: Received {d['amount_btc']:.8f} BTC</li>" for d in summary['top_receivers_in_flow']]) + '</ul>'}

                <h3>Top Senders in Traced Flow (Major Distribution Points)</h3>
                <p>These wallets sent the largest net amounts within the traced transaction network, indicating major distribution points for funds.</p>
                {'<p>No top senders identified.</p>' if not summary['top_senders_in_flow'] else '<ul>' + ''.join([f"<li>{d['address']}: Sent {d['amount_btc']:.8f} BTC</li>" for d in summary['top_senders_in_flow']]) + '</ul>'}
            </div>

            <h2>Transaction Flow Graph</h2>
    """

    dot_graph_code_raw = """digraph G {
  rankdir=LR;
  node [shape=box, style="rounded,filled", fillcolor="#1a1a1a", fontcolor="#00f5d4", color="#00ff88"];
  edge [color="#00f5d4", fontcolor="#ccc"];
"""
    graph_addresses = set()
    has_edges = False

    for addr, data in forensic_data['analyzed_wallets'].items():
        label_addr = addr[:10] + "..." + addr[-4:]
        node_color = "#00ff88"
        fill_color = "#1a1a1a"
        prefix = ""

        if addr == forensic_data['target_address']:
            label_addr = f"TARGET\\n{label_addr}"
            node_color = "#6999FC"
            fill_color = "#002040"
        elif data.get('is_ransomware_local') or data.get('is_ransomware_api') or data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
            node_color = "#e53935"
            fill_color = "#330a0a"
            if data.get('is_ransomware_local') or data.get('is_ransomware_api'):
                prefix = "MALICIOUS\\n"
            elif data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
                prefix = "REPORTED\\n"
            label_addr = f"{prefix}{label_addr}"
        elif data.get('red_flags'):
            node_color = "#ffeb3b"
            fill_color = "#33330a"
            prefix = "SUSPICIOUS\\n"
            label_addr = f"{prefix}{label_addr}"

        dot_graph_code_raw += f'  "{addr}" [label="{label_addr}", color="{node_color}", fillcolor="{fill_color}"];\n'
        graph_addresses.add(addr)

    for sender, connections in forensic_data['transaction_graph'].items():
        for receiver, amount in connections['sent_to'].items():
            if sender in graph_addresses and receiver in graph_addresses:
                dot_graph_code_raw += f'  "{sender}" -> "{receiver}" [label="{amount:.4f} BTC"];\n'
                has_edges = True
    
    dot_graph_code_raw += "}"

    graph_section_content = ""
    if not graph_addresses and not has_edges:
        graph_section_content = f"<p class='error-message'>No transaction flow graph could be generated for this wallet based on the tracing depth ({forensic_data['max_tracing_depth']}). This might mean no transactions were found or the depth was too shallow.</p>"
    else:
        try:
            process = subprocess.run(
                [DOT_EXECUTABLE_PATH, "-Tsvg"],
                input=dot_graph_code_raw.encode('utf-8'),
                capture_output=True,
                check=True
            )
            svg_data = process.stdout
            encoded_svg = base64.b64encode(svg_data).decode('utf-8')
            svg_uri = f"data:image/svg+xml;base64,{encoded_svg}"

            graph_section_content = f"""
            <p>Below is a visualization of the transaction flow generated using Graphviz.</p>
            <div class="graph-container">
                <img src="{svg_uri}" alt="Transaction Flow Graph">
            </div>
            """
        except FileNotFoundError:
            print(f"Error: Graphviz 'dot' executable not found at '{DOT_EXECUTABLE_PATH}'. Graph SVG will not be generated.", file=sys.stderr)
            graph_section_content = f"<p class='error-message'>Graphviz 'dot' executable not found at '{DOT_EXECUTABLE_PATH}'. Please ensure Graphviz is installed and the path is correct to view the graph directly in the report.</p>"
            graph_section_content += f"<p><strong>Raw DOT Graph Code (for manual viewing):</strong></p><textarea style='width:100%; height:200px; background-color:var(--input-bg); color:var(--text-color); border:1px solid var(--input-border); border-radius:5px; padding:10px;'>{dot_graph_code_raw}</textarea>"
        except subprocess.CalledProcessError as e:
            print(f"Error generating graph with Graphviz: {e.stderr.decode('utf-8')}", file=sys.stderr)
            graph_section_content = f"<p class='error-message'>Error generating graph with Graphviz: {e.stderr.decode('utf-8')}</p>"
            graph_section_content += f"<p><strong>Raw DOT Graph Code (for manual viewing):</strong></p><textarea style='width:100%; height:200px; background-color:var(--input-bg); color:var(--text-color); border:1px solid var(--input-border); border-radius:5px; padding:10px;'>{dot_graph_code_raw}</textarea>"
        except Exception as e:
            print(f"An unexpected error occurred during graph generation: {e}", file=sys.stderr)
            graph_section_content = f"<p class='error-message'>An unexpected error occurred during graph generation: {e}</p>"
            graph_section_content += f"<p><strong>Raw DOT Graph Code (for manual viewing):</strong></p><textarea style='width:100%; height:200px; background-color:var(--input-bg); color:var(--text-color); border:1px solid var(--input-border); border-radius:5px; padding:10px;'>{dot_graph_code_raw}</textarea>"

    html_content += graph_section_content
    html_content += """
            </div>

            <h2>Target Wallet Detailed Analysis</h2>
            <div class="section-content">
    """
    
    target_wallet_data = analyzed_wallets[target_address]

    html_content += f"""
        <div class="wallet-summary-card">
            <h3>Wallet: {target_address} (Depth: 0)</h3>
            <p><strong>Current Balance:</strong> {target_wallet_data.get('balance_btc', 0.0):.8f} BTC</p>
            <p><strong>Total Transactions:</strong> {target_wallet_data.get('total_transactions', 'N/A')}</p>
            <p><strong>Last Transaction:</strong> {target_wallet_data.get('last_transaction_time_utc', 'N/A')}</p>
            <p><strong>Inferred Type:</strong> {target_wallet_data.get('wallet_type_inferred', 'N/A')}</p>
            <p><strong>Total Incoming (traced):</strong> {target_wallet_data.get('incoming_tx_value_sum_traced', 0.0):.8f} BTC</p>
            <p><strong>Total Outgoing (traced):</strong> {target_wallet_data.get('outgoing_tx_value_sum_traced', 0.0):.8f} BTC</p>
            {'<p><strong>Associated Ransomware Family:</strong> ' + ', '.join(target_wallet_data.get('ransomware_family_api', ['N/A'])) + '</p>' if target_wallet_data.get('ransomware_family_api') else ''}
            {'<p><strong>Chainabuse Reports:</strong> ' + str(target_wallet_data.get('chainabuse_reports', {}).get('total_reports_count', 0)) + ' reports</p>' if target_wallet_data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0 else ''}
            
            <h4>Reputation Flags:</h4>
            <ul>
    """
    if target_wallet_data.get('red_flags'):
        for flag in target_wallet_data['red_flags']:
            html_content += f'<li>{flag}</li>'
    else:
        html_content += '<li>No specific flags detected for this wallet.</li>'

    html_content += """
            </ul>
    """
    if target_wallet_data.get('chainabuse_reports', {}).get('reports'):
        html_content += """
            <h4>Detailed Chainabuse Reports:</h4>
        """
        for report in target_wallet_data['chainabuse_reports']['reports']:
            html_content += f"""
                <div class="chainabuse-report-card">
                    <h5>Report {target_wallet_data['chainabuse_reports']['reports'].index(report) + 1}: {report.get('category', 'N/A')}</h5>
                    <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                    <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                    <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                    <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', ['N/A']))}</p>
                </div>
            """
    html_content += """
        </div>
    </div>
    """

    html_content += """
            <h2>Involved Wallets Summary</h2>
            <div class="section-content">
                <p>Below is a summary of all wallets involved in the traced transaction flow, categorized by their reputation status. For non-target wallets, only basic reputation checks (ransomware databases and Chainabuse) are performed.</p>
                
                <h3>Directly Connected Wallets (Sent to or Received from Target)</h3>
                <ul class="wallet-list-summary">
    """
    if forensic_data['directly_connected_wallets']:
        for addr in forensic_data['directly_connected_wallets']:
            data = analyzed_wallets[addr]
            flags_text = []
            if data.get('directly_sent_to_target') > 0:
                flags_text.append(f"Sent {data['directly_sent_to_target']:.8f} BTC to target")
            if data.get('directly_received_from_target') > 0:
                flags_text.append(f"Received {data['directly_received_from_target']:.8f} BTC from target")
            
            if not flags_text and not (data.get('is_ransomware_local') or data.get('is_ransomware_api') or data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0):
                flags_text.append("No specific flags")
            elif data.get('is_ransomware_local'):
                flags_text.append("Address found in local ransomware database.")
            if data.get('is_ransomware_api'):
                flags_text.append("Address found in Ransomwhere.re API.")
            if data.get('chainabuse_reports', {}).get('total_reports_count', 0) > 0:
                flags_text.append(f"Found {data['chainabuse_reports']['total_reports_count']} scam report(s) on Chainabuse.")

            html_content += f"""
                    <li>
                        <span class="address">{addr}</span>
                        <span class="flags">
                            {' '.join(flags_text)}
                        </span>
                    </li>
            """
    else:
        html_content += """
                    <li>
                        <span class="flags">No directly connected wallets found.</span>
                    </li>
        """
    html_content += """
                </ul>

                <h3>Flagged Wallets (Ransomware, Suspicious, or Chainabuse Reports)</h3>
                <ul class="wallet-list-summary">
    """
    if forensic_data['flagged_wallets']:
        for addr in forensic_data['flagged_wallets']:
            data = analyzed_wallets[addr]
            flags_text = ', '.join(data.get('red_flags', ['No specific flags']))
            html_content += f"""
                    <li>
                        <span class="address">{addr}</span>
                        <span class="flags">{flags_text}</span>
                    </li>
            """
    else:
        html_content += """
                    <li>
                        <span class="flags">No flagged wallets found.</span>
                    </li>
        """
    html_content += """
                </ul>

                <h3>Unflagged Wallets (No Known Issues)</h3>
                <ul class="wallet-list-summary">
    """
    if forensic_data['unflagged_wallets']:
        truly_unflagged = [
            addr for addr in forensic_data['unflagged_wallets']
            if not analyzed_wallets[addr].get('is_ransomware_local') and
               not analyzed_wallets[addr].get('is_ransomware_api') and
               not analyzed_wallets[addr].get('red_flags') and
               analyzed_wallets[addr].get('chainabuse_reports', {}).get('total_reports_count', 0) == 0
        ]

        if truly_unflagged:
            for addr in truly_unflagged:
                html_content += f"""
                        <li>
                            <span class="address">{addr}</span>
                            <span class="flags">Clean</span>
                        </li>
                """
        else:
            html_content += """
                    <li>
                        <span class="flags">No unflagged wallets found.</span>
                    </li>
        """
    else:
        html_content += """
                    <li>
                        <span class="flags">No unflagged wallets found.</span>
                    </li>
        """
    html_content += """
                </ul>
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

# --- Main Execution Block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XenoByte Bitcoin Wallet Forensic Analysis Tool")
    parser.add_argument("wallet_address", help="The Bitcoin wallet address for forensic analysis.")
    parser.add_argument("--depth", type=int, default=2, help="Max tracing depth (-1 for full depth). Default is 2.")
    parser.add_argument("--json-output", action="store_true", help="Output results as JSON to stdout.")

    args = parser.parse_args()

    target_address = args.wallet_address
    GLOBAL_MAX_DEPTH = args.depth

    if not target_address:
        print("No wallet address entered. Exiting.", file=sys.stderr)
        sys.exit(1)

    depth_display_output = "Full" if GLOBAL_MAX_DEPTH == -1 else GLOBAL_MAX_DEPTH
    print(f"\n[+] Starting forensic analysis for {target_address} up to depth {depth_display_output}...", file=sys.stderr)
    
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    forensic_report_data = perform_forensic_analysis(target_address, GLOBAL_MAX_DEPTH)

    if args.json_output:
        # This print goes to sys.stdout, which is captured by the calling FastAPI process
        print(json.dumps(forensic_report_data, indent=2))
        sys.exit(0)
    else:
        report_filename = f"XenoByte_Forensic_Report_{target_address[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_forensic_report(forensic_report_data)

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Forensic report saved to {report_filename}", file=sys.stderr)
            webbrowser.open(report_filename)
        except Exception as e:
            print(f"Error saving or opening report: {e}", file=sys.stderr)
            sys.exit(1)
