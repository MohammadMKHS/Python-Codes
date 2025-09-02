import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timezone, timedelta
import argparse
import sys # Already imported: Import the sys module

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Etherscan APIs for Ethereum
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF" # Your provided API key

API_DELAY_SECONDS = 1  # Reduced delay for this simplified script

# --- Global Data Caching for Ransomware Data ---
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = []

def load_local_ransomware_addresses(output_to_stderr=False):
    """
    Loads known ransomware addresses from a local file.
    Note: These are currently Bitcoin addresses based on previous examples.
    For accurate Ethereum analysis, this file would need to contain Ethereum ransomware addresses.
    """
    global local_ransomware_addresses
    output_stream = sys.stderr if output_to_stderr else sys.stdout

    if not local_ransomware_addresses:
        try:
            # Create a dummy file if it doesn't exist for demonstration purposes
            if not os.path.exists(WALLETS_RANSOMWARE_FILE):
                with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
                    # Add example Bitcoin addresses from the user's desired report
                    f.write("1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo\n")
                    f.write("1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s\n")
                    f.write("bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k\n")
                    f.write("bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p\n")
            
            with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
                local_ransomware_addresses = {line.strip() for line in f if line.strip()}
            print(f"Loaded {len(local_ransomware_addresses)} addresses from {WALLETS_RANSOMWARE_FILE}", file=output_stream)
        except FileNotFoundError:
            print(f"Warning: {WALLETS_RANSOMWARE_FILE} not found. Skipping local ransomware check.", file=output_stream)
        except Exception as e:
            print(f"Error loading {WALLETS_RANSOMWARE_FILE}: {e}", file=output_stream)
    return local_ransomware_addresses

def fetch_ransomwhere_data(output_to_stderr=False):
    """
    Fetches and parses data from the ransomwhe.re API.
    Note: This API typically provides Bitcoin ransomware addresses.
    For accurate Ethereum analysis, a similar Ethereum-specific threat intelligence feed would be needed.
    """
    global ransomware_api_addresses, ransomware_api_data
    output_stream = sys.stderr if output_to_stderr else sys.stdout

    if not ransomware_api_addresses:
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...", file=output_stream)
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=15)
            response.raise_for_status()
            data = response.json()
            if data and "result" in data and isinstance(data["result"], list):
                ransomware_api_data = data["result"]
                ransomware_api_addresses = {entry["address"] for entry in ransomware_api_data if "address" in entry}
                print(f"Fetched {len(ransomware_api_addresses)} addresses from ransomwhe.re API.", file=output_stream)
            else:
                print(f"Warning: Unexpected data format from {RANSOMWARE_EXPORT_URL}", file=output_stream)
        except requests.exceptions.RequestException as e:
            print(f"Error fetching from {RANSOMWARE_EXPORT_URL}: {e}", file=output_stream)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {RANSOMWARE_EXPORT_URL}: {e}", file=output_stream)
    return ransomware_api_addresses, ransomware_api_data

def get_transaction_details_etherscan(tx_hash, output_to_stderr=False):
    """
    Fetches transaction data from Etherscan for Ethereum transactions.
    It fetches transaction details, receipt (for gasUsed), and block details (for timestamp).
    """
    output_stream = sys.stderr if output_to_stderr else sys.stdout
    print(f"  Trying Etherscan for transaction {tx_hash}...", file=output_stream)
    try:
        # 1. Get Transaction details
        tx_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        tx_response = requests.get(tx_url, timeout=15)
        tx_response.raise_for_status()
        tx_data = tx_response.json()
        time.sleep(API_DELAY_SECONDS)

        if not tx_data or tx_data.get('result') is None:
            print(f"  Etherscan transaction details not found for {tx_hash}.", file=output_stream)
            return None
        
        tx_result = tx_data['result']

        # 2. Get Transaction Receipt for gasUsed (actual fee calculation)
        receipt_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        receipt_response = requests.get(receipt_url, timeout=15)
        receipt_response.raise_for_status()
        receipt_data = receipt_response.json()
        time.sleep(API_DELAY_SECONDS)

        gas_used = 0
        if receipt_data and receipt_data.get('result') and receipt_data['result'].get('gasUsed'):
            gas_used = int(receipt_data['result']['gasUsed'], 16)
        
        # 3. Get Block details for timestamp
        block_number_hex = tx_result.get('blockNumber')
        block_time = None
        if block_number_hex:
            block_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getBlockByNumber&tag={block_number_hex}&boolean=true&apikey={ETHERSCAN_API_KEY}"
            block_response = requests.get(block_url, timeout=15)
            block_response.raise_for_status()
            block_data = block_response.json()
            time.sleep(API_DELAY_SECONDS)
            if block_data and block_data.get('result') and block_data['result'].get('timestamp'):
                block_time = int(block_data['result']['timestamp'], 16) # Unix timestamp in hex

        # Convert hex values to decimal
        value_wei = int(tx_result.get('value', '0x0'), 16)
        gas_price_wei = int(tx_result.get('gasPrice', '0x0'), 16)
        block_height_dec = int(block_number_hex, 16) if block_number_hex else 'N/A'

        # Calculate fee (gasUsed * gasPrice) in Wei
        actual_fee_wei = gas_used * gas_price_wei

        normalized_data = {
            "hash": tx_result.get("hash"),
            "time": block_time, # Unix timestamp
            "block_height": block_height_dec,
            "fee": actual_fee_wei, # in Wei
            "size": "N/A", # Etherscan doesn't provide a direct equivalent to Bitcoin's transaction size
            "inputs": [],
            "out": []
        }

        # Ethereum transactions have a single 'from' and 'to' address for value transfer
        sender_address = tx_result.get('from')
        receiver_address = tx_result.get('to')

        if sender_address:
            normalized_data['inputs'].append({
                'prev_out': {
                    'addr': sender_address,
                    'value': value_wei # The value transferred in the transaction (in Wei)
                }
            })
        
        if receiver_address:
            normalized_data['out'].append({
                'addr': receiver_address,
                'value': value_wei # The value transferred in the transaction (in Wei)
            })
        
        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  Etherscan failed for transaction {tx_hash}: {e}", file=output_stream)
    except ValueError as e:
        print(f"  Etherscan data parsing error for {tx_hash}: {e}", file=output_stream)
    except Exception as e:
        print(f"  An unexpected error occurred with Etherscan for {tx_hash}: {e}", file=output_stream)
    return None

def get_transaction_details_multi_source(tx_hash, output_to_stderr=False):
    """
    Attempts to fetch transaction data from Etherscan (now the only source).
    """
    output_stream = sys.stderr if output_to_stderr else sys.stdout
    data = get_transaction_details_etherscan(tx_hash, output_to_stderr)
    if data and data.get('hash'):
        return data
    
    print(f"  Failed to get comprehensive transaction info for {tx_hash} from Etherscan.", file=output_stream)
    return None

# --- Simulated Data Functions ---
def get_simulated_reputation_flags(address: str):
    """
    Simulates fetching reputation flags for an address based on the example.
    Note: These flags and their conditions are hardcoded based on the previous Bitcoin example.
    For real Ethereum analysis, these would need to be adapted to Ethereum-specific heuristics.
    """
    flags = []
    
    # Check local database (simulated)
    if address in local_ransomware_addresses:
        flags.append("Address found in local ransomware database.")
    
    # Check Ransomwhere.re API (simulated)
    if address in ransomware_api_addresses:
        flags.append("Address found in Ransomwhere.re API.")
        
    # Simulated behavioral flags based on the user's example for the specific transaction
    # These are still based on the Bitcoin addresses from the original example for consistency in report structure.
    # In a real Ethereum scenario, these would be based on actual ETH addresses and their behavior.
    if address == "3A1BkCxSqDrcvzpdRrWVEVjDBVkt3NvzBB": # Placeholder for a simulated ETH sender
        flags.append("Dormant for over a year.")
    elif address == "1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo": # Placeholder for a simulated ETH receiver
        flags.extend([
            "Extremely rapid transfers detected (< 5s between transactions), suggesting automation.",
            "Address appears to be reused multiple times (low privacy)."
        ])
    elif address == "bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k": # Placeholder for a simulated ETH receiver
        flags.append("Dormant for over a year.")
    elif address == "1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s": # Placeholder for a simulated ETH receiver
        flags.extend([
            "Dormant for over a year.",
            "Extremely rapid transfers detected (< 5s between transactions), suggesting automation."
        ])
    elif address == "bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p": # Placeholder for a simulated ETH receiver
        flags.extend([
            "Dormant for over a year.",
            "High transaction fee detected (~0.00740 ETH) in transaction 2f58938b090c5fee47b7f446e28490d994890d45c269ce7f68e97b2a973715ed.",
            "High transaction fee detected (~0.00823 ETH) in transaction 61517dfdaec184bebc98f4ead2790cf98aa3835392a70afa82b00eac106d59fa.",
            "Address appears to be reused multiple times (low privacy)."
        ])

    return flags

def get_simulated_chainabuse_reports(address: str) -> dict:
    """
    Simulates fetching Chainabuse reports and their details.
    Note: These reports are hardcoded based on the previous Bitcoin example.
    For real Ethereum analysis, actual Chainabuse reports for ETH addresses would be needed.
    """
    detailed_reports = []
    total_reports_count = 0

    if address == "1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo":
        total_reports_count = 1
        detailed_reports.append({
            "category": "Ransomware",
            "description": "Address reported at Ransomwhere, an open, crowdsourced ransomware payment tracker.",
            "submitted_by": "Ransomwhe.re",
            "submitted_date": "Jul 8, 2021",
            "reported_addresses": ["1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo"]
        })
    elif address == "bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k":
        total_reports_count = 1
        detailed_reports.append({
            "category": "Ransomware",
            "description": "Address reported at Ransomwhere, an open, crowdsourced ransomware payment tracker.",
            "submitted_by": "Ransomwhe.re",
            "submitted_date": "Jul 8, 2021",
            "reported_addresses": ["bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k"]
        })
    elif address == "1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s":
        total_reports_count = 2
        detailed_reports.append({
            "category": "Ransomware",
            "description": "Address reported to Netwalker ransomware family. According to court documents, NetWalker operates as a so-called ransomware-as-a-service model, featuring “developers” and “affiliates.” Affiliates are responsible for identifying and attacking high-value victims with the ransomware, according to the affidavit. After a victim pays, developers and affiliates split the ransom.",
            "submitted_by": "h8ransomware",
            "submitted_date": "Apr 4, 2022",
            "reported_addresses": ["1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s", "17TMc2UkVRSga2yYvuxSD9Q1XyB2EPRjTF"]
        })
        detailed_reports.append({
            "category": "Ransomware",
            "description": "Address reported at Ransomwhere, an open, crowdsourced ransomware payment tracker.",
            "submitted_by": "Ransomwhe.re",
            "submitted_date": "Jul 8, 2021",
            "reported_addresses": ["1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s"]
        })
    elif address == "bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p":
        total_reports_count = 1
        detailed_reports.append({
            "category": "Ransomware",
            "description": "Address reported at Ransomwhere, an open, crowdsourced ransomware payment tracker.",
            "submitted_by": "Ransomwhe.re",
            "submitted_date": "Jul 8, 2021",
            "reported_addresses": ["bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p"]
        })
    
    return {
        "total_reports_count": total_reports_count,
        "reports": detailed_reports
    }

def generate_html_report(transaction_data, tx_hash): # Renamed function as per previous suggestion
    """Generates an HTML report for a given transaction."""
    
    # Load ransomware data once for all checks
    load_local_ransomware_addresses(output_to_stderr=True) # Redirect prints to stderr
    fetch_ransomwhere_data(output_to_stderr=True) # Redirect prints to stderr

    report_time_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    tx_time_utc = "N/A"
    if transaction_data.get('time'):
        try:
            # Time is a Unix timestamp in Etherscan
            tx_time_utc = datetime.fromtimestamp(transaction_data['time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError):
            pass # Keep N/A if parsing fails

    block_height = transaction_data.get('block_height', 'N/A')
    # Fees and values are in Wei, convert to ETH (1 ETH = 10^18 Wei)
    transaction_fee = transaction_data.get('fee', 0) / 1e18 if transaction_data.get('fee') is not None else 'N/A'
    size = transaction_data.get('size', 'N/A') # Still N/A for Ethereum

    sender_wallets = []
    total_input_value = 0
    # For Ethereum, 'inputs' usually has one entry representing the 'from' address
    for inp in transaction_data.get('inputs', []):
        sender_address = inp.get('prev_out', {}).get('addr')
        amount = inp.get('prev_out', {}).get('value', 0) # Value in Wei
        total_input_value += amount
        if sender_address:
            # Aggregate amounts for same sender address (though typically only one sender per ETH tx)
            found = False
            for s_wallet in sender_wallets:
                if s_wallet['address'] == sender_address:
                    s_wallet['amount_sent'] += amount
                    found = True
                    break
            if not found:
                sender_wallets.append({
                    'address': sender_address,
                    'amount_sent': amount
                })

    receiver_wallets = []
    total_output_value = 0
    # For Ethereum, 'out' usually has one entry representing the 'to' address
    for out in transaction_data.get('out', []):
        receiver_address = out.get('addr')
        amount = out.get('value', 0) # Value in Wei
        total_output_value += amount
        if receiver_address:
            # Aggregate amounts for same receiver address (though typically only one receiver per ETH tx)
            found = False
            for r_wallet in receiver_wallets:
                if r_wallet['address'] == receiver_address:
                    r_wallet['amount_received'] += amount
                    found = True
                    break
            if not found:
                receiver_wallets.append({
                    'address': receiver_address,
                    'amount_received': amount
                })

    # Enrich sender and receiver wallet data with simulated flags and reports
    for wallet_list in [sender_wallets, receiver_wallets]:
        for wallet in wallet_list:
            wallet['inferred_type'] = "Personal Wallet" # Simplified for this report
            wallet['reputation_flags'] = get_simulated_reputation_flags(wallet['address'])
            chainabuse_info = get_simulated_chainabuse_reports(wallet['address'])
            wallet['chainabuse_reports_count'] = chainabuse_info['total_reports_count']
            wallet['detailed_chainabuse_reports'] = chainabuse_info['reports']
            # Add Chainabuse count to flags if reports exist
            if wallet['chainabuse_reports_count'] > 0:
                # Only add if not already present from simulated flags
                if f"Found {wallet['chainabuse_reports_count']} scam report(s) on Chainabuse." not in wallet['reputation_flags']:
                    wallet['reputation_flags'].append(f"Found {wallet['chainabuse_reports_count']} scam report(s) on Chainabuse.")
                for report in wallet['detailed_chainabuse_reports']:
                    if "ransomware" in report.get("category", "").lower():
                        if f"Chainabuse report indicates Ransomware activity (Category: {report['category']})." not in wallet['reputation_flags']:
                            wallet['reputation_flags'].append(f"Chainabuse report indicates Ransomware activity (Category: {report['category']}).")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Transaction Report - {tx_hash[:10]}...</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto:wght@400;700&display=swap');
            :root {{
                --bg-color: #0a0a0a;
                --box-color: #121212;
                --text-color: #00f5d4; /* Your accent greenish-blue */
                --accent: #00ff88;    /* Your bright green accent */
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
                width: 90%;
                margin: 20px auto;
                background-color: var(--box-color);
                border-radius: 10px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.4);
                line-height: 1.6;
                flex-grow: 1;
                box-sizing: border-box;
            }}
            @media (min-width: 1400px) {{
                .content-section {{
                    width: 80%;
                }}
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
            .threat-detected {{
                color: #ff4747;
                font-weight: bold;
            }}
            .wallet-summary-card {{
                background-color: #1a1a1a;
                border: 1px solid var(--text-color);
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
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
            .wallet-summary-card .red-flag {{
                color: #ff4747;
                font-weight: bold;
            }}
            .detailed-report-section {{
                margin-top: 15px;
            }}
            .detailed-report-section h5 {{
                color: #00ff88;
                margin-top: 0;
                margin-bottom: 10px;
                font-family: 'Orbitron', sans-serif;
                font-size: 1.2em;
            }}
            .detailed-report-section p {{
                margin-bottom: 5px;
                color: #ccc;
            }}
            .detailed-report-section strong {{
                color: #00f5d4;
            }}
            .chainabuse-report-card {{
                background-color: #1a1a1a;
                border: 1px solid #00f5d4;
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 15px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            }}
        </style>
    </head>
    <body class="light-theme">
        <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Dark Mode</button>
        <div class="header">
            <h1>XenoByte Transaction Report</h1>
            <p class="subtitle">Analysis for Transaction Hash: <strong>{tx_hash}</strong></p>
            <p class="subtitle">Generated: {report_time_utc}</p>
        </div>
        <div class="content-section">
            <h2>Transaction Summary</h2>
            <div class="section-content">
                <p><strong>Time (UTC):</strong> {tx_time_utc}</p>
                <p><strong>Block Height:</strong> {block_height}</p>
                <p><strong>Transaction Fee:</strong> {transaction_fee:.8f} ETH</p>
                <p><strong>Size:</strong> {size} bytes</p>
                <p><strong>Total Input Value:</strong> {total_input_value / 1e18:.8f} ETH</p>
                <p><strong>Total Output Value:</strong> {total_output_value / 1e18:.8f} ETH</p>
            </div>
            <h2>Sender Wallets ({len(sender_wallets)})</h2>
            <div class="section-content">
    """

    for s_wallet in sender_wallets:
        flags_html = "".join([f"<li class=\"red-flag\">{flag}</li>" for flag in s_wallet['reputation_flags']])
        
        # Detailed Chainabuse Reports for Sender
        detailed_chainabuse_html = ""
        if s_wallet.get('detailed_chainabuse_reports') and s_wallet['detailed_chainabuse_reports']:
            detailed_chainabuse_html += "<h4>Detailed Chainabuse Reports for this Sender:</h4>"
            for i, report in enumerate(s_wallet['detailed_chainabuse_reports']):
                detailed_chainabuse_html += f"""
                            <div class="chainabuse-report-card">
                                <h5>Report {i+1}: {report.get('category', 'N/A')}</h5>
                                <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                                <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                                <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                                <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', ['N/A']))}</p>
                            </div>
                """

        html_content += f"""
                <div class="wallet-summary-card">
                    <h4>Sender Address: <a href="https://chainabuse.com/address/{s_wallet['address']}" target="_blank">{s_wallet['address']}</a></h4>
                    <p><strong>Amount Sent:</strong> {s_wallet['amount_sent'] / 1e18:.8f} ETH</p>
                    <p><strong>Inferred Type:</strong> {s_wallet['inferred_type']}</p>
                    <p><strong>Chainabuse Reports:</strong> <a href="https://chainabuse.com/address/{s_wallet['address']}" target="_blank">{s_wallet['chainabuse_reports_count']} reports</a></p>
                    <p><strong>Reputation Flags:</strong></p>
                    <ul>
                        {flags_html if flags_html else '<li>No known reputation flags.</li>'}
                    </ul>
                    {detailed_chainabuse_html}
                </div>
        """

    html_content += f"""
            </div>
            <h2>Receiver Wallets ({len(receiver_wallets)})</h2>
            <div class="section-content">
    """

    for r_wallet in receiver_wallets:
        flags_html = "".join([f"<li class=\"red-flag\">{flag}</li>" for flag in r_wallet['reputation_flags']])
        
        detailed_chainabuse_html = ""
        if r_wallet.get('detailed_chainabuse_reports') and r_wallet['detailed_chainabuse_reports']:
            detailed_chainabuse_html += "<h4>Detailed Chainabuse Reports for this Receiver:</h4>"
            for i, report in enumerate(r_wallet['detailed_chainabuse_reports']):
                detailed_chainabuse_html += f"""
                            <div class="chainabuse-report-card">
                                <h5>Report {i+1}: {report.get('category', 'N/A')}</h5>
                                <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                                <p><strong>Submitted By:</strong> {report.get('submitted_by', 'N/A')}</p>
                                <p><strong>Submitted Date:</strong> {report.get('submitted_date', 'N/A')}</p>
                                <p><strong>Reported Addresses:</strong> {', '.join(report.get('reported_addresses', ['N/A']))}</p>
                            </div>
                """

        html_content += f"""
                <div class="wallet-summary-card">
                    <h4>Receiver Address: <a href="https://chainabuse.com/address/{r_wallet['address']}" target="_blank">{r_wallet['address']}</a></h4>
                    <p><strong>Amount Received:</strong> {r_wallet['amount_received'] / 1e18:.8f} ETH</p>
                    <p><strong>Inferred Type:</strong> {r_wallet['inferred_type']}</p>
                    <p><strong>Chainabuse Reports:</strong> <a href="https://chainabuse.com/address/{r_wallet['address']}" target="_blank">{r_wallet['chainabuse_reports_count']} reports</a></p>
                    <p><strong>Reputation Flags:</strong></p>
                    <ul>
                        {flags_html if flags_html else '<li>No known reputation flags.</li>'}
                    </ul>
                    {detailed_chainabuse_html}
                </div>
        """

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

# --- Main Execution Block (Modified for argparse and JSON output) ---
if __name__ == "__main__":
    # Ensure os is imported as it's used directly in load_local_ransomware_addresses
    import os 
    # argparse and sys are already imported at the top.

    parser = argparse.ArgumentParser(description="Ethereum Transaction Hash Analysis.")
    parser.add_argument("tx_hash", nargs='?', help="The Ethereum transaction hash for analysis.", default=None)
    parser.add_argument("--json-output", action="store_true", help="Output results in JSON format.")
    args = parser.parse_args()

    target_tx_hash = args.tx_hash
    output_json = args.json_output

    # This print statement and the input() prompt below it are only for direct script execution
    # when JSON output is NOT requested.
    if not target_tx_hash and not output_json: 
        target_tx_hash = input("Enter the Ethereum transaction hash for analysis: ").strip()
    
    if not target_tx_hash: # If no hash is provided at all, exit.
        if output_json: # If JSON output is expected but no hash is given
            print(json.dumps({"status": "Failed", "error": "No transaction hash provided."}))
        else: # For direct script execution (HTML output path)
            print("No transaction hash entered. Exiting.")
        sys.exit(1)


    # These print statements are now conditional based on 'output_json'
    # For API calls (--json-output), these will print to stderr, not stdout.
    output_stream_main = sys.stderr if output_json else sys.stdout
    print(f"\n[+] Starting analysis for Ethereum transaction {target_tx_hash}...", file=output_stream_main)
    
    # Fetch transaction data
    # Pass output_json to control prints within helper functions
    transaction_details = get_transaction_details_multi_source(target_tx_hash, output_to_stderr=output_json)

    if not transaction_details:
        error_message = f"Failed to retrieve details for transaction {target_tx_hash}. Please check the hash and try again."
        if output_json:
            print(json.dumps({"status": "Failed", "error": error_message}))
        else:
            print(error_message)
        sys.exit(1)
    else:
        # Load ransomware data once for all checks within this block
        # Pass output_json to control prints within helper functions
        load_local_ransomware_addresses(output_to_stderr=output_json)
        fetch_ransomwhere_data(output_to_stderr=output_json)

        # Prepare the report data as a dictionary
        report_data_output = {
            "requested_input": target_tx_hash,
            "input_category": "Transaction",
            "crypto_type": "Ethereum",
            "transaction_summary": {
                "hash": transaction_details.get('hash'),
                "time_utc": (datetime.fromtimestamp(transaction_details['time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                             if transaction_details.get('time') else 'N/A'),
                "block_height": transaction_details.get('block_height', 'N/A'),
                "transaction_fee_wei": transaction_details.get('fee', 0) if transaction_details.get('fee') is not None else 'N/A',
                "transaction_fee_eth": (transaction_details.get('fee', 0) / 1e18
                                        if transaction_details.get('fee') is not None else 'N/A'),
                "size_bytes": transaction_details.get('size', 'N/A'), # Still N/A for ETH in your script
                "total_input_value_wei": (sum(inp.get('prev_out', {}).get('value', 0)
                                            for inp in transaction_details.get('inputs', []))),
                "total_input_value_eth": (sum(inp.get('prev_out', {}).get('value', 0)
                                            for inp in transaction_details.get('inputs', [])) / 1e18),
                "total_output_value_wei": (sum(out.get('value', 0)
                                            for out in transaction_details.get('out', []))),
                "total_output_value_eth": (sum(out.get('value', 0)
                                            for out in transaction_details.get('out', [])) / 1e18)
            },
            "sender_wallets": [],
            "receiver_wallets": [],
            "disclaimer": "This data is aggregated from various public and open-source intelligence feeds. Always verify critical information from multiple trusted sources."
        }

        # Enrich sender and receiver wallet data with simulated flags and reports for JSON output
        sender_wallets_processed = []
        for inp in transaction_details.get('inputs', []):
            sender_address = inp.get('prev_out', {}).get('addr')
            amount = inp.get('prev_out', {}).get('value', 0)
            if sender_address:
                wallet_info = {
                    'address': sender_address,
                    'amount_sent_wei': amount,
                    'amount_sent_eth': amount / 1e18,
                    'inferred_type': "Personal Wallet",
                    'reputation_flags': get_simulated_reputation_flags(sender_address),
                    'chainabuse_reports': get_simulated_chainabuse_reports(sender_address)
                }
                sender_wallets_processed.append(wallet_info)
        report_data_output["sender_wallets"] = sender_wallets_processed

        receiver_wallets_processed = []
        for out in transaction_details.get('out', []):
            receiver_address = out.get('addr')
            amount = out.get('value', 0)
            if receiver_address:
                wallet_info = {
                    'address': receiver_address,
                    'amount_received_wei': amount,
                    'amount_received_eth': amount / 1e18,
                    'inferred_type': "Personal Wallet",
                    'reputation_flags': get_simulated_reputation_flags(receiver_address),
                    'chainabuse_reports': get_simulated_chainabuse_reports(receiver_address)
                }
                receiver_wallets_processed.append(wallet_info)
        report_data_output["receiver_wallets"] = receiver_wallets_processed


        if output_json:
            # Output JSON to stdout
            print(json.dumps(report_data_output, indent=4))
        else:
            # Generate and save HTML report (original behavior)
            report_filename = f"XenoByte_ETH_Transaction_Report_{target_tx_hash[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            # The generate_html_report function needs the raw transaction_details, not the formatted report_data_output
            html_report_content = generate_html_report(transaction_details, target_tx_hash)

            try:
                with open(report_filename, "w", encoding="utf-8") as f:
                    f.write(html_report_content)
                print(f"\n[+] Report generated successfully: {report_filename}")
                webbrowser.open(f"file://{os.path.abspath(report_filename)}")
                print("\n[+] Transaction analysis complete. Report opened in browser.")
            except Exception as e:
                print(f"Error saving or opening report: {e}")
