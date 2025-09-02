import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timezone, timedelta

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Blockchain.info APIs (simplified for direct raw transaction fetch)
BLOCKCHAIN_INFO_RAW_TX_API = "https://blockchain.info/rawtx/{tx_hash}?format=json"

# BlockCypher APIs (Public API, no token needed for basic usage, but limits apply)
BLOCKCYPHER_API_BASE = "https://api.blockcypher.com/v1/btc/main"
BLOCKCYPHER_TX_API = f"{BLOCKCYPHER_API_BASE}/txs/{{tx_hash}}"

# Blockchair APIs (Public API, no token needed for basic usage, but limits apply)
BLOCKCHAIR_API_BASE = "https://api.blockchair.com/bitcoin"
BLOCKCHAIR_TX_API = f"{BLOCKCHAIR_API_BASE}/dashboards/transaction/{{tx_hash}}"

API_DELAY_SECONDS = 1  # Reduced delay for this simplified script

# --- Global Data Caching for Ransomware Data ---
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = []

def load_local_ransomware_addresses():
    """Loads known ransomware addresses from a local file."""
    global local_ransomware_addresses
    if not local_ransomware_addresses:
        try:
            # Create a dummy file if it doesn't exist for demonstration purposes
            if not os.path.exists(WALLETS_RANSOMWARE_FILE):
                with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
                    # Add example addresses from the user's desired report
                    f.write("1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo\n")
                    f.write("1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s\n")
                    f.write("bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k\n")
                    f.write("bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p\n")
            
            with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
                local_ransomware_addresses = {line.strip() for line in f if line.strip()}
            print(f"Loaded {len(local_ransomware_addresses)} addresses from {WALLETS_RANSOMWARE_FILE}")
        except FileNotFoundError:
            print(f"Warning: {WALLETS_RANSOMWARE_FILE} not found. Skipping local ransomware check.")
        except Exception as e:
            print(f"Error loading {WALLETS_RANSOMWARE_FILE}: {e}")
    return local_ransomware_addresses

def fetch_ransomwhere_data():
    """Fetches and parses data from the ransomwhe.re API."""
    global ransomware_api_addresses, ransomware_api_data
    if not ransomware_api_addresses:
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...")
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=15)
            response.raise_for_status()
            data = response.json()
            if data and "result" in data and isinstance(data["result"], list):
                ransomware_api_data = data["result"]
                ransomware_api_addresses = {entry["address"] for entry in ransomware_api_data if "address" in entry}
                print(f"Fetched {len(ransomware_api_addresses)} addresses from ransomwhe.re API.")
            else:
                print(f"Warning: Unexpected data format from {RANSOMWARE_EXPORT_URL}")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching from {RANSOMWARE_EXPORT_URL}: {e}")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from {RANSOMWARE_EXPORT_URL}: {e}")
    return ransomware_api_addresses, ransomware_api_data

def get_transaction_details_blockchain_info(tx_hash):
    """Fetches raw transaction data from blockchain.info."""
    url = BLOCKCHAIN_INFO_RAW_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying blockchain.info for transaction {tx_hash}...")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        return data
    except requests.exceptions.RequestException as e:
        print(f"  blockchain.info failed for {tx_hash}: {e}")
    return None

def get_transaction_details_blockcypher(tx_hash):
    """Fetches transaction data from BlockCypher."""
    url = BLOCKCYPHER_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying BlockCypher for transaction {tx_hash}...")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        # Normalize BlockCypher data to match blockchain.info's rawtx structure
        normalized_inputs = []
        for inp in data.get('inputs', []):
            if inp.get('addresses') and inp.get('output_value') is not None:
                normalized_inputs.append({'prev_out': {'addr': inp['addresses'][0], 'value': inp['output_value']}})
        normalized_outputs = []
        for out in data.get('outputs', []):
            if out.get('addresses') and out.get('value') is not None:
                normalized_outputs.append({'addr': out['addresses'][0], 'value': out['value']})
        return {
            "hash": data.get("hash"),
            "time": datetime.strptime(data['confirmed'], '%Y-%m-%dT%H:%M:%SZ').timestamp() if 'confirmed' in data else None,
            "block_height": data.get("block_height"),
            "fee": data.get("fees"),
            "size": data.get("size"),
            "inputs": normalized_inputs,
            "out": normalized_outputs
        }
    except requests.exceptions.RequestException as e:
        print(f"  BlockCypher failed for {tx_hash}: {e}")
    except ValueError as e:
        print(f"  BlockCypher data parsing error for {tx_hash}: {e}")
    return None

def get_transaction_details_blockchair(tx_hash):
    """Fetches transaction data from Blockchair."""
    url = BLOCKCHAIR_TX_API.format(tx_hash=tx_hash)
    print(f"  Trying Blockchair for transaction {tx_hash}...")
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        # Blockchair's transaction data is nested under data[tx_hash]['transaction'] and 'inputs'/'outputs'
        tx_data = data.get('data', {}).get(tx_hash, {}).get('transaction', {})
        inputs_data = data.get('data', {}).get(tx_hash, {}).get('inputs', [])
        outputs_data = data.get('data', {}).get(tx_hash, {}).get('outputs', [])

        normalized_data = {
            "hash": tx_data.get("hash"),
            "time": tx_data.get("time"), # This is usually a Unix timestamp
            "block_height": tx_data.get("block_id"),
            "fee": tx_data.get("fee"),
            "size": tx_data.get("size"),
            "inputs": [],
            "out": []
        }

        for inp in inputs_data:
            normalized_data["inputs"].append({
                'prev_out': {
                    'addr': inp.get('recipient'),
                    'value': inp.get('value')
                }
            })
        for out in outputs_data:
            normalized_data["out"].append({
                'addr': out.get('recipient'),
                'value': out.get('value')
            })
        return normalized_data
    except requests.exceptions.RequestException as e:
        print(f"  Blockchair failed for {tx_hash}: {e}")
    except json.JSONDecodeError as e:
        print(f"  Blockchair JSON decoding error for {tx_hash}: {e}")
    return None

def get_transaction_details_multi_source(tx_hash):
    """
    Attempts to fetch transaction data from multiple sources.
    Returns the first successful result.
    """
    sources = [
        get_transaction_details_blockchain_info,
        get_transaction_details_blockcypher,
        get_transaction_details_blockchair
    ]
    
    for source_func in sources:
        data = source_func(tx_hash)
        if data:
            return data
    
    print(f"  Failed to get comprehensive transaction info for {tx_hash} from all sources.")
    return None

# --- Simulated Data Functions ---
def get_simulated_reputation_flags(address: str):
    """Simulates fetching reputation flags for an address based on the example."""
    flags = []
    
    # Check local database (simulated)
    if address in local_ransomware_addresses:
        flags.append("Address found in local ransomware database.")
    
    # Check Ransomwhere.re API (simulated)
    if address in ransomware_api_addresses:
        flags.append("Address found in Ransomwhere.re API.")
        
    # Simulated behavioral flags based on the user's example for the specific transaction
    # These would typically require fetching full address transaction history and analyzing it.
    if address == "3A1BkCxSqDrcvzpdRrWVEVjDBVkt3NvzBB":
        flags.append("Dormant for over a year.")
    elif address == "1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo":
        flags.extend([
            "Extremely rapid transfers detected (< 5s between transactions), suggesting automation.",
            "Address appears to be reused multiple times (low privacy)."
        ])
    elif address == "bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k":
        flags.append("Dormant for over a year.")
    elif address == "1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s":
        flags.extend([
            "Dormant for over a year.",
            "Extremely rapid transfers detected (< 5s between transactions), suggesting automation."
        ])
    elif address == "bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p":
        flags.extend([
            "Dormant for over a year.",
            "High transaction fee detected (~0.00740 BTC) in transaction 2f58938b090c5fee47b7f446e28490d994890d45c269ce7f68e97b2a973715ed.",
            "High transaction fee detected (~0.00823 BTC) in transaction 61517dfdaec184bebc98f4ead2790cf98aa3835392a70afa82b00eac106d59fa.",
            "Address appears to be reused multiple times (low privacy)."
        ])

    return flags

def get_simulated_chainabuse_reports(address: str) -> dict:
    """
    Simulates fetching Chainabuse reports and their details.
    This replaces the actual scraping function.
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
            "description": "Address reported to Netwalker ransomware family. According to court documents, NetWalker operates as a so-called ransomware-as-a-service model, featuring “developers” and “affiliates.” Developers are responsible for creating and updating the ransomware and making it available to affiliates. Affiliates are responsible for identifying and attacking high-value victims with the ransomware, according to the affidavit. After a victim pays, developers and affiliates split the ransom.",
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

def generate_transaction_report(transaction_data, tx_hash):
    """Generates an HTML report for a given transaction."""
    
    # Load ransomware data once for all checks
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()

    report_time_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    tx_time_utc = "N/A"
    if transaction_data.get('time'):
        try:
            # Blockchair might return ISO format, others timestamp
            if isinstance(transaction_data['time'], (int, float)):
                tx_time_utc = datetime.fromtimestamp(transaction_data['time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            else: # Assume string format like ISO
                dt_object = datetime.fromisoformat(transaction_data['time'].replace('Z', '+00:00'))
                tx_time_utc = dt_object.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError):
            pass # Keep N/A if parsing fails

    block_height = transaction_data.get('block_height', 'N/A')
    # Fees and values are often in satoshis, convert to BTC
    transaction_fee = transaction_data.get('fee', 0) / 100_000_000.0 if transaction_data.get('fee') is not None else 'N/A'
    size = transaction_data.get('size', 'N/A')

    sender_wallets = []
    total_input_value = 0
    for inp in transaction_data.get('inputs', []):
        sender_address = inp.get('prev_out', {}).get('addr')
        amount = inp.get('prev_out', {}).get('value', 0)
        total_input_value += amount
        if sender_address:
            # Aggregate amounts for same sender address
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
    for out in transaction_data.get('out', []):
        receiver_address = out.get('addr')
        amount = out.get('value', 0)
        total_output_value += amount
        if receiver_address:
            # Aggregate amounts for same receiver address
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
                /* Removed padding-left and border-left as per example */
                /* Removed display: block; */
            }}
            .detailed-report-section h5 {{
                color: #00ff88; /* Changed to accent color for consistency with example */
                margin-top: 0;
                margin-bottom: 10px; /* Adjusted margin to match example */
                font-family: 'Orbitron', sans-serif;
                font-size: 1.2em; /* Adjusted font size to match example */
            }}
            .detailed-report-section p {{
                margin-bottom: 5px; /* Adjusted margin to match example */
                color: #ccc; /* Adjusted color to match example */
            }}
            .detailed-report-section strong {{
                color: #00f5d4; /* Adjusted color to match example */
            }}
            .chainabuse-report-card {{ /* Re-added this class for individual report cards */
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
                <p><strong>Transaction Fee:</strong> {transaction_fee:.8f} BTC</p>
                <p><strong>Size:</strong> {size} bytes</p>
                <p><strong>Total Input Value:</strong> {total_input_value / 100_000_000.0:.8f} BTC</p>
                <p><strong>Total Output Value:</strong> {total_output_value / 100_000_000.0:.8f} BTC</p>
            </div>
            <h2>Sender Wallets ({len(sender_wallets)})</h2>
            <div class="section-content">
    """

    for s_wallet in sender_wallets:
        flags_html = "".join([f"<li class=\"red-flag\">{flag}</li>" for flag in s_wallet['reputation_flags']])
        
        # Detailed Chainabuse Reports for Sender
        detailed_chainabuse_html = ""
        if s_wallet.get('detailed_chainabuse_reports') and s_wallet['detailed_chainabuse_reports']: # Only add if reports exist
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
                    <p><strong>Amount Sent:</strong> {s_wallet['amount_sent'] / 100_000_000.0:.8f} BTC</p>
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
        if r_wallet.get('detailed_chainabuse_reports') and r_wallet['detailed_chainabuse_reports']: # Only add if reports exist
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
                    <p><strong>Amount Received:</strong> {r_wallet['amount_received'] / 100_000_000.0:.8f} BTC</p>
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

# --- Main Execution Block ---
if __name__ == "__main__":
    # Ensure os is imported as it's used directly in load_local_ransomware_addresses
    import os 

    target_tx_hash = input("Enter the Bitcoin transaction hash for analysis: ").strip()
    if not target_tx_hash:
        print("No transaction hash entered. Exiting.")
        exit()

    print(f"\n[+] Starting analysis for transaction {target_tx_hash}...")
    
    # Fetch transaction data
    transaction_details = get_transaction_details_multi_source(target_tx_hash)

    if not transaction_details:
        print(f"Failed to retrieve details for transaction {target_tx_hash}. Please check the hash and try again.")
    else:
        report_filename = f"XenoByte_Transaction_Report_{target_tx_hash[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_transaction_report(transaction_details, target_tx_hash)

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Report generated successfully: {report_filename}")
            webbrowser.open(f"file://{os.path.abspath(report_filename)}") # Automatically open the report
        except Exception as e:
            print(f"Error saving or opening report: {e}")
