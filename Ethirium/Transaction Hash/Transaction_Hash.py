import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timezone, timedelta
import argparse
import sys

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Etherscan APIs for Ethereum
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF"

API_DELAY_SECONDS = 1

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
                with open(WALLETS_RANSOMWARE_FILE, "w") as f:
                    f.write("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n") # Example Bitcoin address
            
            with open(WALLETS_RANSOMWARE_FILE, "r") as f:
                addresses = f.read().splitlines()
                local_ransomware_addresses.update(addresses)
            print(f"[+] Loaded {len(local_ransomware_addresses)} local ransomware addresses.", file=output_stream)
        except Exception as e:
            print(f"[-] Failed to load local ransomware addresses: {e}", file=output_stream)

def fetch_latest_ransomware_addresses():
    """Fetches and caches the latest ransomware addresses from Ransomwhere.re."""
    global ransomware_api_addresses
    print("[*] Fetching latest ransomware addresses from Ransomwhere.re...")
    try:
        response = requests.get(RANSOMWARE_EXPORT_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # NOTE: The Ransomwhere API returns a list of objects, not just addresses.
        # This code assumes the 'address' key exists.
        for item in data:
            if 'address' in item:
                ransomware_api_addresses.add(item['address'])
        
        # Store the entire data object for later use if needed
        global ransomware_api_data
        ransomware_api_data = data
        
        print(f"[+] Fetched {len(ransomware_api_addresses)} addresses from Ransomwhere.re.")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")

def check_ransomware_and_reputation(address):
    """Checks if an address is on the ransomware list and provides a simulated reputation."""
    reputation_flags = []
    
    # Check against local and API addresses
    if address in local_ransomware_addresses:
        reputation_flags.append("🚨 Known Ransomware Address (Local)")
    if address in ransomware_api_addresses:
        reputation_flags.append("🚨 Known Ransomware Address (API)")
    
    # Check for simulated reputation flags
    simulated_flags = get_simulated_reputation_flags(address)
    reputation_flags.extend(simulated_flags)
    
    # A generic check for known scams (could be expanded)
    if "0xbde430f54a63016d8a5f31f243761653728086a2".lower() in address.lower():
        reputation_flags.append("⚠️ Reported Phishing/Impersonation Scam")

    return reputation_flags

def get_simulated_reputation_flags(address):
    """
    Returns simulated reputation flags for demonstration purposes.
    In a real application, this would be a real-time check against a threat intelligence API.
    """
    simulated_flags = []
    # Hardcoded checks for demonstration
    if address.lower() == "0x1b5e71412004cc38dc711919c4f307d73a64a80ef84e39db84b341f094071af0".lower():
        simulated_flags.append("✅ Reputable Address (Simulated)")
    elif address.lower() == "0xbde430f54a63016d8a5f31f243761653728086a2".lower():
        simulated_flags.append("🚫 Reported Scam Address (Simulated)")
    elif "0x" in address and len(address) > 10:
        simulated_flags.append("✅ Reputable Address (Simulated)")
    return simulated_flags

def get_simulated_chainabuse_reports(address):
    """
    This function is a SIMULATION.
    In a real application, this would call the Chainabuse API with a valid API key
    to get real-time reports. Since we don't have access to the live API,
    we'll return a hardcoded report for demonstration.
    """
    if address.lower() == "0xbde430f54a63016d8a5f31f243761653728086a2".lower():
        return [
            {
                "report_id": "report_eth_123",
                "scam_type": "Phishing Scam",
                "reported_domain": None,
                "reported_address": "0xbde430f54a63016d8a5f31f243761653728086a2",
                "submitted_by": "Anonymous",
                "date": "2022-11-25",
                "description": "Scammer's wallet address."
            },
            {
                "report_id": "report_eth_456",
                "scam_type": "Impersonation Scam",
                "reported_domain": "https://ethpromotion.info",
                "reported_address": "0xbde430f54a63016d8a5f31f243761653728086a2",
                "submitted_by": "Anonymous",
                "date": "2022-11-05",
                "description": "Trust trading scam site."
            }
        ]
    return []

def get_transaction_details_etherscan(tx_hash):
    """Fetches transaction details from Etherscan API."""
    print(f"[*] Fetching transaction details for hash: {tx_hash}...")
    try:
        url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data['result'] is None:
            return None
        
        print("[+] Transaction details fetched successfully.")
        return data['result']
        
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred fetching transaction details: {e}")
    return None

def get_transaction_receipt_etherscan(tx_hash):
    """Fetches transaction receipt from Etherscan API to get gasUsed."""
    print(f"[*] Fetching transaction receipt for hash: {tx_hash}...")
    try:
        url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionReceipt&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data['result'] is None:
            print("[-] Could not find transaction receipt.")
            return None

        print("[+] Transaction receipt fetched successfully.")
        return data['result']

    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred fetching transaction receipt: {e}")
    return None

def get_internal_transactions_etherscan(tx_hash):
    """Fetches internal transactions from Etherscan API."""
    print(f"[*] Fetching internal transactions for hash: {tx_hash}...")
    try:
        url = f"{ETHERSCAN_BASE_URL}?module=account&action=txlistinternal&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data['status'] == '1' and data['result']:
            print("[+] Internal transactions fetched successfully.")
            return data['result']
        else:
            print(f"[-] Could not find internal transactions. Response: {data}")
            return []
            
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred fetching internal transactions: {e}")
        return []

def get_transaction_and_report(target_tx_hash, output_json):
    """Main function to orchestrate data fetching and report generation."""
    # Fetch data
    transaction_details = get_transaction_details_etherscan(target_tx_hash)
    if not transaction_details:
        return

    transaction_receipt = get_transaction_receipt_etherscan(target_tx_hash)
    internal_transactions = get_internal_transactions_etherscan(target_tx_hash)

    # Combine data from both sources
    if transaction_receipt:
        transaction_details['gasUsed'] = transaction_receipt.get('gasUsed')
        transaction_details['status'] = transaction_receipt.get('status')
        transaction_details['cumulativeGasUsed'] = transaction_receipt.get('cumulativeGasUsed')

    # Process wallets
    sender_address = transaction_details.get('from', 'N/A')
    receiver_address = transaction_details.get('to', 'N/A')

    # Prepare data for report
    report_data = {
        "transaction_details": transaction_details,
        "sender_wallet": {
            "address": sender_address,
            "reputation_flags": check_ransomware_and_reputation(sender_address),
            "chainabuse_reports": get_simulated_chainabuse_reports(sender_address)
        },
        "receiver_wallets": [{
            "address": receiver_address,
            "reputation_flags": check_ransomware_and_reputation(receiver_address),
            "chainabuse_reports": get_simulated_chainabuse_reports(receiver_address)
        }],
        "internal_transactions": internal_transactions
    }
    
    if output_json:
        print(json.dumps(report_data, indent=4))
        print("\n[+] Transaction analysis complete. JSON output displayed.")
        return

    # Generate and save HTML report
    report_filename = f"XenoByte_ETH_Transaction_Report_{target_tx_hash[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_report_content = generate_html_report(report_data, target_tx_hash)

    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report_content)
        print(f"\n[+] Report generated successfully: {report_filename}")
        webbrowser.open(f"file://{os.path.abspath(report_filename)}")
        print("\n[+] Transaction analysis complete. Report opened in browser.")
    except Exception as e:
        print(f"[-] Failed to generate or open report: {e}")

def generate_html_report(report_data, tx_hash):
    """Generates the HTML report content, updated to use a dark theme."""
    transaction_details = report_data["transaction_details"]
    sender_wallet = report_data["sender_wallet"]
    receiver_wallets = report_data["receiver_wallets"]
    internal_transactions = report_data["internal_transactions"]

    # --- HTML and CSS Template (UPDATED for dark theme) ---
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XenoByte Transaction Report: {tx_hash[:10]}...</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
        <style>
            :root {{
                --background-color-dark: #121212;
                --text-color-dark: #e0e0e0;
                --border-color-dark: #444;
                --card-bg-dark: #1e1e1e;
                --header-bg-dark: #333;
                --link-color-dark: #81c784;
                --icon-color-dark: #bdbdbd;

                --background-color-light: #f5f5f5;
                --text-color-light: #333;
                --border-color-light: #ccc;
                --card-bg-light: #ffffff;
                --header-bg-light: #e0e0e0;
                --link-color-light: #388e3c;
                --icon-color-light: #757575;
            }}

            body.dark-theme {{
                background-color: var(--background-color-dark);
                color: var(--text-color-dark);
            }}

            body.light-theme {{
                background-color: var(--background-color-light);
                color: var(--text-color-light);
            }}

            body {{
                font-family: 'Roboto', sans-serif;
                margin: 0;
                padding: 20px;
                line-height: 1.6;
            }}

            a {{
                color: var(--link-color-dark);
                text-decoration: none;
            }}

            a:hover {{
                text-decoration: underline;
            }}
            
            h1, h2, h3 {{
                color: var(--text-color-dark);
            }}
            
            .container {{
                max-width: 1200px;
                margin: auto;
                background: var(--card-bg-dark);
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            }}

            .header {{
                background: var(--header-bg-dark);
                padding: 15px;
                border-radius: 8px 8px 0 0;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            .report-info {{
                font-family: 'Share Tech Mono', monospace;
                font-size: 0.9em;
            }}

            .section {{
                border: 1px solid var(--border-color-dark);
                padding: 15px;
                margin-top: 20px;
                border-radius: 8px;
            }}
            
            .section h2 {{
                margin-top: 0;
                border-bottom: 2px solid var(--border-color-dark);
                padding-bottom: 5px;
            }}

            .key-value {{
                display: flex;
                flex-wrap: wrap;
                margin-bottom: 5px;
            }}

            .key {{
                font-weight: 500;
                min-width: 150px;
            }}
            
            .value {{
                word-break: break-all;
                font-family: 'Share Tech Mono', monospace;
                flex: 1;
            }}

            .wallet-card {{
                background: var(--card-bg-dark);
                padding: 10px;
                border: 1px solid var(--border-color-dark);
                border-radius: 6px;
                margin-top: 10px;
            }}

            .wallet-card h3 {{
                margin-top: 0;
                font-size: 1.1em;
            }}
            
            .label {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                font-weight: bold;
                margin-right: 5px;
                margin-bottom: 5px;
            }}

            .label.warning {{
                background-color: #ffc107;
                color: #212121;
            }}
            .label.danger {{
                background-color: #f44336;
                color: #fff;
            }}
            .label.safe {{
                background-color: #4caf50;
                color: #fff;
            }}

            .report-card {{
                background: var(--card-bg-dark);
                border: 1px solid var(--border-color-dark);
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 10px;
            }}
            .report-card h4 {{
                margin-top: 0;
                margin-bottom: 5px;
            }}

            .mode-toggle {{
                background: var(--card-bg-dark);
                border: 1px solid var(--border-color-dark);
                color: var(--text-color-dark);
                padding: 5px 10px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 0.9em;
            }}
            
            .mode-toggle:hover {{
                background: var(--header-bg-dark);
            }}

            @media (prefers-color-scheme: light) {{
                body {{
                    background-color: var(--background-color-light);
                    color: var(--text-color-light);
                }}
                h1, h2, h3 {{
                    color: var(--text-color-light);
                }}
                .container {{
                    background: var(--card-bg-light);
                    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    background: var(--header-bg-light);
                }}
                a {{
                    color: var(--link-color-light);
                }}
                .section {{
                    border: 1px solid var(--border-color-light);
                }}
                .section h2 {{
                    border-bottom: 2px solid var(--border-color-light);
                }}
                .wallet-card {{
                    background: var(--card-bg-light);
                    border: 1px solid var(--border-color-light);
                }}
                .report-card {{
                    background: var(--card-bg-light);
                    border: 1px solid var(--border-color-light);
                }}
                .mode-toggle {{
                    background: var(--card-bg-light);
                    border: 1px solid var(--border-color-light);
                    color: var(--text-color-light);
                }}
                .mode-toggle:hover {{
                    background: var(--header-bg-light);
                }}
            }}
        </style>
    </head>
    <body class="dark-theme">
        <div class="container">
            <div class="header">
                <div class="report-info">
                    <p><strong>XenoByte Transaction Report</strong></p>
                    <p>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                <button class="mode-toggle" id="mode-toggle-button">Light Mode</button>
            </div>
            
            <div class="section">
                <h2>Transaction Overview</h2>
                <div class="key-value"><span class="key">Transaction Hash:</span> <span class="value">{transaction_details.get('hash', 'N/A')}</span></div>
                <div class="key-value"><span class="key">Block Number:</span> <span class="value">{int(transaction_details.get('blockNumber', '0x0'), 16)}</span></div>
                <div class="key-value"><span class="key">From:</span> <span class="value"><a href="https://etherscan.io/address/{transaction_details.get('from', 'N/A')}" target="_blank">{transaction_details.get('from', 'N/A')}</a></span></div>
                <div class="key-value"><span class="key">To:</span> <span class="value"><a href="https://etherscan.io/address/{transaction_details.get('to', 'N/A')}" target="_blank">{transaction_details.get('to', 'N/A')}</a></span></div>
                <div class="key-value"><span class="key">Value:</span> <span class="value">{int(transaction_details.get('value', '0x0'), 16) / 1e18} ETH</span></div>
                <div class="key-value"><span class="key">Gas Used:</span> <span class="value">{int(transaction_details.get('gasUsed', '0x0'), 16)}</span></div>
                <div class="key-value"><span class="key">Gas Price:</span> <span class="value">{int(transaction_details.get('gasPrice', '0x0'), 16) / 1e9} Gwei</span></div>
                <div class="key-value"><span class="key">Nonce:</span> <span class="value">{int(transaction_details.get('nonce', '0x0'), 16)}</span></div>
            </div>

            <div class="section">
                <h2>Sender Wallet Analysis</h2>
                <div class="wallet-card">
                    <h3><a href="https://etherscan.io/address/{sender_wallet['address']}" target="_blank">{sender_wallet['address']}</a></h3>
                    <p><strong>Reputation:</strong></p>
                    {"".join([f'<span class="label {"danger" if "scam" in flag.lower() else "warning" if "warning" in flag.lower() else "safe"}">{flag}</span>' for flag in sender_wallet['reputation_flags']])}
                    
                    <h4>Chainabuse Reports:</h4>
                    {"".join([f"""
                    <div class="report-card">
                        <p><strong>Type:</strong> {report.get('scam_type', 'N/A')}</p>
                        <p><strong>Submitted by:</strong> {report.get('submitted_by', 'N/A')} on {report.get('date', 'N/A')}</p>
                        <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                        {"<p><strong>Domain:</strong> <a href='" + report.get('reported_domain', '') + "' target='_blank'>" + report.get('reported_domain', '') + "</a></p>" if report.get('reported_domain') else ""}
                    </div>
                    """ for report in sender_wallet['chainabuse_reports']]) if sender_wallet['chainabuse_reports'] else "<p>No Chainabuse reports found for this address.</p>"}
                </div>
            </div>

            <div class="section">
                <h2>Receiver Wallet(s) Analysis</h2>
                {"".join([f"""
                <div class="wallet-card">
                    <h3><a href="https://etherscan.io/address/{wallet['address']}" target="_blank">{wallet['address']}</a></h3>
                    <p><strong>Reputation:</strong></p>
                    {"".join([f'<span class="label {"danger" if "scam" in flag.lower() else "warning" if "warning" in flag.lower() else "safe"}">{flag}</span>' for flag in wallet['reputation_flags']])}
                    
                    <h4>Chainabuse Reports:</h4>
                    {"".join([f"""
                    <div class="report-card">
                        <p><strong>Type:</strong> {report.get('scam_type', 'N/A')}</p>
                        <p><strong>Submitted by:</strong> {report.get('submitted_by', 'N/A')} on {report.get('date', 'N/A')}</p>
                        <p><strong>Description:</strong> {report.get('description', 'N/A')}</p>
                        {"<p><strong>Domain:</strong> <a href='" + report.get('reported_domain', '') + "' target='_blank'>" + report.get('reported_domain', '') + "</a></p>" if report.get('reported_domain') else ""}
                    </div>
                    """ for report in wallet['chainabuse_reports']]) if wallet['chainabuse_reports'] else "<p>No Chainabuse reports found for this address.</p>"}
                </div>
                """ for wallet in receiver_wallets])}
            </div>
            
            <div class="section">
                <h2>Internal Transactions</h2>
                {"".join([f"""
                <div class="key-value">
                    <span class="key">From:</span> <span class="value"><a href="https://etherscan.io/address/{tx.get('from', 'N/A')}" target="_blank">{tx.get('from', 'N/A')}</a></span>
                </div>
                <div class="key-value">
                    <span class="key">To:</span> <span class="value"><a href="https://etherscan.io/address/{tx.get('to', 'N/A')}" target="_blank">{tx.get('to', 'N/A')}</a></span>
                </div>
                <div class="key-value">
                    <span class="key">Value:</span> <span class="value">{int(tx.get('value', '0x0'), 16) / 1e18} ETH</span>
                </div>
                <hr>
                """ for tx in internal_transactions]) if internal_transactions else "<p>No internal transactions found.</p>"}
            </div>
            
        </div>
        <script>
            document.getElementById('mode-toggle-button').addEventListener('click', function() {{
                const body = document.body;
                if (body.classList.contains('dark-theme')) {{
                    body.classList.remove('dark-theme');
                    body.classList.add('light-theme');
                    this.textContent = 'Dark Mode';
                }} else {{
                    body.classList.remove('light-theme');
                    body.classList.add('dark-theme');
                    this.textContent = 'Light Mode';
                }}
            }});
        </script>
    </body>
    </html>
    """
    return html_content

# --- Main Execution Block ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze an Ethereum transaction hash and generate a report.")
    parser.add_argument("tx_hash", help="The Ethereum transaction hash to analyze.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON data to stdout instead of generating an HTML report.")
    args = parser.parse_args()

    target_tx_hash = args.tx_hash
    output_json = args.json

    print(f"\n[+] Starting analysis for transaction {target_tx_hash}...")

    # Fetch and cache ransomware data
    load_local_ransomware_addresses()
    fetch_latest_ransomware_addresses()

    # Get transaction and report
    get_transaction_and_report(target_tx_hash, output_json)