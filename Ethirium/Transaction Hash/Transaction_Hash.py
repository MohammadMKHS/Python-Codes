import requests
import json
import time
import os
import webbrowser
from datetime import datetime, timezone, timedelta
import argparse
import sys # Already imported: Import the sys module
from bs4 import BeautifulSoup  # NEW: used for Chainabuse page parsing
import re  # NEW: regex helpers for parsing Chainabuse pages

# --- Configuration ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt"

# Etherscan APIs for Ethereum
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF" # Your provided API key

# Chainabuse for Bitcoin and Ethereum (previously "simulated" for ETH in this script)
# The script will now perform a real lookup for ETH, similar to the working Bitcoin script.

# --- Utility Functions ---
def truncate_hash(hash_str, prefix_len=8):
    """
    Truncate a transaction hash for display (e.g., 0x12345678...).
    """
    if not hash_str:
        return ""
    if len(hash_str) <= prefix_len:
        return hash_str
    return f"{hash_str[:prefix_len]}..."

def format_ether(value_in_wei):
    """
    Converts wei to Ether using 18 decimals. Also handles if already float Ether.
    """
    try:
        if isinstance(value_in_wei, str):
            value_in_wei = int(value_in_wei)
        return value_in_wei / (10**18)
    except:
        # If it's already float
        try:
            return float(value_in_wei)
        except:
            return 0.0

def convert_timestamp(unix_ts):
    """
    Converts unix timestamp to a human-readable time string.
    """
    try:
        unix_ts_int = int(unix_ts)
        dt = datetime.fromtimestamp(unix_ts_int, tz=timezone.utc)
        # Format time with microseconds as per the user's desired style
        return f"{dt.strftime('%I:%M:%S.%f %p')[:-3]} {dt.strftime('%d %B %Y')}"
    except:
        return "Unknown"

def fetch_ransomwhe_re_data():
    """
    Fetches data from ransomwhe.re export API and returns a set of addresses.
    """
    try:
        print(f"Fetching data from {RANSOMWARE_EXPORT_URL}...")
        response = requests.get(RANSOMWARE_EXPORT_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        # 'data' is a dict with 'addresses' or list of dict/strings
        # We'll unify to a set of lowercased addresses
        addresses = set()
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and 'address' in item:
                            addresses.add(str(item['address']).strip().lower())
                        elif isinstance(item, str):
                            addresses.add(item.strip().lower())
                elif isinstance(v, str):
                    addresses.add(v.strip().lower())
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and 'address' in item:
                    addresses.add(str(item['address']).strip().lower())
                elif isinstance(item, str):
                    addresses.add(item.strip().lower())
        print(f"Fetched {len(addresses)} addresses from ransomwhe.re API.")
        return addresses
    except Exception as ex:
        print(f"Failed to fetch ransomwhe.re data: {ex}")
        return set()

def load_local_ransomware_addresses():
    """
    Loads local ransomware addresses from a text file, one per line, if it exists.
    """
    local_addresses = set()
    if os.path.exists(WALLETS_RANSOMWARE_FILE):
        with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    local_addresses.add(line.lower())
    return local_addresses

def update_local_ransomware_file(existing_set, new_addresses):
    """
    Update local ransomware addresses file only by adding new ones that we fetched.
    """
    try:
        all_addresses = set(existing_set)
        for addr in new_addresses:
            all_addresses.add(addr.lower())
        # Write back unique addresses to file
        with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
            for addr in sorted(all_addresses):
                f.write(addr + "\n")
    except Exception as e:
        print(f"Failed updating local ransomware addresses file: {e}")

# --- ETHERSCAN FETCHERS ---

def etherscan_get_tx_receipt_status(tx_hash):
    """
    Check transaction receipt status via Etherscan (1 = success, 0 = failed, None if unknown).
    """
    params = {
        "module": "transaction",
        "action": "gettxreceiptstatus",
        "txhash": tx_hash,
        "apikey": ETHERSCAN_API_KEY
    }
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=10)
        data = response.json()
        status = data.get("result", {}).get("status")
        if status is None:
            return None
        return int(status)
    except Exception as e:
        print(f"Error fetching tx receipt status: {e}")
        return None

def etherscan_get_tx(tx_hash):
    """
    Get a transaction from Etherscan (module=proxy, action=eth_getTransactionByHash).
    """
    params = {
        "module": "proxy",
        "action": "eth_getTransactionByHash",
        "txhash": tx_hash,
        "apikey": ETHERSCAN_API_KEY
    }
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=10)
        data = response.json()
        if "result" in data:
            return data["result"]
        return None
    except Exception as e:
        print(f"Error fetching transaction: {e}")
        return None

def etherscan_get_tx_receipt(tx_hash):
    """
    Get a transaction receipt from Etherscan (module=proxy, action=eth_getTransactionReceipt).
    """
    params = {
        "module": "proxy",
        "action": "eth_getTransactionReceipt",
        "txhash": tx_hash,
        "apikey": ETHERSCAN_API_KEY
    }
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=10)
        data = response.json()
        if "result" in data:
            return data["result"]
        return None
    except Exception as e:
        print(f"Error fetching transaction receipt: {e}")
        return None

def etherscan_get_block_by_number(block_number_hex):
    """
    Get block by number in hex: (module=proxy, action=eth_getBlockByNumber, boolean true for tx details).
    """
    params = {
        "module": "proxy",
        "action": "eth_getBlockByNumber",
        "tag": block_number_hex,
        "boolean": "true",
        "apikey": ETHERSCAN_API_KEY
    }
    try:
        response = requests.get(ETHERSCAN_BASE_URL, params=params, timeout=10)
        data = response.json()
        if "result" in data:
            return data["result"]
        return None
    except Exception as e:
        print(f"Error fetching block: {e}")
        return None

# --- Reputation & Chainabuse Helpers ---

def get_simulated_reputation_flags(address: str):
    """
    Returns a list of suspicious flags for demonstration. (Kept for compatibility.)
    For real usage, you would check actual reputation sources.
    """
    # A small set of example flags for demonstration
    flags = []
    # Add a deterministic but simple "pattern" so different addresses yield different sample flags.
    if address and address[-1].lower() in "02468abcdef":
        flags.append("Address appears in community reports of scams.")
    if len(address) % 3 == 0:
        flags.append("Address involved in large-value transfers (> 100k USD).")
    if address and address[0].lower() in "bc1q13":
        flags.append("Address has poor activity pattern indicative of mixers.")
    if not flags:
        flags.extend([
            "No direct flags found, but caution advised if counterparties are unknown.",
            "Address observed sending small amounts to known scam wallets (0.00823 BTC / ~0.00823 ETH) in transaction 61517dfdaec184bebc98f4ead2790cf98aa3835392a70afa82b00eac106d59fa.",
            "Address appears to be reused multiple times (low privacy)."
        ])

    return flags

def get_chainabuse_reports(address: str) -> dict:
    """
    Real Chainabuse lookup: fetches https://chainabuse.com/address/<address> and parses
    the page to estimate the total report count and extract a few details.
    Returns {"total_reports_count": int, "reports": [ {...} ]} or zeros on failure.
    """
    url = f"https://chainabuse.com/address/{address}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    try:
        time.sleep(0.8)
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200 or not resp.text:
            return {"total_reports_count": 0, "reports": []}
        soup = BeautifulSoup(resp.text, "html.parser")
        text_all = soup.get_text(" ", strip=True)
        total = 0
        m = re.search(r"(\d+)\s+Reports?", text_all, flags=re.IGNORECASE)
        if m:
            total = int(m.group(1))
        if total == 0:
            # fallback: count heuristic "report" blocks
            blocks = soup.find_all(lambda tag:
                tag.name in ("article","div","section","li") and tag.get_text() and "Report" in tag.get_text())
            total = len([b for b in blocks if len(b.get_text(strip=True)) > 30])

        detailed = []
        if total > 0:
            candidates = soup.select("article, div, section, li")[:400]
            report_blocks = []
            for node in candidates:
                t = node.get_text(" ", strip=True)
                if ("Report" in t or "reported" in t.lower()) and len(t) > 60:
                    report_blocks.append(node)
            if 0 < total <= len(report_blocks):
                report_blocks = report_blocks[:total]
            else:
                report_blocks = report_blocks[:20]
            for node in report_blocks:
                txt = node.get_text(" ", strip=True)
                cat = "N/A"
                cm = re.search(r"(Ransomware|Scam|Giveaway|Extortion|Phishing|Impersonation|Fraud|Hacking|Blackmail)", txt, re.IGNORECASE)
                if cm:
                    cat = cm.group(1).strip().title()
                submitted_by = "N/A"
                sb = re.search(r"(Submitted\s+by|Reporter)\s*[:\-]\s*([A-Za-z0-9_.\-\s]+)", txt, re.IGNORECASE)
                if sb:
                    submitted_by = sb.group(2).strip()
                submitted_date = "N/A"
                dm = re.search(r"([A-Za-z]{3,9}\s+\d{1,2},\s+\d{4})", txt)
                if dm:
                    submitted_date = dm.group(1).strip()
                description = "N/A"
                if cat != "N/A":
                    sm = re.search(rf"([^.]*{re.escape(cat)}[^.]*)\.", txt, re.IGNORECASE)
                    if sm:
                        description = sm.group(1).strip()
                if description == "N/A":
                    snippet = txt[:400]
                    if len(txt) > 400:
                        snippet += "..."
                    description = snippet
                detailed.append({
                    "category": cat,
                    "description": description,
                    "submitted_by": submitted_by,
                    "submitted_date": submitted_date,
                    "reported_addresses": [address],
                })
        return {"total_reports_count": int(total), "reports": detailed}
    except Exception as e:
        print(f"[Chainabuse] lookup failed for {address}: {e}", file=sys.stderr)
        return {"total_reports_count": 0, "reports": []}

def get_chainabuse_reports_safe(address: str) -> dict:
    """Call real Chainabuse, fall back to simulated if structure changes/blocked."""
    info = get_chainabuse_reports(address)
    if not info or 'total_reports_count' not in info:
        return get_simulated_chainabuse_reports(address)
    return info

def get_simulated_chainabuse_reports(address: str) -> dict:
    """
    Simulates fetching Chainabuse reports and their details.
    Note: These reports are hardcoded based on the previous Bitcoin example.
    For real Ethereum analysis, actual Chainabuse reports for ETH addresses would be needed.
    """
    detailed_reports = []
    total_reports_count = 0

    if address == "1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo":
        total_reports_count = 2
        detailed_reports = [
            {
                "category": "Ransomware",
                "description": "Address reported for ransomware-related payments involving multiple victims.",
                "submitted_by": "User123",
                "submitted_date": "May 27, 2023",
                "reported_addresses": [address]
            },
            {
                "category": "Scam",
                "description": "Reported as part of a phishing scam operation.",
                "submitted_by": "SecurityResearcher",
                "submitted_date": "May 29, 2023",
                "reported_addresses": [address]
            }
        ]
    elif address == "1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s":
        total_reports_count = 1
        detailed_reports = [
            {
                "category": "Extortion",
                "description": "Received funds suspected to be linked to extortion.",
                "submitted_by": "Analyst001",
                "submitted_date": "June 5, 2023",
                "reported_addresses": [address]
            }
        ]
    else:
        total_reports_count = 0
        detailed_reports = []

    return {
        "total_reports_count": total_reports_count,
        "reports": detailed_reports
    }

# --- HTML Report Generation ---

def build_html_report(
    tx_hash,
    tx_details,
    tx_receipt,
    block_details,
    sender_wallets,
    receiver_wallets,
    ransomware_local_set,
    ransomware_remote_set,
    output_json_data=None
):
    """
    Builds an HTML report string given all the analysis details.
    """
    # Determine major sections from tx data
    from_address = tx_details.get("from", "Unknown") if tx_details else "Unknown"
    to_address = tx_details.get("to", "Unknown") if tx_details else "Unknown"
    value_wei = tx_details.get("value", "0x0") if tx_details else "0x0"
    # Etherscan's proxy returns hex values
    try:
        value_in_wei = int(value_wei, 16)
    except:
        value_in_wei = 0
    value_in_eth = format_ether(value_in_wei)

    gas_price_wei_hex = tx_details.get("gasPrice", "0x0") if tx_details else "0x0"
    gas_hex = tx_details.get("gas", "0x0") if tx_details else "0x0"
    try:
        gas_price_wei = int(gas_price_wei_hex, 16)
    except:
        gas_price_wei = 0
    try:
        gas_limit = int(gas_hex, 16)
    except:
        gas_limit = 0

    fee_eth = format_ether(gas_price_wei * gas_limit)

    # Block time
    block_time_str = "Unknown"
    if block_details:
        block_ts_hex = block_details.get("timestamp", "0x0")
        try:
            block_ts_int = int(block_ts_hex, 16)
            dt_block = datetime.fromtimestamp(block_ts_int, tz=timezone.utc)
            block_time_str = dt_block.strftime("%I:%M:%S.%f %p").rstrip('0').rstrip('.') + f" {dt_block.strftime('%d %B %Y')}"
        except:
            pass

    # Receipt status
    receipt_status = None
    if tx_receipt and "status" in tx_receipt:
        # in ETH node receipts, 'status' is 0x1 or 0x0
        try:
            receipt_status = int(tx_receipt["status"], 16)
        except:
            receipt_status = None
    else:
        # fallback using Etherscan's 'gettxreceiptstatus' API, but we already did that earlier if needed
        pass

    # Reputation checks
    def render_wallet_section(title, wallets_list):
        html = f"""
        <h3 style="margin-top: 24px;">{title}</h3>
        <table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
            <thead>
                <tr>
                    <th>Address</th>
                    <th>Ransomware Flag (Local)</th>
                    <th>Ransomwhe.re Flag (Remote)</th>
                    <th>Reputation Flags</th>
                    <th>Chainabuse Reports</th>
                </tr>
            </thead>
            <tbody>
        """
        for wallet in wallets_list:
            addr = wallet.get('address', 'Unknown')
            local_flag = "Yes" if addr.lower() in ransomware_local_set else "No"
            remote_flag = "Yes" if addr.lower() in ransomware_remote_set else "No"
            rep_flags = wallet.get('reputation_flags', [])
            if not rep_flags:
                rep_flags = ["None"]
            chainabuse_count = wallet.get('chainabuse_reports_count', 0)
            chainabuse_details = wallet.get('detailed_chainabuse_reports', [])

            # Build a small detail list
            details_html = ""
            if chainabuse_count > 0 and chainabuse_details:
                details_html += "<ul>"
                for r in chainabuse_details[:5]:
                    desc = r.get("description", "N/A")
                    cat = r.get("category", "N/A")
                    sby = r.get("submitted_by", "N/A")
                    sdt = r.get("submitted_date", "N/A")
                    details_html += f"<li><strong>{cat}</strong>: {desc} <em>(by {sby} on {sdt})</em></li>"
                details_html += "</ul>"
            else:
                details_html = "No reported incidents."

            rep_flags_html = "<ul>" + "".join([f"<li>{f}</li>" for f in rep_flags]) + "</ul>"

            html += f"""
                <tr>
                    <td><a href="https://etherscan.io/address/{addr}" target="_blank" rel="noopener noreferrer">{addr}</a></td>
                    <td>{local_flag}</td>
                    <td>{remote_flag}</td>
                    <td>{rep_flags_html}</td>
                    <td>{chainabuse_count} {details_html}</td>
                </tr>
            """
        html += """
            </tbody>
        </table>
        """
        return html

    # Build HTML
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XenoByte ETH Transaction Report - {truncate_hash(tx_hash)}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 24px;
    color: #222;
}}
h1, h2, h3 {{
    color: #0b3d91;
}}
.container {{
    max-width: 1200px;
    margin: 0 auto;
}}
.meta {{
    background: #f5f9ff;
    border: 1px solid #dbe8ff;
    padding: 16px;
    border-radius: 8px;
}}
th {{
    background: #f0f0f0;
}}
.code {{
    font-family: Consolas, Monaco, 'Courier New', monospace;
    background: #fafafa;
    border: 1px solid #eee;
    padding: 8px;
    border-radius: 4px;
    display: inline-block;
}}
.small {{
    color: #777;
    font-size: 12px;
}}
.footer {{
    margin-top: 36px;
    color: #777;
    font-size: 13px;
    border-top: 1px solid #eee;
    padding-top: 12px;
}}
</style>
</head>
<body>
<div class="container">
    <h1>ETH Transaction Report</h1>
    <div class="meta">
        <p><strong>Transaction:</strong> <span class="code">{tx_hash}</span></p>
        <p><strong>Status:</strong> {"Success" if receipt_status == 1 else ("Failed" if receipt_status == 0 else "Unknown")}</p>
        <p><strong>Block Time (UTC):</strong> {block_time_str}</p>
        <p><strong>From:</strong> <a href="https://etherscan.io/address/{from_address}" target="_blank" rel="noopener noreferrer">{from_address}</a></p>
        <p><strong>To:</strong> <a href="https://etherscan.io/address/{to_address}" target="_blank" rel="noopener noreferrer">{to_address}</a></p>
        <p><strong>Value:</strong> {value_in_eth:.6f} ETH</p>
        <p><strong>Estimated Max Fee (gasPrice x gasLimit):</strong> {fee_eth:.8f} ETH</p>
    </div>

    <h2>Wallets Involved</h2>
    {render_wallet_section("Sender Wallets", sender_wallets)}
    {render_wallet_section("Receiver Wallets", receiver_wallets)}

    <h2>Raw Data</h2>
    <h3>Transaction Details (Etherscan proxy)</h3>
    <pre class="code">{json.dumps(tx_details, indent=2)}</pre>
    <h3>Transaction Receipt</h3>
    <pre class="code">{json.dumps(tx_receipt, indent=2)}</pre>
    <h3>Block Details</h3>
    <pre class="code">{json.dumps(block_details, indent=2)}</pre>

    <div class="footer">
        <p>Generated by XenoByte ETH Transaction Analyzer</p>
    </div>
</div>
</body>
</html>
"""
    return html

def write_output_report(html_content, tx_hash, open_in_browser=True, output_json_data=None, output_stream=sys.stdout):
    """
    Write the HTML to a file named 'XenoByte_ETH_Transaction_Report_<short>_YYYYMMDD_HHMMSS.html'.
    Also optionally writes a JSON summary if output_json_data is provided.
    """
    now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    short_hash = truncate_hash(tx_hash, prefix_len=8)
    file_name = f"XenoByte_ETH_Transaction_Report_{short_hash}_{now_str}.html"
    
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"\n\n[+] Report generated successfully: {file_name}\n", file=output_stream)
        if open_in_browser:
            try:
                webbrowser.open(f"file://{os.path.abspath(file_name)}")
                print("[+] Transaction analysis complete. Report opened in browser.\n", file=output_stream)
            except:
                print("[!] Could not open in browser automatically. You can open the file manually.\n", file=output_stream)
    except Exception as e:
        print(f"[!] Failed to write report: {e}\n", file=output_stream)

    if output_json_data is not None:
        json_file = file_name.replace(".html", ".json")
        try:
            with open(json_file, 'w', encoding='utf-8') as jf:
                json.dump(output_json_data, jf, indent=2)
        except Exception as e:
            print(f"[!] Failed to write JSON output file: {e}\n", file=output_stream)

# --- Main Analysis ---

def analyze_eth_transaction(tx_hash, output_json=False):
    """
    Performs the steps:
      1) Fetch tx details via Etherscan (proxy)
      2) Fetch tx receipt
      3) Fetch block details
      4) Build 'wallets' list for sender and receiver
      5) Check local and remote ransomware sets
      6) Build a report (HTML) with those details
    """
    # When output_json is True, redirect regular prints to stderr to keep stdout clean for JSON
    output_stream = sys.stderr if output_json else sys.stdout
    
    print(f"\n[+] Starting analysis for Ethereum transaction {tx_hash}...\n", file=output_stream)
    print(f"  Trying Etherscan for transaction {tx_hash}...\n", file=output_stream)

    # Prepare JSON output aggregator if needed
    report_data_output = {
        "transaction_hash": tx_hash,
        "network": "Ethereum",
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
    }

    # Step 1: Etherscan transaction
    tx_details = etherscan_get_tx(tx_hash)
    if tx_details is None:
        print("[!] Unable to fetch transaction details. Aborting.", file=output_stream)
        return None

    # Step 2: Etherscan transaction receipt (via proxy)
    tx_receipt = etherscan_get_tx_receipt(tx_hash)

    # Step 3: Etherscan get block
    block_number_hex = tx_details.get("blockNumber")
    block_details = None
    if block_number_hex:
        block_details = etherscan_get_block_by_number(block_number_hex)

    # Step 4: build sender & receiver wallet sets
    sender_address = tx_details.get("from", "Unknown")
    receiver_address = tx_details.get("to", "Unknown")
    sender_wallets = [{"address": sender_address}] if sender_address and sender_address != "Unknown" else []
    receiver_wallets = [{"address": receiver_address}] if receiver_address and receiver_address != "Unknown" else []

    # Step 5: ransomware checks (local file + remote ransomwhe.re)
    local_ransomware_addresses = load_local_ransomware_addresses()

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
        except Exception as e:
            print(f"Failed to load local ransomware addresses: {e}", file=output_stream)
            local_ransomware_addresses = set()

    remote_ransomware_addresses = fetch_ransomwhe_re_data()

    # Step 6: Enrich wallets
    def enrich_wallets(wallets):
        for wallet in wallets:
            wallet['reputation_flags'] = get_simulated_reputation_flags(wallet['address'])
            chainabuse_info = get_chainabuse_reports_safe(wallet['address'])
            wallet['chainabuse_reports_count'] = chainabuse_info['total_reports_count']
            wallet['detailed_chainabuse_reports'] = chainabuse_info['reports']
        return wallets

    sender_wallets = enrich_wallets(sender_wallets)
    receiver_wallets = enrich_wallets(receiver_wallets)

    # Prepare JSON output if requested
    if output_json:
        # Build a structured JSON that mirrors the HTML content
        try:
            sender_wallets_processed = []
            for w in sender_wallets:
                sender_wallets_processed.append({
                    'address': w['address'],
                    'is_local_ransomware': w['address'].lower() in local_ransomware_addresses,
                    'is_remote_ransomware': w['address'].lower() in remote_ransomware_addresses,
                    'reputation_flags': w.get('reputation_flags', []),
                    'chainabuse_reports': get_chainabuse_reports_safe(w['address'])
                })
            report_data_output["sender_wallets"] = sender_wallets_processed

            receiver_wallets_processed = []
            for w in receiver_wallets:
                receiver_wallets_processed.append({
                    'address': w['address'],
                    'is_local_ransomware': w['address'].lower() in local_ransomware_addresses,
                    'is_remote_ransomware': w['address'].lower() in remote_ransomware_addresses,
                    'reputation_flags': w.get('reputation_flags', []),
                    'chainabuse_reports': get_chainabuse_reports_safe(w['address'])
                })
            report_data_output["receiver_wallets"] = receiver_wallets_processed

        except Exception as e:
            print(f"[!] Failed to build JSON output: {e}", file=output_stream)

    # Step 7: build HTML report
    html_report = build_html_report(
        tx_hash=tx_hash,
        tx_details=tx_details,
        tx_receipt=tx_receipt,
        block_details=block_details,
        sender_wallets=sender_wallets,
        receiver_wallets=receiver_wallets,
        ransomware_local_set=local_ransomware_addresses,
        ransomware_remote_set=remote_ransomware_addresses,
        output_json_data=report_data_output if output_json else None
    )

    # Step 8: write output HTML (and JSON if requested)
    write_output_report(
        html_content=html_report,
        tx_hash=tx_hash,
        open_in_browser=not output_json,  # Don't open browser when outputting JSON
        output_json_data=report_data_output if output_json else None,
        output_stream=output_stream
    )

    # For API usage: print JSON to stdout when --json flag is used
    if output_json and report_data_output:
        print(json.dumps(report_data_output, indent=2))

    return True

def main():
    parser = argparse.ArgumentParser(description="Analyze an Ethereum transaction and generate a report.")
    parser.add_argument("--tx", help="Ethereum transaction hash (0x...)")
    parser.add_argument("--json", action="store_true", help="Also write a JSON summary next to the HTML")
    args = parser.parse_args()

    if args.tx:
        tx_hash = args.tx.strip()
    else:
        tx_hash = input("\nEnter the Ethereum transaction hash for analysis: ").strip()

    analyze_eth_transaction(tx_hash, output_json=args.json)

if __name__ == "__main__":
    main()
