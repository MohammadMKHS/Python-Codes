import requests
import json
import re
import time
import datetime
import os
import webbrowser # Import the webbrowser module

# --- API Configuration ---
# BlockCypher (Bitcoin, Litecoin, Dogecoin) - No API key typically needed for basic lookups, but limits apply.
# Documentation: https://www.blockcypher.com/dev/bitcoin/
BLOCKCYPHER_BTC_BASE_URL = "https://api.blockcypher.com/v1/btc/main"
BLOCKCYPHER_LTC_BASE_URL = "https://api.blockcypher.com/v1/ltc/main"
BLOCKCYPHER_DOGE_BASE_URL = "https://api.blockcypher.com/v1/doge/main"

# Etherscan (Ethereum) - An API key is highly recommended for any significant usage.
# You can get a free API key from https://etherscan.io/myapikey
# Documentation: https://etherscan.io/apis
ETHERSCAN_BASE_URL = "https://api.etherscan.io/api"
ETHERSCAN_API_KEY = "ERDMVYFY2R8WA3HVMXXNBKC79388UND3AF" # <<< Your provided API Key

# Public Ethereum RPC Endpoint (Fallback if Etherscan API Key is missing/invalid)
PUBLIC_ETH_RPC_URL = "https://eth.nownodes.io/" # Heavily rate-limited

# Blockchair (Bitcoin Cash, Dash, Zcash) - Public API, limits apply.
# Documentation: https://blockchair.com/api/docs
BLOCKCHAIR_BCH_BASE_URL = "https://api.blockchair.com/bitcoin-cash"
BLOCKCHAIR_DASH_BASE_URL = "https://api.blockchair.com/dash"
BLOCKCHAIR_ZEC_BASE_URL = "https://api.blockchair.com/zcash"

# Tronscan (Tron) - Public API, limits apply.
# Documentation: https://developers.tron.network/reference/get-account-info
TRONSCAN_BASE_URL = "https://apilist.tronscan.org/api"

# Solscan (Solana) - Public API, limits apply.
# Documentation: https://docs.solscan.io/
SOLSCAN_BASE_URL = "https://api.solscan.io"

# XRPScan (Ripple) - Public API, limits apply.
# Documentation: https://xrpscan.com/api
XRPSCAN_BASE_URL = "https://api.xrpscan.com/api/v1"


API_DELAY_SECONDS = 1  # To respect API rate limits
MAX_RETRIES = 3 # Reduced retries for faster feedback on unsupported APIs
INITIAL_BACKOFF_DELAY = 1 # seconds

# --- CSS Styling ---
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
.content-section p, .content-section table {
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
.wallet-summary-card .red-flag {
    color: #ff4747;
    font-weight: bold;
}
.wallet-summary-card .green-flag {
    color: #47ff47;
}
"""

# --- Helper Functions ---

def get_data_from_api(url, params=None, method="GET", json_payload=None, retries=MAX_RETRIES, backoff_delay=INITIAL_BACKOFF_DELAY):
    """
    Generic function to make HTTP GET/POST requests to an API.
    Handles basic error checking, retries with exponential backoff, and returns the JSON response.
    """
    for i in range(retries):
        try:
            if method == "GET":
                response = requests.get(url, params=params, timeout=15)
            elif method == "POST":
                response = requests.post(url, json=json_payload, timeout=15)
            else:
                print(f"Error: Unsupported HTTP method: {method}")
                return None

            response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            # Specific Etherscan error handling
            if "etherscan.io" in url and data.get('status') == '0':
                error_message = data.get('message', 'Unknown Etherscan API error.')
                if "No transactions found" in error_message:
                    print(f"  Etherscan API returned 'No transactions found'. Skipping further retries for this query.")
                    return None # No need to retry for this specific message
                else:
                    if i < retries - 1:
                        print(f"  Etherscan API returned error (attempt {i+1}/{retries}): {error_message}. Retrying...")
                        time.sleep(backoff_delay * (2 ** i))
                        continue # Continue to next retry attempt
                    else:
                        print(f"  Etherscan API returned error after {retries} attempts: {error_message}")
                        return None # Exhausted retries

            time.sleep(API_DELAY_SECONDS) # Respect rate limits
            return data
        except requests.exceptions.Timeout:
            if i < retries - 1:
                print(f"Error: Request to {url} timed out (attempt {i+1}/{retries}). Retrying...")
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"Error: Request to {url} timed out after {retries} attempts.")
                return None
        except requests.exceptions.ConnectionError:
            if i < retries - 1:
                print(f"Error: Could not connect to {url} (attempt {i+1}/{retries}). Retrying...")
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"Error: Could not connect to {url} after {retries} attempts. Check your internet connection.")
                return None
        except requests.exceptions.HTTPError as e:
            if i < retries - 1:
                print(f"Error fetching data from {url}: HTTP {response.status_code} - {e} (attempt {i+1}/{retries}). Retrying...")
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"Error fetching data from {url}: HTTP {response.status_code} - {e} after {retries} attempts.")
                return None
        except json.JSONDecodeError:
            if i < retries - 1:
                print(f"Error: Could not decode JSON from response at {url} (attempt {i+1}/{retries}). Raw response: {response.text}. Retrying...")
                time.sleep(backoff_delay * (2 ** i))
            else:
                print(f"Error: Could not decode JSON from response at {url} after {retries} attempts. Raw response: {response.text}")
                return None
        except Exception as e:
            print(f"An unexpected error occurred while fetching data from {url}: {e}")
            return None
    return None

# --- Address Identification Functions ---

def is_bitcoin_address(address):
    return re.match(r"^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}$", address) is not None

def is_ethereum_address(address):
    return re.match(r"^0x[a-fA-F0-9]{40}$", address) is not None

def is_litecoin_address(address):
    # Litecoin addresses typically start with 'L', 'M', or 'ltc1' (bech32)
    return re.match(r"^(L|M|ltc1)[a-zA-HJ-NP-Z0-9]{25,39}$", address) is not None

def is_ripple_address(address):
    # Ripple addresses start with 'r' and are typically 33-35 characters long
    return re.match(r"^r[0-9a-zA-Z]{24,34}$", address) is not None

def is_dogecoin_address(address):
    # Dogecoin addresses typically start with 'D', 'A', or '9'
    return re.match(r"^[DA9][a-zA-Z0-9]{33}$", address) is not None

def is_bitcoin_cash_address(address):
    # Bitcoin Cash addresses have two main formats: legacy (starts with 1 or 3) and CashAddr (starts with bitcoincash:)
    # This regex focuses on CashAddr, as legacy can conflict with BTC
    return re.match(r"^(bitcoincash:)?(q|p)[0-9a-z]{40,}$", address) is not None or \
           re.match(r"^[13][a-zA-HJ-NP-Z0-9]{25,39}$", address) is not None # Legacy format (can overlap with BTC)

def is_dash_address(address):
    # Dash addresses typically start with 'X' or '7'
    return re.match(r"^(X|7)[a-zA-Z0-9]{33}$", address) is not None

def is_zcash_address(address):
    # Zcash addresses can start with 't' (transparent) or 'z' (shielded)
    return re.match(r"^[tz][0-9a-zA-Z]{33,95}$", address) is not None

def is_monero_address(address):
    # Monero addresses are long, start with '4' or '8'
    return re.match(r"^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$", address) is not None

def is_tron_address(address):
    # Tron addresses start with 'T' and are 34 characters long
    return re.match(r"^T[a-zA-Z0-9]{33}$", address) is not None

def is_binance_coin_address(address):
    # BNB (BEP20) addresses are Ethereum-compatible, starting with '0x'
    # BNB (BEP2) addresses start with 'bnb'
    return re.match(r"^0x[a-fA-F0-9]{40}$", address) is not None or \
           re.match(r"^bnb[0-9a-zA-Z]{39}$", address) is not None

def is_cardano_address(address):
    # Cardano addresses (Shelley era) start with 'addr1'
    return re.match(r"^addr1[0-9a-z]{98,}$", address) is not None

def is_solana_address(address):
    # Solana addresses are Base58 encoded, typically 32-44 characters
    return re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", address) is not None

def is_polkadot_address(address):
    # Polkadot addresses (Substrate format) typically start with '1' or '3' (SS58 format)
    return re.match(r"^[13][a-zA-Z0-9]{46,47}$", address) is not None

def is_avalanche_address(address):
    # Avalanche C-chain addresses are Ethereum-compatible, starting with '0x'
    # P-chain addresses start with 'P-'
    # X-chain addresses start with 'X-'
    return re.match(r"^0x[a-fA-F0-9]{40}$", address) is not None or \
           re.match(r"^[PX]-[a-zA-Z0-9]{36,37}$", address) is not None


# --- Transaction Hash Identification Functions ---

def is_transaction_hash(tx_hash):
    """
    Checks if the given string is likely a transaction hash.
    Assumes a 64-character hexadecimal string (for Bitcoin/Litecoin/Dogecoin/BCH/Dash/Zcash) or
    a 66-character hexadecimal string starting with '0x' (for Ethereum/BNB/AVAX C-chain).
    Tron hashes are 64 hex chars. Solana hashes are Base58.
    """
    return re.match(r"^[0-9a-fA-F]{64}$", tx_hash) is not None or \
           re.match(r"^0x[0-9a-fA-F]{64}$", tx_hash) is not None or \
           re.match(r"^[1-9A-HJ-NP-Za-km-z]{43,44}$", tx_hash) is not None # Solana tx hash length (can vary)


# --- Data Fetching Functions (Simplified) ---

def get_blockcypher_info(address_or_hash, coin_url_base, is_address=True):
    """Generic function for BlockCypher APIs (BTC, LTC, DOGE)."""
    if is_address:
        url = f"{coin_url_base}/addrs/{address_or_hash}"
    else:
        url = f"{coin_url_base}/txs/{address_or_hash}"
    
    data = get_data_from_api(url)
    if not data:
        return None

    if is_address:
        balance_denom = data.get('final_balance', 0) / 10**8
        sent_denom = data.get('total_sent', 0) / 10**8
        received_denom = data.get('total_received', 0) / 10**8
        n_tx = data.get('n_tx', 0)
        coin_unit = coin_url_base.split('/')[-1].upper() # e.g., BTC, LTC, DOGE
        return {
            "address": address_or_hash,
            "balance": f"{balance_denom:.8f} {coin_unit}",
            "total_sent": f"{sent_denom:.8f} {coin_unit}",
            "total_received": f"{received_denom:.8f} {coin_unit}",
            "transaction_count": n_tx,
            "last_seen": "N/A (API limitation)"
        }
    else: # Transaction
        inputs = data.get('inputs', [])
        outputs = data.get('outputs', [])
        sender_addresses = list(set([a for inp in inputs if 'addresses' in inp for a in inp['addresses']]))
        receiver_addresses = list(set([a for out in outputs if 'addresses' in out for a in out['addresses']]))
        total_value_satoshis = sum(out.get('value', 0) for out in outputs)
        coin_unit = coin_url_base.split('/')[-1].upper()
        total_value_denom = total_value_satoshis / 10**8
        return {
            "hash": address_or_hash,
            "sender": ", ".join(sender_addresses) if sender_addresses else "Unknown",
            "receiver": ", ".join(receiver_addresses) if receiver_addresses else "Unknown",
            "value": f"{total_value_denom:.8f} {coin_unit}",
            "block_height": data.get('block_height'),
            "confirmed_at": data.get('confirmed')
        }

def get_blockchair_info(address_or_hash, coin_url_base, is_address=True):
    """Generic function for Blockchair APIs (BCH, DASH, ZEC)."""
    if is_address:
        url = f"{coin_url_base}/dashboards/address/{address_or_hash}"
    else:
        url = f"{coin_url_base}/dashboards/transaction/{address_or_hash}" # Blockchair has transaction dashboards too
    
    data = get_data_from_api(url)
    if not data or not data.get('data'):
        return None

    if is_address:
        address_data = list(data['data'].values())[0]['address'] # First key is the address itself
        balance_denom = address_data.get('balance', 0) / 10**8
        sent_denom = address_data.get('spent_total', 0) / 10**8
        received_denom = address_data.get('received_total', 0) / 10**8
        n_tx = address_data.get('transaction_count', 0)
        last_seen_timestamp = address_data.get('last_seen_time') # ISO format
        last_seen = datetime.datetime.fromisoformat(last_seen_timestamp).strftime('%Y-%m-%d %H:%M:%S UTC') if last_seen_timestamp else "N/A"
        coin_unit = coin_url_base.split('/')[-1].upper().replace('-CASH', 'CASH')
        return {
            "address": address_or_hash,
            "balance": f"{balance_denom:.8f} {coin_unit}",
            "total_sent": f"{sent_denom:.8f} {coin_unit}",
            "total_received": f"{received_denom:.8f} {coin_unit}",
            "transaction_count": n_tx,
            "last_seen": last_seen
        }
    else: # Transaction
        tx_data = list(data['data'].values())[0]['transaction']
        inputs = list(data['data'].values())[0]['inputs']
        outputs = list(data['data'].values())[0]['outputs']

        sender_addresses = list(set([inp['recipient'] for inp in inputs if 'recipient' in inp]))
        receiver_addresses = list(set([out['recipient'] for out in outputs if 'recipient' in out]))
        
        total_value_denom = tx_data.get('total_output', 0) / 10**8
        coin_unit = coin_url_base.split('/')[-1].upper().replace('-CASH', 'CASH')
        return {
            "hash": address_or_hash,
            "sender": ", ".join(sender_addresses) if sender_addresses else "Unknown",
            "receiver": ", ".join(receiver_addresses) if receiver_addresses else "Unknown",
            "value": f"{total_value_denom:.8f} {coin_unit}",
            "block_height": tx_data.get('block_id'),
            "confirmed_at": tx_data.get('time')
        }

def get_ethereum_info(address_or_hash, is_address=True):
    """Ethereum specific fetching (Etherscan primary, Public RPC fallback)."""
    if is_address:
        print(f"Fetching Ethereum address data for {address_or_hash} from Etherscan...")
        balance_url = f"{ETHERSCAN_BASE_URL}?module=account&action=balance&address={address_or_hash}&tag=latest&apikey={ETHERSCAN_API_KEY}"
        tx_list_url = f"{ETHERSCAN_BASE_URL}?module=account&action=txlist&address={address_or_hash}&startblock=0&endblock=99999999&sort=desc&apikey={ETHERSCAN_API_KEY}"
        
        balance_data = get_data_from_api(balance_url)
        tx_data = get_data_from_api(tx_list_url)

        balance_eth = 0
        if balance_data and balance_data.get('status') == '1' and balance_data.get('result') is not None:
            balance_eth = int(balance_data['result']) / 10**18

        total_sent_eth = 0
        total_received_eth = 0
        last_tx_time = "N/A"
        transaction_count = 0

        if tx_data and tx_data.get('status') == '1' and tx_data.get('result'):
            transactions = tx_data['result']
            transaction_count = len(transactions)
            if transactions:
                last_tx_timestamp = int(transactions[0]['timeStamp'])
                last_tx_time = datetime.datetime.fromtimestamp(last_tx_timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            for tx in transactions:
                try:
                    value_wei = int(tx.get('value', '0'))
                    value_eth = value_wei / 10**18
                    if tx.get('from', '').lower() == address_or_hash.lower():
                        total_sent_eth += value_eth
                    elif tx.get('to', '').lower() == address_or_hash.lower():
                        total_received_eth += value_eth
                except ValueError:
                    pass # Ignore unparsable values

        return {
            "address": address_or_hash,
            "balance": f"{balance_eth:.8f} ETH",
            "total_sent": f"{total_sent_eth:.8f} ETH",
            "total_received": f"{total_received_eth:.8f} ETH",
            "transaction_count": transaction_count,
            "last_seen": last_tx_time,
        }
    else: # Transaction
        print(f"Fetching Ethereum transaction data for {address_or_hash} from Etherscan...")
        tx_url = f"{ETHERSCAN_BASE_URL}?module=proxy&action=eth_getTransactionByHash&txhash={address_or_hash}&apikey={ETHERSCAN_API_KEY}"
        data = get_data_from_api(tx_url)

        if data and data.get('result') and data['result'] != "null":
            tx = data['result']
            value_wei = int(tx.get('value', '0x0'), 16)
            value_eth = value_wei / 10**18
            block_number_hex = tx.get('blockNumber', '0x0')
            block_number = int(block_number_hex, 16) if block_number_hex != '0x' else 0
            timestamp = "N/A (Transaction might be pending)"
            if block_number > 0:
                block_params = {
                    "module": "block", "action": "getblockreward", "blockno": block_number, "apikey": ETHERSCAN_API_KEY
                }
                block_data = get_data_from_api(ETHERSCAN_BASE_URL, block_params)
                if block_data and block_data.get('status') == '1' and block_data.get('result'):
                    timestamp = datetime.datetime.fromtimestamp(int(block_data['result']['timeStamp']), datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            return {
                "hash": address_or_hash,
                "sender": tx.get('from'),
                "receiver": tx.get('to'),
                "value": f"{value_eth:.8f} ETH",
                "block_number": block_number,
                "timestamp": timestamp
            }
        else:
            print(f"Etherscan failed for {address_or_hash}. Trying public RPC (limited data).")
            payload = {"jsonrpc": "2.0", "method": "eth_getTransactionByHash", "params": [address_or_hash], "id": 1}
            data = get_data_from_api(PUBLIC_ETH_RPC_URL, method="POST", json_payload=payload)
            if data and 'result' in data and data['result'] is not None:
                tx = data['result']
                value_wei = int(tx.get('value', '0x0'), 16) if tx.get('value') else 0
                value_eth = value_wei / 10**18
                return {
                    "hash": address_or_hash,
                    "sender": tx.get('from', 'Unknown'),
                    "receiver": tx.get('to', 'Unknown'),
                    "value": f"{value_eth:.8f} ETH",
                    "block_number": int(tx.get('blockNumber', '0x0'), 16) if tx.get('blockNumber') else 'N/A',
                    "timestamp": "N/A (Public RPC limitation)"
                }
            return None

def get_tron_info(address_or_hash, is_address=True):
    """Tron specific fetching (Tronscan API)."""
    if is_address:
        url = f"{TRONSCAN_BASE_URL}/account/detail?address={address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('address'):
            balance_trx = data.get('balance', 0) / 1_000_000 # TRX is 6 decimal places
            total_transactions = data.get('totalTransactionCount', 0)
            last_op_time = data.get('latestOperationTime', 0) # Milliseconds Unix timestamp
            last_seen = datetime.datetime.fromtimestamp(last_op_time / 1000, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if last_op_time else "N/A"
            return {
                "address": address_or_hash,
                "balance": f"{balance_trx:.6f} TRX",
                "total_transactions": total_transactions,
                "last_seen": last_seen
            }
    else: # Transaction
        url = f"{TRONSCAN_BASE_URL}/transaction/{address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('hash'):
            value_sun = data.get('amount', 0) # Amount in SUN
            value_trx = value_sun / 1_000_000
            timestamp_ms = data.get('timestamp', 0)
            timestamp = datetime.datetime.fromtimestamp(timestamp_ms / 1000, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp_ms else "N/A"
            return {
                "hash": address_or_hash,
                "sender": data.get('ownerAddress', 'Unknown'),
                "receiver": data.get('toAddress', 'Unknown'),
                "value": f"{value_trx:.6f} TRX",
                "block_number": data.get('block', 'N/A'),
                "timestamp": timestamp
            }
    return None

def get_solana_info(address_or_hash, is_address=True):
    """Solana specific fetching (Solscan API)."""
    if is_address:
        url = f"{SOLSCAN_BASE_URL}/account?account={address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('data') and data['data'].get('account'):
            account_data = data['data']['account']
            balance_lamports = account_data.get('lamports', 0)
            balance_sol = balance_lamports / 1_000_000_000 # 9 decimal places
            tx_count = account_data.get('txCount', 0)
            return {
                "address": address_or_hash,
                "balance": f"{balance_sol:.9f} SOL",
                "transaction_count": tx_count,
                "last_seen": "N/A (API limitation)" # Solscan account endpoint doesn't directly provide last seen
            }
    else: # Transaction
        url = f"{SOLSCAN_BASE_URL}/transaction?tx={address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('data') and data['data'].get('tx'):
            tx_data = data['data']['tx']
            # Solana transactions can have multiple senders/receivers and complex structures
            # For simplicity, we'll try to extract common sender/receiver
            sender = tx_data.get('signer', ['Unknown'])[0] if tx_data.get('signer') else 'Unknown'
            receiver_candidates = []
            if tx_data.get('parsedInstruction'):
                for inst in tx_data['parsedInstruction']:
                    if inst.get('program') == 'spl-token' and inst.get('parsed') and inst['parsed'].get('type') == 'transfer':
                        receiver_candidates.append(inst['parsed']['info'].get('destination', 'Unknown'))
                    elif inst.get('parsed') and inst['parsed'].get('info') and inst['parsed']['info'].get('destination'):
                        receiver_candidates.append(inst['parsed']['info']['destination'])
            receiver = ', '.join(list(set(receiver_candidates))) if receiver_candidates else 'Unknown'

            # Value extraction is complex for SOL, often involves multiple token transfers
            # For simplicity, we'll indicate it's complex.
            value = "Complex (multiple transfers/tokens)"
            if tx_data.get('lamport'): # If direct SOL transfer
                value_sol = tx_data['lamport'] / 1_000_000_000
                value = f"{value_sol:.9f} SOL"

            timestamp_unix = tx_data.get('blockTime', 0)
            timestamp = datetime.datetime.fromtimestamp(timestamp_unix, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if timestamp_unix else "N/A"

            return {
                "hash": address_or_hash,
                "sender": sender,
                "receiver": receiver,
                "value": value,
                "block_number": tx_data.get('slot', 'N/A'),
                "timestamp": timestamp
            }
    return None

def get_xrpscan_info(address_or_hash, is_address=True):
    """Ripple specific fetching (XRPScan API)."""
    if is_address:
        url = f"{XRPSCAN_BASE_URL}/account/{address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('account'):
            account_data = data['account']
            balance_xrp = float(account_data.get('xrpBalance', 0))
            tx_count = account_data.get('txCount', 0)
            # XRPScan account endpoint doesn't directly provide last seen time
            return {
                "address": address_or_hash,
                "balance": f"{balance_xrp:.6f} XRP",
                "transaction_count": tx_count,
                "last_seen": "N/A (API limitation)"
            }
    else: # Transaction
        url = f"{XRPSCAN_BASE_URL}/tx/{address_or_hash}"
        data = get_data_from_api(url)
        if data and data.get('tx'):
            tx_data = data['tx']
            sender = tx_data.get('Account', 'Unknown')
            receiver = tx_data.get('Destination', 'Unknown')
            value_xrp = float(tx_data.get('Amount', 0)) if isinstance(tx_data.get('Amount'), (int, float)) else "N/A"
            
            # XRP timestamps are in Ripple Epoch (seconds since 2000-01-01 00:00:00 UTC)
            ripple_epoch = datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            timestamp_ripple_epoch = tx_data.get('date')
            timestamp = "N/A"
            if timestamp_ripple_epoch is not None:
                actual_timestamp = ripple_epoch + datetime.timedelta(seconds=timestamp_ripple_epoch)
                timestamp = actual_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')

            return {
                "hash": address_or_hash,
                "sender": sender,
                "receiver": receiver,
                "value": f"{value_xrp:.6f} XRP" if isinstance(value_xrp, float) else value_xrp,
                "ledger_index": tx_data.get('ledger_index', 'N/A'),
                "timestamp": timestamp
            }
    return None


def get_unsupported_info(address_or_hash, crypto_type, is_address=True):
    """Placeholder for currently unsupported APIs."""
    if is_address:
        return {
            "address": address_or_hash,
            "type": f"{crypto_type} Address (Data Fetching Not Implemented)",
            "status": "API not integrated or requires key/complex setup.",
            "note": "This tool focuses on identification for this crypto. For detailed data, please use a dedicated explorer."
        }
    else: # Transaction
        return {
            "hash": address_or_hash,
            "type": f"{crypto_type} Transaction (Data Fetching Not Implemented)",
            "status": "API not integrated or requires key/complex setup.",
            "note": "This tool focuses on identification for this crypto. For detailed data, please use a dedicated explorer."
        }


def generate_html_report(input_string, report_data, input_category, crypto_type):
    """
    Generates the HTML content for the simplified report.
    """
    current_time = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    
    report_title = f"XenoByte Report - {input_category}: {input_string[:10]}..."
    
    basic_info_html = ""
    transaction_parties_html = "" # For sender/receiver details in transaction reports

    if report_data:
        # --- Basic Information Table ---
        basic_info_html += """
            <h2>Basic Information</h2>
            <div class="section-content">
                <table>
                    <thead>
                        <tr>
                            <th>Field</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        for key, value in report_data.items():
            if key == 'type': # Skip 'type' as it's in the subtitle
                continue
            # Special handling for sender/receiver if it's a transaction, to move to a separate section
            if input_category == "Transaction" and (key == 'sender' or key == 'receiver'):
                continue
            basic_info_html += f"""
                        <tr>
                            <td><strong>{key.replace('_', ' ').title()}</strong></td>
                            <td>{value}</td>
                        </tr>
            """
        basic_info_html += """
                    </tbody>
                </table>
            </div>
        """
        
        # --- Sender/Receiver Wallets for Transactions ---
        if input_category == "Transaction":
            sender_address = report_data.get('sender', 'Unknown')
            receiver_address = report_data.get('receiver', 'Unknown')
            transaction_value = report_data.get('value', 'N/A')

            transaction_parties_html = f"""
                <h2>Involved Wallets</h2>
                <div class="section-content">
                    <div class="wallet-summary-card">
                        <h4>Sender Address: <a href="https://etherscan.io/address/{sender_address}" target="_blank">{sender_address}</a></h4>
                        <p><strong>Amount Sent:</strong> {transaction_value}</p>
                    </div>
                    <div class="wallet-summary-card">
                        <h4>Receiver Address: <a href="https://etherscan.io/address/{receiver_address}" target="_blank">{receiver_address}</a></h4>
                        <p><strong>Amount Received:</strong> {transaction_value}</p>
                    </div>
                </div>
            """
            # Adjust links for Bitcoin/other chain addresses
            if crypto_type == "Bitcoin":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://www.blockchain.com/btc/address/")
            elif crypto_type == "Litecoin":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://live.blockcypher.com/ltc/address/")
            elif crypto_type == "Dogecoin":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://live.blockcypher.com/doge/address/")
            elif crypto_type == "Bitcoin Cash":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://blockchair.com/bitcoin-cash/address/")
            elif crypto_type == "Dash":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://blockchair.com/dash/address/")
            elif crypto_type == "Zcash":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://blockchair.com/zcash/address/")
            elif crypto_type == "Tron":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://tronscan.org/#/address/")
            elif crypto_type == "Solana":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://solscan.io/address/")
            elif crypto_type == "Ripple":
                transaction_parties_html = transaction_parties_html.replace("https://etherscan.io/address/", "https://xrpscan.com/account/")
            # For other unsupported/complex chains, links will default to Etherscan, which might be incorrect but provides a clickable element.

    else:
        # Error message if no report data
        basic_info_html = f"""
            <div class="section-content error-message">
                <p>Could not identify the input as a known cryptocurrency address/transaction, or failed to fetch data.</p>
                <p>Please ensure the input is a valid address or transaction hash for a supported cryptocurrency.</p>
                <p>Supported cryptocurrencies for detailed data fetching: Bitcoin, Ethereum, Litecoin, Dogecoin, Bitcoin Cash, Dash, Zcash, Tron, Solana, Ripple.</p>
                <p>Supported for identification only (data fetching not implemented): Monero, Binance Coin, Cardano, Polkadot, Avalanche.</p>
                <p>Possible reasons for failure:</p>
                <ul>
                    <li>Invalid input format.</li>
                    <li>Network issues.</li>
                    <li>API rate limits reached.</li>
                    <li>The address/transaction might not exist.</li>
                    <li>For full Ethereum data, ensure your Etherscan API key is correctly set.</li>
                </ul>
            </div>
        """

    html_content = f"""
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
            <h1>XenoByte Report</h1>
            <p class="subtitle">Input: <strong>{input_string}</strong></p>
            <p class="subtitle">Type: <strong>{input_category} ({crypto_type})</strong></p>
            <p class="subtitle">Generated: {current_time}</p>
        </div>
        <div class="content-section">
            {basic_info_html}
            {transaction_parties_html}
        </div>
        <footer class="xeno-footer">
            <p>&copy; {datetime.datetime.now().year} XenoByte Threat Intelligence. All rights reserved.</p>
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
                    document.body.classList.add('dark-theme'); // Ensure dark theme is applied by default if no preference
                    document.getElementById('theme-toggle-button').textContent = 'Light Mode';
                }}
            }});
        </script>
    </body>
    </html>
    """
    return html_content

# --- Main Execution Block ---
if __name__ == "__main__":
    user_input = input("Enter Bitcoin/Ethereum/Other Crypto address or transaction hash for analysis: ").strip()
    if not user_input:
        print("No input provided. Exiting.")
        exit()

    report_data = None
    input_category = "Unknown"
    crypto_type = "Unknown"

    # --- Address Identification and Data Fetching ---
    if is_bitcoin_address(user_input):
        input_category = "Address"
        crypto_type = "Bitcoin"
        print(f"\n[+] Detected Bitcoin Address: {user_input}")
        report_data = get_blockcypher_info(user_input, BLOCKCYPHER_BTC_BASE_URL, is_address=True)
    elif is_ethereum_address(user_input):
        input_category = "Address"
        crypto_type = "Ethereum"
        print(f"\n[+] Detected Ethereum Address: {user_input}")
        report_data = get_ethereum_info(user_input, is_address=True)
    elif is_litecoin_address(user_input):
        input_category = "Address"
        crypto_type = "Litecoin"
        print(f"\n[+] Detected Litecoin Address: {user_input}")
        report_data = get_blockcypher_info(user_input, BLOCKCYPHER_LTC_BASE_URL, is_address=True)
    elif is_ripple_address(user_input):
        input_category = "Address"
        crypto_type = "Ripple"
        print(f"\n[+] Detected Ripple Address: {user_input}")
        report_data = get_xrpscan_info(user_input, is_address=True)
    elif is_dogecoin_address(user_input):
        input_category = "Address"
        crypto_type = "Dogecoin"
        print(f"\n[+] Detected Dogecoin Address: {user_input}")
        report_data = get_blockcypher_info(user_input, BLOCKCYPHER_DOGE_BASE_URL, is_address=True)
    elif is_bitcoin_cash_address(user_input):
        input_category = "Address"
        crypto_type = "Bitcoin Cash"
        print(f"\n[+] Detected Bitcoin Cash Address: {user_input}")
        report_data = get_blockchair_info(user_input, BLOCKCHAIR_BCH_BASE_URL, is_address=True)
    elif is_dash_address(user_input):
        input_category = "Address"
        crypto_type = "Dash"
        print(f"\n[+] Detected Dash Address: {user_input}")
        report_data = get_blockchair_info(user_input, BLOCKCHAIR_DASH_BASE_URL, is_address=True)
    elif is_zcash_address(user_input):
        input_category = "Address"
        crypto_type = "Zcash"
        print(f"\n[+] Detected Zcash Address: {user_input}")
        report_data = get_blockchair_info(user_input, BLOCKCHAIR_ZEC_BASE_URL, is_address=True)
    elif is_tron_address(user_input):
        input_category = "Address"
        crypto_type = "Tron"
        print(f"\n[+] Detected Tron Address: {user_input}")
        report_data = get_tron_info(user_input, is_address=True)
    elif is_solana_address(user_input):
        input_category = "Address"
        crypto_type = "Solana"
        print(f"\n[+] Detected Solana Address: {user_input}")
        report_data = get_solana_info(user_input, is_address=True)
    elif is_monero_address(user_input):
        input_category = "Address"
        crypto_type = "Monero"
        print(f"\n[+] Detected Monero Address: {user_input}")
        report_data = get_unsupported_info(user_input, crypto_type, is_address=True)
    elif is_binance_coin_address(user_input):
        input_category = "Address"
        crypto_type = "Binance Coin"
        print(f"\n[+] Detected Binance Coin Address: {user_input}")
        report_data = get_unsupported_info(user_input, crypto_type, is_address=True)
    elif is_cardano_address(user_input):
        input_category = "Address"
        crypto_type = "Cardano"
        print(f"\n[+] Detected Cardano Address: {user_input}")
        report_data = get_unsupported_info(user_input, crypto_type, is_address=True)
    elif is_polkadot_address(user_input):
        input_category = "Address"
        crypto_type = "Polkadot"
        print(f"\n[+] Detected Polkadot Address: {user_input}")
        report_data = get_unsupported_info(user_input, crypto_type, is_address=True)
    elif is_avalanche_address(user_input):
        input_category = "Address"
        crypto_type = "Avalanche"
        print(f"\n[+] Detected Avalanche Address: {user_input}")
        report_data = get_unsupported_info(user_input, crypto_type, is_address=True)
    
    # --- Transaction Hash Identification and Data Fetching ---
    elif is_transaction_hash(user_input):
        # Determine crypto type for hash based on format or trying common APIs
        if len(user_input) == 64: # Common for BTC, LTC, DOGE, BCH, DASH, ZEC, TRX
            # Try Bitcoin first
            report_data = get_blockcypher_info(user_input, BLOCKCYPHER_BTC_BASE_URL, is_address=False)
            if report_data:
                input_category = "Transaction"
                crypto_type = "Bitcoin"
                print(f"\n[+] Detected Bitcoin Transaction Hash: {user_input}")
            else: # Try other 64-char hash coins
                report_data = get_blockcypher_info(user_input, BLOCKCYPHER_LTC_BASE_URL, is_address=False)
                if report_data:
                    input_category = "Transaction"
                    crypto_type = "Litecoin"
                    print(f"\n[+] Detected Litecoin Transaction Hash: {user_input}")
                else:
                    report_data = get_blockcypher_info(user_input, BLOCKCYPHER_DOGE_BASE_URL, is_address=False)
                    if report_data:
                        input_category = "Transaction"
                        crypto_type = "Dogecoin"
                        print(f"\n[+] Detected Dogecoin Transaction Hash: {user_input}")
                    else:
                        report_data = get_blockchair_info(user_input, BLOCKCHAIR_BCH_BASE_URL, is_address=False)
                        if report_data:
                            input_category = "Transaction"
                            crypto_type = "Bitcoin Cash"
                            print(f"\n[+] Detected Bitcoin Cash Transaction Hash: {user_input}")
                        else:
                            report_data = get_blockchair_info(user_input, BLOCKCHAIR_DASH_BASE_URL, is_address=False)
                            if report_data:
                                input_category = "Transaction"
                                crypto_type = "Dash"
                                print(f"\n[+] Detected Dash Transaction Hash: {user_input}")
                            else:
                                report_data = get_blockchair_info(user_input, BLOCKCHAIR_ZEC_BASE_URL, is_address=False)
                                if report_data:
                                    input_category = "Transaction"
                                    crypto_type = "Zcash"
                                    print(f"\n[+] Detected Zcash Transaction Hash: {user_input}")
                                else:
                                    report_data = get_tron_info(user_input, is_address=False)
                                    if report_data:
                                        input_category = "Transaction"
                                        crypto_type = "Tron"
                                        print(f"\n[+] Detected Tron Transaction Hash: {user_input}")
                                    else:
                                        print(f"\n[-] Could not determine specific crypto for 64-char hash: {user_input}. Data fetching not implemented or hash not found.")
                                        input_category = "Transaction"
                                        crypto_type = "Unknown (64-char hash)"
                                        report_data = get_unsupported_info(user_input, crypto_type, is_address=False)


        elif len(user_input) == 66 and user_input.startswith('0x'): # Common for ETH, BNB, AVAX C-chain
            report_data = get_ethereum_info(user_input, is_address=False)
            if report_data:
                input_category = "Transaction"
                crypto_type = "Ethereum"
                print(f"\n[+] Detected Ethereum Transaction Hash: {user_input}")
            else:
                print(f"\n[-] Could not determine specific crypto for 0x-prefixed 66-char hash: {user_input}. Data fetching not implemented or hash not found.")
                input_category = "Transaction"
                crypto_type = "Unknown (0x-prefixed hash)"
                report_data = get_unsupported_info(user_input, crypto_type, is_address=False)
        elif is_solana_address(user_input): # Solana hashes can be identified by address regex due to Base58
            input_category = "Transaction"
            crypto_type = "Solana"
            print(f"\n[+] Detected Solana Transaction Hash: {user_input}")
            report_data = get_solana_info(user_input, is_address=False)
        elif is_ripple_address(user_input): # XRP uses 64-char hex for tx hashes, but its address starts with 'r'
            # If it passes is_ripple_address, it's an address, not a tx hash.
            # XRP tx hashes are 64 hex chars, so they would fall into the first `if len(user_input) == 64` block.
            # This check is mostly for clarity.
            input_category = "Transaction"
            crypto_type = "Ripple"
            print(f"\n[+] Detected Ripple Transaction Hash: {user_input}")
            report_data = get_xrpscan_info(user_input, is_address=False)
        else:
            print(f"\n[-] Could not determine type for hash: {user_input}. It might be an invalid or unsupported hash format.")
    else:
        print(f"\n[-] Input '{user_input}' is not a recognized cryptocurrency address or transaction hash.")

    # --- Generate and Save Report ---
    if report_data:
        report_filename = f"XenoByte_Report_{user_input[:10].replace('0x', '')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_report_content = generate_html_report(user_input, report_data, input_category, crypto_type)

        try:
            with open(report_filename, "w", encoding="utf-8") as f:
                f.write(html_report_content)
            print(f"\n[+] Report generated successfully: {report_filename}")
            webbrowser.open(f"file://{os.path.abspath(report_filename)}") # Automatically open the report
        except Exception as e:
            print(f"Error saving or opening report: {e}")
    else:
        print("\n[!] No report could be generated due to data fetching issues or unrecognized input.")
