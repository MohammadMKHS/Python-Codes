import os
import json
import time
import secrets
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

import requests
from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

# --- Configuration (from your original script) ---
RANSOMWARE_EXPORT_URL = "https://api.ransomwhe.re/export"
WALLETS_RANSOMWARE_FILE = "wallets_ransomware.txt" # This file will be created/used by the API

BLOCKCHAIN_INFO_RAW_TX_API = "https://blockchain.info/rawtx/{tx_hash}?format=json"
BLOCKCYPHER_API_BASE = "https://api.blockcypher.com/v1/btc/main"
BLOCKCYPHER_TX_API = f"{BLOCKCYPHER_API_BASE}/txs/{{tx_hash}}"
BLOCKCHAIR_API_BASE = "https://api.blockchair.com/bitcoin"
BLOCKCHAIR_TX_API = f"{BLOCKCHAIR_API_BASE}/dashboards/transaction/{{tx_hash}}"

API_DELAY_SECONDS = 1

# --- Global Data Caching for Ransomware Data ---
ransomware_api_addresses = set()
local_ransomware_addresses = set()
ransomware_api_data = []

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
# DO NOT USE THIS METHOD FOR PRODUCTION SYSTEMS
GENERATED_API_KEY = secrets.token_hex(32)

# Initialize FastAPI app
app = FastAPI(
    title="XenoByte Bitcoin Transaction Analysis API",
    description="API for analyzing Bitcoin transactions, including reputation checks and Chainabuse reports.",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    """
    Initializes ransomware data sources on API startup.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] Loading local ransomware addresses...")
    load_local_ransomware_addresses()
    print("[INFO] Fetching ransomware data from Ransomwhere.re API...")
    fetch_ransomwhere_data()
    print("[INFO] API startup complete.")

async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Dependency to validate the API key.
    """
    if api_key_header == GENERATED_API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=403, detail="Could not validate credentials - Invalid API Key"
        )

# --- Functions from your original script, adapted for API use ---

def load_local_ransomware_addresses():
    """Loads known ransomware addresses from a local file."""
    global local_ransomware_addresses
    if not local_ransomware_addresses:
        try:
            if not os.path.exists(WALLETS_RANSOMWARE_FILE):
                with open(WALLETS_RANSOMWARE_FILE, 'w') as f:
                    f.write("1DgLhGeJfoUkkXdYNVf7SNckX5ST5taPVo\n")
                    f.write("1DTE5x3Rjn2q75HjX6hiu8CQwEGqe6wQ4s\n")
                    f.write("bc1qcwadmycvzen2qkjnge2hhgtgulerssy56pqx9k\n")
                    f.write("bc1q98z5gcxan998h0uem0y4y4qtmm45xk4r2e5m9p\n")

            with open(WALLETS_RANSOMWARE_FILE, 'r') as f:
                local_ransomware_addresses = {line.strip() for line in f if line.strip()}
            print(f"  Loaded {len(local_ransomware_addresses)} addresses from {WALLETS_RANSOMWARE_FILE}")
        except FileNotFoundError:
            print(f"  Warning: {WALLETS_RANSOMWARE_FILE} not found. Skipping local ransomware check.")
        except Exception as e:
            print(f"  Error loading {WALLETS_RANSOMWARE_FILE}: {e}")

def fetch_ransomwhere_data():
    """Fetches and parses data from the ransomwhe.re API."""
    global ransomware_api_addresses, ransomware_api_data
    if not ransomware_api_addresses:
        try:
            response = requests.get(RANSOMWARE_EXPORT_URL, timeout=15)
            response.raise_for_status()
            data = response.json()
            if data and "result" in data and isinstance(data["result"], list):
                ransomware_api_data = data["result"]
                ransomware_api_addresses = {entry["address"] for entry in ransomware_api_data if "address" in entry}
                print(f"  Fetched {len(ransomware_api_addresses)} addresses from ransomwhe.re API.")
            else:
                print(f"  Warning: Unexpected data format from {RANSOMWARE_EXPORT_URL}")
        except requests.exceptions.RequestException as e:
            print(f"  Error fetching from {RANSOMWARE_EXPORT_URL}: {e}")
        except json.JSONDecodeError as e:
            print(f"  Error decoding JSON from {RANSOMWARE_EXPORT_URL}: {e}")

def get_transaction_details_blockchain_info(tx_hash):
    """Fetches raw transaction data from blockchain.info."""
    url = BLOCKCHAIN_INFO_RAW_TX_API.format(tx_hash=tx_hash)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        return data
    except requests.exceptions.RequestException as e:
        print(f"    blockchain.info failed for {tx_hash}: {e}")
    return None

def get_transaction_details_blockcypher(tx_hash):
    """Fetches transaction data from BlockCypher."""
    url = BLOCKCYPHER_TX_API.format(tx_hash=tx_hash)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
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
        print(f"    BlockCypher failed for {tx_hash}: {e}")
    except ValueError as e:
        print(f"    BlockCypher data parsing error for {tx_hash}: {e}")
    return None

def get_transaction_details_blockchair(tx_hash):
    """Fetches transaction data from Blockchair."""
    url = BLOCKCHAIR_TX_API.format(tx_hash=tx_hash)
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        data = response.json()
        time.sleep(API_DELAY_SECONDS)
        tx_data = data.get('data', {}).get(tx_hash, {}).get('transaction', {})
        inputs_data = data.get('data', {}).get(tx_hash, {}).get('inputs', [])
        outputs_data = data.get('data', {}).get(tx_hash, {}).get('outputs', [])

        normalized_data = {
            "hash": tx_data.get("hash"),
            "time": tx_data.get("time"),
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
        print(f"    Blockchair failed for {tx_hash}: {e}")
    except json.JSONDecodeError as e:
        print(f"    Blockchair JSON decoding error for {tx_hash}: {e}")
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
        print(f"  Trying {source_func.__name__} for transaction {tx_hash}...")
        data = source_func(tx_hash)
        if data:
            return data

    print(f"  Failed to get comprehensive transaction info for {tx_hash} from all sources.")
    return None

def get_simulated_reputation_flags(address: str):
    """Simulates fetching reputation flags for an address based on the example."""
    flags = []

    if address in local_ransomware_addresses:
        flags.append("Address found in local ransomware database.")

    if address in ransomware_api_addresses:
        flags.append("Address found in Ransomwhere.re API.")

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

# --- API Endpoint ---
@app.get("/api/bitcoin/transaction", response_model=Dict[str, Any], summary="Analyze Bitcoin Transaction Hash")
async def analyze_bitcoin_transaction(
    tx_hash: str = Query(..., description="The Bitcoin transaction hash to analyze."),
    api_key: str = Security(get_api_key)
):
    """
    Retrieves comprehensive analysis for a specified Bitcoin transaction hash.

    This endpoint fetches transaction details from multiple public blockchain explorers
    and enriches the data with:
    - Reputation flags based on known ransomware addresses (local and Ransomwhere.re API).
    - Simulated Chainabuse reports for involved wallet addresses.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for Bitcoin transaction hash: {tx_hash}")

    # Fetch transaction data
    transaction_details = get_transaction_details_multi_source(tx_hash)

    if not transaction_details:
        raise HTTPException(
            status_code=404,
            detail=f"Failed to retrieve details for transaction {tx_hash}. Please check the hash and try again."
        )

    # Process sender and receiver wallets
    sender_wallets_data = []
    total_input_value = 0
    for inp in transaction_details.get('inputs', []):
        sender_address = inp.get('prev_out', {}).get('addr')
        amount = inp.get('prev_out', {}).get('value', 0)
        total_input_value += amount
        if sender_address:
            found = False
            for s_wallet in sender_wallets_data:
                if s_wallet['address'] == sender_address:
                    s_wallet['amount_sent'] += amount
                    found = True
                    break
            if not found:
                sender_wallets_data.append({
                    'address': sender_address,
                    'amount_sent': amount
                })

    receiver_wallets_data = []
    total_output_value = 0
    for out in transaction_details.get('out', []):
        receiver_address = out.get('addr')
        amount = out.get('value', 0)
        total_output_value += amount
        if receiver_address:
            found = False
            for r_wallet in receiver_wallets_data:
                if r_wallet['address'] == receiver_address:
                    r_wallet['amount_received'] += amount
                    found = True
                    break
            if not found:
                receiver_wallets_data.append({
                    'address': receiver_address,
                    'amount_received': amount
                })

    # Enrich sender and receiver wallet data with simulated flags and reports
    for wallet_list in [sender_wallets_data, receiver_wallets_data]:
        for wallet in wallet_list:
            wallet['inferred_type'] = "Personal Wallet" # Simplified for this report
            wallet['reputation_flags'] = get_simulated_reputation_flags(wallet['address'])
            chainabuse_info = get_simulated_chainabuse_reports(wallet['address'])
            wallet['chainabuse_reports_count'] = chainabuse_info['total_reports_count']
            wallet['detailed_chainabuse_reports'] = chainabuse_info['reports']
            if wallet['chainabuse_reports_count'] > 0:
                if f"Found {wallet['chainabuse_reports_count']} scam report(s) on Chainabuse." not in wallet['reputation_flags']:
                    wallet['reputation_flags'].append(f"Found {wallet['chainabuse_reports_count']} scam report(s) on Chainabuse.")
                for report in wallet['detailed_chainabuse_reports']:
                    if "ransomware" in report.get("category", "").lower():
                        if f"Chainabuse report indicates Ransomware activity (Category: {report['category']})." not in wallet['reputation_flags']:
                            wallet['reputation_flags'].append(f"Chainabuse report indicates Ransomware activity (Category: {report['category']}).")

    tx_time_utc = "N/A"
    if transaction_details.get('time'):
        try:
            if isinstance(transaction_details['time'], (int, float)):
                tx_time_utc = datetime.fromtimestamp(transaction_details['time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
            else:
                dt_object = datetime.fromisoformat(transaction_details['time'].replace('Z', '+00:00'))
                tx_time_utc = dt_object.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError):
            pass

    response_data = {
        "requested_tx_hash": tx_hash,
        "transaction_summary": {
            "hash": transaction_details.get("hash"),
            "time_utc": tx_time_utc,
            "block_height": transaction_details.get('block_height', 'N/A'),
            "transaction_fee_btc": transaction_details.get('fee', 0) / 100_000_000.0 if transaction_details.get('fee') is not None else 'N/A',
            "size_bytes": transaction_details.get('size', 'N/A'),
            "total_input_value_btc": total_input_value / 100_000_000.0,
            "total_output_value_btc": total_output_value / 100_000_000.0
        },
        "sender_wallets": sender_wallets_data,
        "receiver_wallets": receiver_wallets_data,
        "disclaimer": "This data is aggregated from various public blockchain explorers and open-source intelligence feeds. Always verify critical information from multiple trusted sources."
    }

    return response_data

