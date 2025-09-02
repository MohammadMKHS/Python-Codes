# all_public_api.py
from fastapi import FastAPI, Query, HTTPException, Security, UploadFile, File, status, APIRouter
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any, List
import secrets
import sys
import os
import shutil

# --- PATH ADJUSTMENTS ---
# Get the directory where this script (all_public_api.py) is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# Add the directories containing your utility scripts to sys.path
# This allows importing modules like APT_Checkout, xenobyte_tracer, etc.
# Assumes the structure:
# All_Public/
# ├── APT_Checkout/
# ├── Crypto/
# ├── Hash_Checker/
# └── all_public_api.py
sys.path.insert(0, os.path.join(current_dir, "APT_Checkout"))
sys.path.insert(0, os.path.join(current_dir, "Crypto"))
sys.path.insert(0, os.path.join(current_dir, "Hash_Checker"))

# --- IMPORTS FROM YOUR SCRIPTS ---
# From APT_Checkout/Apt_Checkout.py
try:
    from Apt_Checkout import (
        get_apt_group_info_from_mitre,
        query_otx_for_apt,
        get_iocs_from_github_repo,
        load_random_wallet_addresses,
        load_mitre_attack_data,
        is_valid_ip,
        is_likely_filename,
        RANSOMWARE_WALLETS_FILE
    )
except ImportError as e:
    print(f"ERROR: Could not import functions from Apt_Checkout.py: {e}", file=sys.stderr)
    sys.exit(1)

# From Crypto/xenobyte_tracer.py
try:
    from xenobyte_tracer import (
        is_bitcoin_address, is_ethereum_address, is_litecoin_address,
        is_ripple_address, is_dogecoin_address, is_bitcoin_cash_address,
        is_dash_address, is_zcash_address, is_monero_address,
        is_tron_address, is_binance_coin_address, is_cardano_address,
        is_solana_address, is_polkadot_address, is_avalanche_address,
        is_transaction_hash,
        get_blockcypher_info, get_blockchair_info, get_ethereum_info,
        get_tron_info, get_solana_info, get_xrpscan_info,
        get_unsupported_info,
        BLOCKCYPHER_BTC_BASE_URL, BLOCKCYPHER_LTC_BASE_URL, BLOCKCYPHER_DOGE_BASE_URL,
        BLOCKCHAIR_BCH_BASE_URL, BLOCKCHAIR_DASH_BASE_URL, BLOCKCHAIR_ZEC_BASE_URL
    )
except ImportError as e:
    print(f"ERROR: Could not import functions from xenobyte_tracer.py: {e}", file=sys.stderr)
    sys.exit(1)

# From Hash_Checker/hash_checker_otx.py
try:
    from hash_checker_otx import check_hash_reputation_otx, get_hash_type
except ImportError as e:
    print(f"ERROR: Could not import functions from hash_checker_otx.py: {e}", file=sys.stderr)
    sys.exit(1)

# From Hash_Checker/file_hash_scanner.py
try:
    from file_hash_scanner import calculate_file_hashes, check_hash_reputation
except ImportError as e:
    print(f"ERROR: Could not import functions from file_hash_scanner.py: {e}", file=sys.stderr)
    sys.exit(1)


# --- MAIN FASTAPI APP INSTANCE ---
app = FastAPI(
    title="XenoByte Unified Threat Intelligence API",
    description="A consolidated API for retrieving APT group intelligence, tracing cryptocurrency, checking file hash reputations, and scanning uploaded files.",
    version="1.0.0"
)

# --- GLOBAL API KEY CONFIGURATION ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
GENERATED_API_KEY = secrets.token_hex(32)

@app.on_event("startup")
async def startup_event():
    """
    Initializes MITRE ATT&CK data and prints the generated API key on startup.
    This runs once when the API server starts.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] Initializing MITRE ATT&CK data (for APT module)...")
    if not load_mitre_attack_data():
        print("[ERROR] Failed to load MITRE ATT&CK data. APT API responses might be incomplete.")

async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Dependency to validate the API key for all endpoints.
    """
    if api_key_header == GENERATED_API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials - Invalid API Key"
        )

# --- API ROUTERS FOR EACH MODULE ---

# APT Threat Intelligence Router
apt_router = APIRouter(prefix="/apt", tags=["APT Threat Intelligence"])

@apt_router.get("/", response_model=Dict[str, Any], summary="Get APT Group Threat Intelligence")
async def get_apt_data(
    group: str = Query(..., description="The name of the APT group (e.g., APT28, Fancy Bear, Lazarus Group)."),
    api_key: str = Security(get_api_key)
):
    """
    Retrieves comprehensive threat intelligence for a specified APT group.

    This endpoint gathers information from:
    - MITRE ATT&CK: Details about the intrusion set, including aliases, description, associated software, and techniques.
    - AlienVault OTX: Publicly available Indicators of Compromise (IOCs) related to the group.
    - GitHub (blackorbird/APT_REPORT): Additional IOCs from a public repository.
    - Ransomware Wallet Addresses: A demonstration list of random ransomware wallet addresses.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for APT group: {group}")

    mitre_info = get_apt_group_info_from_mitre(group)
    if not mitre_info:
        print(f"    [-] No detailed MITRE group profile found for '{group}'.")

    otx_result = query_otx_for_apt(group)
    otx_error = None
    if isinstance(otx_result, dict) and otx_result.get("error"):
        otx_error = otx_result["error"]
        print(f"    [ERROR] OTX Query failed: {otx_error}")
        otx_iocs = []
    else:
        otx_iocs = otx_result.get('all_extracted_iocs', [])
        print(f"    [+] Found {len(otx_iocs)} IOCs from OTX.")

    github_iocs = get_iocs_from_github_repo("blackorbird", "APT_REPORT", group)
    print(f"    [+] Found {len(github_iocs)} IOCs from GitHub.")

    ransomware_wallets = load_random_wallet_addresses(count=15)
    if not ransomware_wallets:
        print(f"    [*] No ransomware wallet addresses loaded from '{RANSOMWARE_WALLETS_FILE}'.")

    master_ioc_list = []
    master_ioc_list.extend(otx_iocs)
    master_ioc_list.extend(github_iocs)

    cve_list = set()
    ip_list = set()
    domain_list = set()
    hash_list = set()
    other_list = set()

    for ioc in master_ioc_list:
        ioc_type = ioc.get('type')
        ioc_value = ioc.get('value')
        if not ioc_value:
            continue

        if ioc_type == 'CVE':
            cve_list.add(ioc_value)
        elif ioc_type == 'IPv4':
            ip_list.add(ioc_value)
        elif ioc_type == 'Domain' or ioc_type == 'Hostname':
            domain_value = ioc_value.strip('.').lower()
            if not is_likely_filename(domain_value) and not is_valid_ip(domain_value):
                domain_list.add(domain_value)
        elif ioc_type.startswith('FileHash'):
            hash_list.add(ioc_value)
        else:
            other_list.add(ioc_value)

    categorized_iocs = {
        "cves": sorted(list(cve_list)),
        "ips": sorted(list(ip_list)),
        "domains": sorted(list(domain_list)),
        "hashes": sorted(list(hash_list)),
        "others": sorted(list(other_list))
    }

    return {
        "requested_group": group,
        "mitre_attack_info": mitre_info if mitre_info else "No detailed MITRE ATT&CK information found for this group.",
        "indicators_of_compromise": categorized_iocs,
        "ransomware_wallet_addresses": ransomware_wallets,
        "otx_query_status": "Success" if not otx_error else f"Failed: {otx_error}",
        "disclaimer": "This data is aggregated from various open-source intelligence feeds and MITRE ATT&CK. Always verify critical information from multiple trusted sources."
    }

# Crypto Tracer Router
crypto_router = APIRouter(prefix="/crypto", tags=["Cryptocurrency Tracer"])

@crypto_router.get("/trace", response_model=Dict[str, Any], summary="Trace Cryptocurrency Address or Transaction")
async def trace_crypto(
    input_string: str = Query(..., description="The cryptocurrency address or transaction hash to trace."),
    api_key: str = Security(get_api_key)
):
    """
    Traces a given cryptocurrency address or transaction hash and returns detailed information.

    This endpoint identifies the type of cryptocurrency and whether it's an address or a transaction
    hash, then fetches relevant data from various block explorers.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for crypto trace: {input_string}")

    report_data = None
    input_category = "Unknown"
    crypto_type = "Unknown"

    if is_bitcoin_address(input_string):
        input_category = "Address"
        crypto_type = "Bitcoin"
        report_data = get_blockcypher_info(input_string, BLOCKCYPHER_BTC_BASE_URL, is_address=True)
    elif is_ethereum_address(input_string):
        input_category = "Address"
        crypto_type = "Ethereum"
        report_data = get_ethereum_info(input_string, is_address=True)
    elif is_litecoin_address(input_string):
        input_category = "Address"
        crypto_type = "Litecoin"
        report_data = get_blockcypher_info(input_string, BLOCKCYPHER_LTC_BASE_URL, is_address=True)
    elif is_ripple_address(input_string):
        input_category = "Address"
        crypto_type = "Ripple"
        report_data = get_xrpscan_info(input_string, is_address=True)
    elif is_dogecoin_address(input_string):
        input_category = "Address"
        crypto_type = "Dogecoin"
        report_data = get_blockcypher_info(input_string, BLOCKCYPHER_DOGE_BASE_URL, is_address=True)
    elif is_bitcoin_cash_address(input_string):
        input_category = "Address"
        crypto_type = "Bitcoin Cash"
        report_data = get_blockchair_info(input_string, BLOCKCHAIR_BCH_BASE_URL, is_address=True)
    elif is_dash_address(input_string):
        input_category = "Address"
        crypto_type = "Dash"
        report_data = get_blockchair_info(input_string, BLOCKCHAIR_DASH_BASE_URL, is_address=True)
    elif is_zcash_address(input_string):
        input_category = "Address"
        crypto_type = "Zcash"
        report_data = get_blockchair_info(input_string, BLOCKCHAIR_ZEC_BASE_URL, is_address=True)
    elif is_tron_address(input_string):
        input_category = "Address"
        crypto_type = "Tron"
        report_data = get_tron_info(input_string, is_address=True)
    elif is_solana_address(input_string):
        input_category = "Address"
        crypto_type = "Solana"
        report_data = get_solana_info(input_string, is_address=True)
    elif is_monero_address(input_string):
        input_category = "Address"
        crypto_type = "Monero"
        report_data = get_unsupported_info(input_string, crypto_type, is_address=True)
    elif is_binance_coin_address(input_string):
        input_category = "Address"
        crypto_type = "Binance Coin"
        report_data = get_unsupported_info(input_string, crypto_type, is_address=True)
    elif is_cardano_address(input_string):
        input_category = "Address"
        crypto_type = "Cardano"
        report_data = get_unsupported_info(input_string, crypto_type, is_address=True)
    elif is_polkadot_address(input_string):
        input_category = "Address"
        crypto_type = "Polkadot"
        report_data = get_unsupported_info(input_string, crypto_type, is_address=True)
    elif is_avalanche_address(input_string):
        input_category = "Address"
        crypto_type = "Avalanche"
        report_data = get_unsupported_info(input_string, crypto_type, is_address=True)

    elif is_transaction_hash(input_string):
        if len(input_string) == 64:
            report_data = get_blockcypher_info(input_string, BLOCKCYPHER_BTC_BASE_URL, is_address=False)
            if report_data:
                input_category = "Transaction"
                crypto_type = "Bitcoin"
            else:
                report_data = get_blockcypher_info(input_string, BLOCKCYPHER_LTC_BASE_URL, is_address=False)
                if report_data:
                    input_category = "Transaction"
                    crypto_type = "Litecoin"
                else:
                    report_data = get_blockcypher_info(input_string, BLOCKCYPHER_DOGE_BASE_URL, is_address=False)
                    if report_data:
                        input_category = "Transaction"
                        crypto_type = "Dogecoin"
                    else:
                        report_data = get_blockchair_info(input_string, BLOCKCHAIR_BCH_BASE_URL, is_address=False)
                        if report_data:
                            input_category = "Transaction"
                            crypto_type = "Bitcoin Cash"
                        else:
                            report_data = get_blockchair_info(input_string, BLOCKCHAIR_DASH_BASE_URL, is_address=False)
                            if report_data:
                                input_category = "Transaction"
                                crypto_type = "Dash"
                            else:
                                report_data = get_blockchair_info(input_string, BLOCKCHAIR_ZEC_BASE_URL, is_address=False)
                                if report_data:
                                    input_category = "Transaction"
                                    crypto_type = "Zcash"
                                else:
                                    report_data = get_tron_info(input_string, is_address=False)
                                    if report_data:
                                        input_category = "Transaction"
                                        crypto_type = "Tron"
        elif len(input_string) == 66 and input_string.startswith('0x'):
            report_data = get_ethereum_info(input_string, is_address=False)
            if report_data:
                input_category = "Transaction"
                crypto_type = "Ethereum"
        elif is_solana_address(input_string):
            input_category = "Transaction"
            crypto_type = "Solana"
            report_data = get_solana_info(input_string, is_address=False)
        elif is_ripple_address(input_string):
            input_category = "Transaction"
            crypto_type = "Ripple"
            report_data = get_xrpscan_info(input_string, is_address=False)

        if not report_data and is_transaction_hash(input_string):
            input_category = "Transaction"
            crypto_type = "Unknown (Hash)"
            report_data = get_unsupported_info(input_string, crypto_type, is_address=False)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Input '{input_string}' is not a recognized cryptocurrency address or transaction hash."
        )

    if report_data:
        return {
            "requested_input": input_string,
            "input_category": input_category,
            "crypto_type": crypto_type,
            "report_data": report_data,
            "status": "Success",
            "disclaimer": "This data is aggregated from various public block explorer APIs. Always verify critical information from multiple trusted sources."
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch data for the given input. It might be an invalid or unsupported format, or an API issue."
        )

# Hash Checker Router
hash_checker_router = APIRouter(prefix="/hash", tags=["Hash Reputation Checker"])

@hash_checker_router.get("/reputation", response_model=Dict[str, Any], summary="Check File Hash Reputation")
async def check_hash(
    hash_value: str = Query(..., description="The file hash (MD5, SHA1, or SHA256) to check."),
    api_key: str = Security(get_api_key)
):
    """
    Checks the reputation of a given file hash using AlienVault OTX.
    Returns detailed information about the hash, including its verdict and any associated IOCs.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for hash: {hash_value}")

    hash_type = get_hash_type(hash_value)
    if not hash_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid hash format. Please provide a valid MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hexadecimal hash."
        )

    result = check_hash_reputation_otx(hash_value)

    if result and "error" in result:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result["error"])
    elif result and result.get("status") == "not_found":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=result["message"])
    elif result and result.get("status") == "success":
        return result
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the hash reputation check."
        )

# File Scanner Router
file_scanner_router = APIRouter(prefix="/file", tags=["File Scanner"])

@file_scanner_router.post("/scan", response_model=Dict[str, Any], summary="Upload and Scan File for Reputation")
async def scan_file(
    file: UploadFile = File(..., description="The file to upload and scan."),
    api_key: str = Security(get_api_key)
):
    """
    Accepts a file upload, calculates its MD5, SHA1, and SHA256 hashes,
    and then checks the SHA256 hash's reputation using AlienVault OTX.
    Returns the file's hashes and the threat intelligence analysis result in JSON format.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for file scan: {file.filename}")

    temp_file_path = os.path.join(current_dir, "temp_uploads", file.filename)
    os.makedirs(os.path.dirname(temp_file_path), exist_ok=True) # Ensure temp_uploads directory exists

    try:
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        file_hashes_result = calculate_file_hashes(temp_file_path)

        if "error" in file_hashes_result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error calculating file hashes: {file_hashes_result['error']}"
            )

        sha256_to_check = file_hashes_result.get('sha256')
        if not sha256_to_check:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="SHA256 hash could not be calculated for the uploaded file."
            )

        analysis_result = check_hash_reputation(sha256_to_check)

        if "error" in analysis_result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=analysis_result["error"]
            )
        elif analysis_result.get("status") == "not_found":
            return {
                "uploaded_file_name": file.filename,
                "file_hashes": file_hashes_result,
                "reputation_analysis": {
                    "status": "not_found",
                    "message": analysis_result["message"]
                },
                "disclaimer": "This data is aggregated from various public threat intelligence feeds. Always verify critical information from multiple trusted sources."
            }
        elif analysis_result.get("status") == "success":
            return {
                "uploaded_file_name": file.filename,
                "file_hashes": file_hashes_result,
                "reputation_analysis": analysis_result,
                "disclaimer": "This data is aggregated from various public threat intelligence feeds. Always verify critical information from multiple trusted sources."
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An unexpected error occurred during file analysis."
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during file processing: {e}"
        )
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

# --- INCLUDE ROUTERS IN THE MAIN APP ---
app.include_router(apt_router)
app.include_router(crypto_router)
app.include_router(hash_checker_router)
app.include_router(file_scanner_router)
