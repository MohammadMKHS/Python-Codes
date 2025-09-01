# tracer_api.py
from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any
import secrets # For generating a random API key
import sys
import os

# Temporarily add the current directory to sys.path to allow importing Apt_Checkout
# In a larger project, you would manage imports using proper Python packaging or virtual environments.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import all necessary functions from xenobyte_tracer.py
# Make sure xenobyte_tracer.py is in the same directory or accessible via PYTHONPATH
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
    print(f"ERROR: Could not import functions from xenobyte_tracer.py. Ensure the file is in the correct directory: {e}", file=sys.stderr)
    # Exit or raise an exception to prevent the FastAPI app from starting without dependencies
    sys.exit(1)

app = FastAPI(
    title="XenoByte Crypto Tracer API",
    description="API for tracing cryptocurrency addresses and transaction hashes, providing data in JSON format.",
    version="1.0.0"
)

# --- API Key Configuration ---
# In a real-world scenario, this key should be loaded securely (e.g., from environment variables, a vault)
# and not hardcoded. For this demonstration, a random key is generated on startup.
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
# DO NOT USE THIS METHOD FOR PRODUCTION SYSTEMS
GENERATED_API_KEY = secrets.token_hex(32)

@app.on_event("startup")
async def startup_event():
    """
    Prints the generated API key on startup.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")

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

@app.get("/api/crypto_trace", response_model=Dict[str, Any], summary="Trace Cryptocurrency Address or Transaction")
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

    # --- Address Identification and Data Fetching ---
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

    # --- Transaction Hash Identification and Data Fetching ---
    elif is_transaction_hash(input_string):
        # Determine crypto type for hash by attempting common APIs
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
        elif is_solana_address(input_string): # Solana hashes can be identified by address regex due to Base58
            input_category = "Transaction"
            crypto_type = "Solana"
            report_data = get_solana_info(input_string, is_address=False)
        elif is_ripple_address(input_string): # XRP uses 64-char hex for tx hashes, but its address starts with 'r'
            input_category = "Transaction"
            crypto_type = "Ripple"
            report_data = get_xrpscan_info(input_string, is_address=False)

        # If after all attempts, no specific crypto type is identified for a hash:
        if not report_data and is_transaction_hash(input_string):
            input_category = "Transaction"
            crypto_type = "Unknown (Hash)"
            report_data = get_unsupported_info(input_string, crypto_type, is_address=False)
    else:
        # If input doesn't match any known address or transaction hash formats
        raise HTTPException(
            status_code=400,
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
            status_code=500,
            detail="Failed to fetch data for the given input. It might be an invalid or unsupported format, or an API issue."
        )
