from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any
import secrets
import os
from datetime import datetime, timezone, timedelta

# Corrected imports to match the function names in Transaction_Hash.py
from Transaction_Hash import (
    get_transaction_details_multi_source,
    generate_html_report,
    load_local_ransomware_addresses,
    fetch_ransomwhere_data,
    get_simulated_reputation_flags,
    get_simulated_chainabuse_reports
)

app = FastAPI(
    title="XenoByte Ethereum Transaction Analysis API",
    description="API for retrieving detailed analysis of Ethereum transactions, including sender/receiver wallet reputation and Chainabuse reports.",
    version="1.0.0"
)

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

GENERATED_API_KEY = secrets.token_hex(32)

@app.on_event("startup")
async def startup_event():
    """
    Initializes ransomware data sources and prints the generated API key on startup.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] Initializing Ransomware data sources (local and API)...")
    load_local_ransomware_addresses()
    fetch_ransomwhere_data()
    print("[INFO] Ransomware data loaded.")

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

@app.get("/api/transaction", response_model=Dict[str, Any], summary="Get Ethereum Transaction Analysis")
async def get_transaction_analysis(
    tx_hash: str = Query(..., description="The Ethereum transaction hash to analyze (e.g., 0x...)."),
    generate_html_report: bool = Query(False, description="Set to true to also generate and return the HTML report content."),
    api_key: str = Security(get_api_key)
):
    """
    Retrieves comprehensive analysis for a specified Ethereum transaction hash.

    This endpoint fetches transaction details from Etherscan, and enriches wallet addresses
    with simulated reputation flags and Chainabuse reports.

    **Parameters:**
    - `tx_hash`: The Ethereum transaction hash (e.g., `0x7a2278917812c3b8a1c8b3d6d0a7a0e7f7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7`).
    - `generate_html_report`: If `true`, the full HTML report content will also be returned in the response.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for transaction hash: {tx_hash}")

    transaction_details = get_transaction_details_multi_source(tx_hash)

    if not transaction_details:
        raise HTTPException(
            status_code=404,
            detail=f"Failed to retrieve details for transaction {tx_hash}. Please check the hash and try again."
        )

    # Convert values from Wei to ETH for clearer reporting in the API response
    tx_time_utc = None
    if transaction_details.get('time'):
        try:
            tx_time_utc = datetime.fromtimestamp(transaction_details['time'], timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError):
            pass

    # Process sender wallets
    processed_senders = []
    for sender_wallet in transaction_details.get('inputs', []):
        sender_address = sender_wallet.get('prev_out', {}).get('addr')
        amount_wei = sender_wallet.get('prev_out', {}).get('value', 0)
        
        reputation_flags = get_simulated_reputation_flags(sender_address)
        chainabuse_info = get_simulated_chainabuse_reports(sender_address) # Corrected function call

        processed_senders.append({
            "address": sender_address,
            "amount_sent_eth": amount_wei / 1e18,
            "inferred_type": "Personal Wallet", # Simplified
            "reputation_flags": reputation_flags,
            "chainabuse_reports_count": chainabuse_info.get('total_reports_count', 0),
            "detailed_chainabuse_reports": chainabuse_info.get('reports', [])
        })

    # Process receiver wallets
    processed_receivers = []
    for receiver_wallet in transaction_details.get('out', []):
        receiver_address = receiver_wallet.get('addr')
        amount_wei = receiver_wallet.get('value', 0)

        reputation_flags = get_simulated_reputation_flags(receiver_address)
        chainabuse_info = get_simulated_chainabuse_reports(receiver_address) # Corrected function call

        processed_receivers.append({
            "address": receiver_address,
            "amount_received_eth": amount_wei / 1e18,
            "inferred_type": "Personal Wallet", # Simplified
            "reputation_flags": reputation_flags,
            "chainabuse_reports_count": chainabuse_info.get('total_reports_count', 0),
            "detailed_chainabuse_reports": chainabuse_info.get('reports', [])
        })

    response_data = {
        "requested_transaction_hash": tx_hash,
        "transaction_summary": {
            "time_utc": tx_time_utc,
            "block_height": transaction_details.get('block_height', 'N/A'),
            "transaction_fee_eth": transaction_details.get('fee', 0) / 1e18 if transaction_details.get('fee') is not None else 'N/A',
            "total_input_value_eth": sum([s['amount_sent_eth'] for s in processed_senders]),
            "total_output_value_eth": sum([r['amount_received_eth'] for r in processed_receivers])
        },
        "sender_wallets": processed_senders,
        "receiver_wallets": processed_receivers,
        "disclaimer": "This data is aggregated from various open-source intelligence feeds and blockchain explorers. Always verify critical information from multiple trusted sources."
    }

    if generate_html_report:
        try:
            # Corrected function call and arguments
            html_report_content = generate_html_report(transaction_details, tx_hash)
            response_data["html_report"] = html_report_content
        except Exception as e:
            print(f"[ERROR] Failed to generate HTML report: {e}")
            response_data["html_report_generation_status"] = f"Failed: {e}"

    return response_data

if __name__ == "__main__":
    import uvicorn
    # To run: uvicorn transaction_hash_api:app --reload --port 8001
    # Ensure you replace 'transaction_hash_api' with the actual filename if different.
    uvicorn.run(app, host="0.0.0.0", port=8001)