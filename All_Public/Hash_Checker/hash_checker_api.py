# hash_checker_api.py
from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any
import secrets # For generating a random API key
import sys
import os

# Temporarily add the current directory to sys.path to allow importing hash_checker_otx
# In a larger project, you would manage imports using proper Python packaging or virtual environments.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the necessary function from hash_checker_otx.py
# Make sure hash_checker_otx.py is in the same directory or accessible via PYTHONPATH
try:
    from hash_checker_otx import check_hash_reputation_otx, get_hash_type
except ImportError as e:
    print(f"ERROR: Could not import functions from hash_checker_otx.py. Ensure the file is in the correct directory: {e}", file=sys.stderr)
    # Exit or raise an exception to prevent the FastAPI app from starting without dependencies
    sys.exit(1)

app = FastAPI(
    title="XenoByte Hash Reputation Checker API",
    description="API for checking the reputation of file hashes (MD5, SHA1, SHA256) using AlienVault OTX.",
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

@app.get("/api/hash_reputation", response_model=Dict[str, Any], summary="Check File Hash Reputation")
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

    # Validate hash format before proceeding
    hash_type = get_hash_type(hash_value)
    if not hash_type:
        raise HTTPException(
            status_code=400,
            detail="Invalid hash format. Please provide a valid MD5 (32 chars), SHA1 (40 chars), or SHA256 (64 chars) hexadecimal hash."
        )

    result = check_hash_reputation_otx(hash_value)

    if result and "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    elif result and result.get("status") == "not_found":
        raise HTTPException(status_code=404, detail=result["message"])
    elif result and result.get("status") == "success":
        return result
    else:
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while processing the hash reputation check."
        )

