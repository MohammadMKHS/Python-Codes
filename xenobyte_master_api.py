# xenobyte_master_api.py
import os
import secrets
import sys
from typing import Dict, Any

from fastapi import FastAPI, Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

# --- PATH ADJUSTMENTS ---
# Get the directory where this script (xenobyte_master_api.py) is located
current_dir = os.path.dirname(os.path.abspath(__file__))

# Add the directories containing your master API routers to sys.path
# This allows importing the APIRouter instances from each module.
# Assumes the structure:
# XenoByte/Python Codes/
# ├── All_Public/
# │   └── all_public_api.py
# ├── BitCoin/
# │   └── bitcoin_master_api.py
# ├── Ethirium/
# │   └── eth_master_api.py
# └── xenobyte_master_api.py
sys.path.insert(0, os.path.join(current_dir, "All_Public"))
sys.path.insert(0, os.path.join(current_dir, "BitCoin"))
sys.path.insert(0, os.path.join(current_dir, "Ethirium"))

# --- IMPORTS FROM YOUR SUB-MASTER API ROUTERS ---
# Import the APIRouter instances from each refactored master API file.
try:
    from all_public_api import public_router
    # Also need the load_mitre_attack_data for startup event from Apt_Checkout.py.
    # Apt_Checkout should already be accessible via the path added by all_public_api.py
    # if it needs to be directly called here.
    # Alternatively, ensure load_mitre_attack_data is also refactored into its own module
    # and imported correctly. For simplicity, we assume all_public_api's path setup
    # makes Apt_Checkout importable relative to current_dir.
    # If Apt_Checkout.py is *not* in All_Public/APT_Checkout directly,
    # you might need to adjust the import for load_mitre_attack_data specifically.
    from Apt_Checkout import load_mitre_attack_data # Assuming Apt_Checkout is discoverable
except ImportError as e:
    print(f"ERROR: Could not import public_router or Apt_Checkout functions: {e}", file=sys.stderr)
    sys.exit(1)

try:
    from bitcoin_master_api import bitcoin_router
except ImportError as e:
    print(f"ERROR: Could not import bitcoin_router: {e}", file=sys.stderr)
    sys.exit(1)

try:
    from eth_master_api import ethereum_router
except ImportError as e:
    print(f"ERROR: Could not import ethereum_router: {e}", file=sys.stderr)
    sys.exit(1)


# --- MAIN FASTAPI APP INSTANCE ---
app = FastAPI(
    title="XenoByte Ultimate Threat Intelligence Platform API",
    description="A comprehensive API consolidating all XenoByte threat intelligence capabilities.",
    version="1.0.0",
)

# --- GLOBAL API KEY CONFIGURATION ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)
GENERATED_API_KEY = secrets.token_hex(32)

@app.on_event("startup")
async def startup_event():
    """
    Initializes MITRE ATT&CK data (for APT module) and prints the generated API key on startup.
    This runs once when the API server starts.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}", file=sys.stderr)
    print("[INFO] Initializing MITRE ATT&CK data (for APT module)...", file=sys.stderr)
    # Call the MITRE data load function from Apt_Checkout
    if not load_mitre_attack_data():
        print("[ERROR] Failed to load MITRE ATT&CK data. APT API responses might be incomplete.", file=sys.stderr)
    print("[INFO] XenoByte Master API startup complete.", file=sys.stderr)


async def get_api_key(api_key_header: str = Security(api_key_header)):
    """
    Dependency to validate the API key for all endpoints across the entire platform.
    """
    if api_key_header == GENERATED_API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials - Invalid API Key"
        )

# --- INCLUDE ALL REFACTORED ROUTERS IN THE MAIN APP ---
# Each router will use the global get_api_key dependency by default.
# The 'prefix' argument here defines the base path for all endpoints within that router.

# Public Intelligence (APT, Crypto Tracer, Hash Checker, File Scanner)
app.include_router(public_router, prefix="/public", dependencies=[Security(get_api_key)])

# Bitcoin Intelligence
app.include_router(bitcoin_router, prefix="/bitcoin", dependencies=[Security(get_api_key)])

# Ethereum Intelligence
app.include_router(ethereum_router, prefix="/ethereum", dependencies=[Security(get_api_key)])


# --- Root Endpoint (Optional, for simple health check or info) ---
@app.get("/", summary="XenoByte API Status", dependencies=[Security(get_api_key)])
async def read_root():
    return {"message": "Welcome to XenoByte Ultimate Threat Intelligence Platform API!"}

# --- Main execution block for direct Uvicorn run ---
if __name__ == '__main__':
    import uvicorn
    # To run this: pip install uvicorn
    # Then run from 'C:\Users\USER\Pictures\XenoByte\Python Codes\':
    # uvicorn xenobyte_master_api:app --reload
    uvicorn.run(app, host='0.0.0.0', port=8000)

