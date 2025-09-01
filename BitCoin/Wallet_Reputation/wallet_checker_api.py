import os
import json
import secrets
import subprocess
import sys # Import sys for sys.executable

from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any

# Path to the XenoByte_Wallet_Checker.py script
# IMPORTANT: Adjust this path if XenoByte_Wallet_Checker.py is not in the same directory as this API script
WALLET_CHECKER_SCRIPT_PATH = "XenoByte_Wallet_Checker.py"

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
GENERATED_API_KEY = secrets.token_hex(32)

# Initialize FastAPI app
app = FastAPI(
    title="XenoByte Bitcoin Wallet Reputation API",
    description="API for checking the reputation of Bitcoin wallet addresses by calling the external wallet checker script.",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    """
    Initializes API on startup, prints the generated API key.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] API startup complete. Wallet reputation checks will be delegated to XenoByte_Wallet_Checker.py.")

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

# --- API Endpoint ---
@app.get("/api/bitcoin/wallet-reputation", response_model=Dict[str, Any], summary="Check Bitcoin Wallet Reputation")
async def check_bitcoin_wallet_reputation_endpoint(
    wallet_address: str = Query(..., description="The Bitcoin wallet address to check for reputation."),
    api_key: str = Security(get_api_key)
):
    """
    Checks the reputation of a specified Bitcoin wallet address by executing
    the `XenoByte_Wallet_Checker.py` script as a subprocess and returning its JSON output.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    if not wallet_address:
        raise HTTPException(status_code=400, detail="Missing 'wallet_address' query parameter.")
    
    print(f"\n[+] API Request received for wallet reputation check: {wallet_address}", file=sys.stderr)
    print(f"[+] Launching external script: {WALLET_CHECKER_SCRIPT_PATH}", file=sys.stderr)

    try:
        # Construct the command to run the external script
        command = [
            sys.executable, # Use the current Python interpreter
            WALLET_CHECKER_SCRIPT_PATH,
            wallet_address,
            "--json-output" # Tell the script to output JSON
        ]

        # Execute the script as a subprocess
        # capture_output=True captures stdout and stderr
        # text=True decodes stdout/stderr as text (UTF-8 by default)
        # check=True raises CalledProcessError if the script returns a non-zero exit code
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd=os.path.dirname(os.path.abspath(__file__)) # Set current working directory to script's location
        )

        # The JSON output is expected in stdout
        wallet_reputation_data = json.loads(process.stdout)
        
        # Any print statements from XenoByte_Wallet_Checker.py (e.g., debug messages) go to stderr
        if process.stderr:
            print(f"[Subprocess STDERR] {process.stderr}", file=sys.stderr)

        return wallet_reputation_data

    except FileNotFoundError:
        print(f"Error: External script '{WALLET_CHECKER_SCRIPT_PATH}' not found. Ensure it's in the same directory or adjust the path.", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"External wallet checker script not found: {WALLET_CHECKER_SCRIPT_PATH}. Ensure it's in the same directory as the API script.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing external script: {e.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Error during wallet reputation analysis in external script: {e.stderr.strip()}"
        )
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from external script: {e}\nSTDOUT: {process.stdout}\nSTDERR: {process.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse JSON output from external script. Raw output might be invalid: {e}"
        )
    except Exception as e:
        print(f"An unexpected error occurred in the API: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    import uvicorn
    # To run this: pip install uvicorn
    # Then run from the directory containing both scripts: uvicorn wallet_checker_api:app --reload
    uvicorn.run(app, host='0.0.0.0', port=8000) # Using port 8000
