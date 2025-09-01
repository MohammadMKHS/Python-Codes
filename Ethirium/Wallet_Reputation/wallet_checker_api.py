from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any, Optional
import secrets
import subprocess
import json
import sys # For sys.executable and sys.stderr
import os # For os.path.dirname and os.path.abspath

# Path to the XenoByte_Wallet_Checker.py script
# IMPORTANT: Ensure XenoByte_Wallet_Checker.py is in the same directory as this API script
WALLET_CHECKER_SCRIPT_PATH = "XenoByte_Wallet_Checker.py"

app = FastAPI(
    title="XenoByte Ethereum Wallet Analysis API",
    description="API for retrieving detailed analysis of Ethereum wallet addresses, including reputation, behavioral patterns, and Chainabuse reports.",
    version="1.0.0"
)

# --- API Key Configuration (Same as apt_api.py) ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
GENERATED_API_KEY = secrets.token_hex(32)

@app.on_event("startup")
async def startup_event():
    """
    Initializes API on startup, prints the generated API key.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] API startup complete. Wallet analysis will be delegated to XenoByte_Wallet_Checker.py.")

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

# --- API Endpoint (Similar to apt_api.py) ---
@app.get("/api/ethereum/wallet-analysis", response_model=Dict[str, Any], summary="Get Ethereum Wallet Analysis")
async def get_ethereum_wallet_analysis(
    address: str = Query(..., description="The Ethereum wallet address to analyze (e.g., 0x...)."),
    api_key: str = Security(get_api_key)
):
    """
    Retrieves comprehensive analysis for a specified Ethereum wallet address.
    This endpoint executes the `XenoByte_Wallet_Checker.py` script as a subprocess
    and returns its JSON output.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    if not address:
        raise HTTPException(status_code=400, detail="Missing 'address' query parameter.")
    
    print(f"\n[+] API Request received for Ethereum wallet analysis: {address}", file=sys.stderr)
    print(f"[+] Launching XenoByte_Wallet_Checker.py as subprocess for {address}...", file=sys.stderr)

    try:
        # Construct the command to run the external script with --json-output
        command = [
            sys.executable, # Use the current Python interpreter
            WALLET_CHECKER_SCRIPT_PATH,
            address,
            "--json-output" # Tell the script to output JSON to stdout
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
        wallet_analysis_data = json.loads(process.stdout)
        
        # Any print statements from XenoByte_Wallet_Checker.py (e.g., debug messages) will go to stderr
        if process.stderr:
            print(f"[Subprocess STDERR for {address}]\n{process.stderr}", file=sys.stderr)

        return wallet_analysis_data

    except FileNotFoundError:
        print(f"Error: External script '{WALLET_CHECKER_SCRIPT_PATH}' not found. Ensure it's in the same directory or adjust the path.", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"External wallet checker script not found: {WALLET_CHECKER_SCRIPT_PATH}. Ensure it's in the same directory as the API script.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing external script for {address}:\n{e.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Error during wallet analysis in external script for {address}: {e.stderr.strip()}"
        )
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from external script for {address}: {e}\nSTDOUT: {process.stdout}\nSTDERR: {process.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse JSON output from external script for {address}. Raw output might be invalid: {e}"
        )
    except Exception as e:
        print(f"An unexpected error occurred in the API for {address}: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    import uvicorn
    # To run this: uvicorn wallet_checker_api:app --reload --port 8002
    # Ensure you replace 'wallet_checker_api' with the actual filename if different.
    uvicorn.run(app, host="0.0.0.0", port=8002) # Using port 8002 to avoid conflict with default 8000
