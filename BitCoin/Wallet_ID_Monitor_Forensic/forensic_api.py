import os
import json
import time
import secrets
import subprocess # Import subprocess module
import sys # Import sys for sys.executable

from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any

# Path to the Wallet_ID_Monitor_Forensic.py script
# IMPORTANT: Adjust this path if Wallet_ID_Monitor_Forensic.py is not in the same directory as forensic_api.py
FORENSIC_SCRIPT_PATH = "Wallet_ID_Monitor_Forensic.py"

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
GENERATED_API_KEY = secrets.token_hex(32)

# Initialize FastAPI app
app = FastAPI(
    title="XenoByte Bitcoin Wallet Forensic API",
    description="API for performing forensic analysis on Bitcoin wallet addresses by calling the external forensic script.",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    """
    Initializes API on startup, prints the generated API key.
    The actual data loading and analysis is now handled by the subprocess script.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] API startup complete. Forensic analysis will be delegated to Wallet_ID_Monitor_Forensic.py.")

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
@app.get("/api/bitcoin/forensic", response_model=Dict[str, Any], summary="Perform Bitcoin Wallet Forensic Analysis")
async def perform_bitcoin_forensic_analysis_endpoint(
    wallet_address: str = Query(..., description="The Bitcoin wallet address for forensic analysis."),
    max_depth: int = Query(2, description="Maximum tracing depth (e.g., 1, 2, 3, or -1 for full depth). Default is 2."),
    api_key: str = Security(get_api_key)
):
    """
    Performs a forensic analysis on a specified Bitcoin wallet address by executing
    the `Wallet_ID_Monitor_Forensic.py` script as a subprocess and returning its JSON output.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    if not wallet_address:
        raise HTTPException(status_code=400, detail="Missing 'wallet_address' query parameter.")
    
    # max_depth validation is performed by argparse in the external script, but good to have a basic check here.
    if max_depth < -1 or (max_depth == 0 and max_depth != -1):
        raise HTTPException(status_code=400, detail="Invalid 'max_depth'. Must be -1 (full depth) or a positive integer.")

    print(f"\n[+] API Request received for wallet forensic analysis: {wallet_address} (Depth: {max_depth})")
    print(f"[+] Launching external script: {FORENSIC_SCRIPT_PATH}")

    try:
        # Construct the command to run the external script
        # We use sys.executable to ensure we're using the python interpreter that launched this FastAPI app
        command = [
            sys.executable, # Use the current Python interpreter
            FORENSIC_SCRIPT_PATH,
            wallet_address,
            "--depth", str(max_depth),
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
        forensic_report_data = json.loads(process.stdout)
        
        # Any print statements from Wallet_ID_Monitor_Forensic.py (e.g., debug messages) go to stderr
        if process.stderr:
            print(f"[Subprocess STDERR] {process.stderr}")

        return forensic_report_data

    except FileNotFoundError:
        print(f"Error: External script '{FORENSIC_SCRIPT_PATH}' not found. Ensure it's in the same directory or adjust the path.", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"External forensic script not found: {FORENSIC_SCRIPT_PATH}. Ensure it's in the same directory as the API script.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing external script: {e.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Error during forensic analysis in external script: {e.stderr.strip()}"
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
    # Then run from the directory containing both scripts: uvicorn forensic_api:app --reload
    uvicorn.run(app, host='0.0.0.0', port=5001)
