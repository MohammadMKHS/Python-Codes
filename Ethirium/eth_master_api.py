import os
import json
import secrets
import subprocess
import sys
from typing import Dict, Any

from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader

# --- IMPORTANT: Configure Paths to your scripts ---
# These paths are relative to where eth_master_api.py is located.
# Adjust them if your directory structure changes.
TRANSACTION_HASH_SCRIPT_PATH = "./Transaction Hash/Transaction_Hash.py"
WALLET_FORENSIC_SCRIPT_PATH = "./Wallet_ID_Monitor_Forensic/Wallet_ID_Monitor_Forensic.py"
WALLET_REPUTATION_SCRIPT_PATH = "./Wallet_Reputation/XenoByte_Wallet_Checker.py"

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Generate a random API key for demonstration purposes
GENERATED_API_KEY = secrets.token_hex(32)

# Initialize FastAPI app
app = FastAPI(
    title="XenoByte Ethereum Intelligence Master API",
    description="A consolidated API for various Ethereum intelligence tasks: transaction analysis, wallet forensic tracing, and wallet reputation checking.",
    version="1.0.0"
)

@app.on_event("startup")
async def startup_event():
    """
    Initializes API on startup, prints the generated API key.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}", file=sys.stderr)
    print("[INFO] Ethereum Master API startup complete. Endpoints will delegate to individual scripts.", file=sys.stderr)

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

async def run_script_subprocess(script_path: str, args: list) -> Dict[str, Any]:
    """
    Helper function to run an external Python script as a subprocess
    and capture its JSON output and stderr.
    """
    # Ensure the script path is absolute for reliable execution
    script_abs_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_path)

    if not os.path.exists(script_abs_path):
        raise FileNotFoundError(f"Script not found at: {script_abs_path}")

    command = [
        sys.executable, # Use the current Python interpreter
        script_abs_path,
        *args,          # Unpack the list of arguments
        "--json-output" # Assuming your scripts support a --json-output flag for JSON output
    ]

    print(f"[+] Running subprocess command: {' '.join(command)}", file=sys.stderr)

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True, # Raise CalledProcessError for non-zero exit codes
            cwd=os.path.dirname(script_abs_path) # Set cwd to the script's directory for relative file access (e.g., wallets_ransomware.txt)
        )

        # Print stderr from the subprocess for debugging
        if process.stderr:
            print(f"[Subprocess STDERR for {script_path}] {process.stderr}", file=sys.stderr)

        # The JSON output is expected in stdout
        return json.loads(process.stdout)

    except FileNotFoundError as e:
        print(f"Error: Script not found - {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"External script not found: {script_path}. Ensure its path is correct.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing external script '{script_path}': {e.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Error during external script execution for {script_path}: {e.stderr.strip()}"
        )
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from external script '{script_path}': {e}\nSTDOUT: {process.stdout}\nSTDERR: {process.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse JSON output from external script {script_path}. Raw output might be invalid: {e}"
        )
    except Exception as e:
        print(f"An unexpected error occurred when running {script_path}: {e}", file=sys.stderr)
        raise HTTPException(status_code=500, detail=f"An unexpected error occurred: {e}")


# --- API Endpoints ---

@app.get("/api/ethereum/transaction-analysis", response_model=Dict[str, Any], summary="Perform Ethereum Transaction Hash Analysis")
async def analyze_ethereum_transaction_hash_endpoint(
    tx_hash: str = Query(..., description="The Ethereum transaction hash for analysis (e.g., '0x123...abc')."),
    api_key: str = Security(get_api_key)
):
    """
    Performs an analysis on a specified Ethereum transaction hash.
    Delegates to `Transaction_Hash.py`.
    """
    if not tx_hash:
        raise HTTPException(status_code=400, detail="Missing 'tx_hash' query parameter.")
    
    print(f"\n[+] API Request received for Ethereum transaction analysis: {tx_hash}", file=sys.stderr)
    return await run_script_subprocess(TRANSACTION_HASH_SCRIPT_PATH, [tx_hash])


@app.get("/api/ethereum/wallet-forensic", response_model=Dict[str, Any], summary="Perform Ethereum Wallet Forensic Analysis")
async def perform_ethereum_forensic_analysis_endpoint(
    wallet_address: str = Query(..., description="The Ethereum wallet address for forensic analysis (e.g., '0xabc...123')."),
    max_depth: int = Query(2, description="Maximum tracing depth (e.g., 1, 2, 3, or -1 for full depth). Default is 2."),
    api_key: str = Security(get_api_key)
):
    """
    Performs a forensic analysis on a specified Ethereum wallet address.
    Delegates to `Wallet_ID_Monitor_Forensic.py`.
    """
    if not wallet_address:
        raise HTTPException(status_code=400, detail="Missing 'wallet_address' query parameter.")
    
    if max_depth < -1 or (max_depth == 0 and max_depth != -1):
        raise HTTPException(status_code=400, detail="Invalid 'max_depth'. Must be -1 (full depth) or a positive integer.")

    print(f"\n[+] API Request received for Ethereum wallet forensic analysis: {wallet_address} (Depth: {max_depth})", file=sys.stderr)
    return await run_script_subprocess(WALLET_FORENSIC_SCRIPT_PATH, [wallet_address, "--depth", str(max_depth)])


@app.get("/api/ethereum/wallet-reputation", response_model=Dict[str, Any], summary="Check Ethereum Wallet Reputation")
async def check_ethereum_wallet_reputation_endpoint(
    wallet_address: str = Query(..., description="The Ethereum wallet address to check for reputation."),
    api_key: str = Security(get_api_key)
):
    """
    Checks the reputation of a specified Ethereum wallet address.
    Delegates to `XenoByte_Wallet_Checker.py`.
    """
    if not wallet_address:
        raise HTTPException(status_code=400, detail="Missing 'wallet_address' query parameter.")
    
    print(f"\n[+] API Request received for Ethereum wallet reputation check: {wallet_address}", file=sys.stderr)
    return await run_script_subprocess(WALLET_REPUTATION_SCRIPT_PATH, [wallet_address])


if __name__ == '__main__':
    import uvicorn
    # To run this: pip install uvicorn
    # Then run from the main Ethirium directory: uvicorn eth_master_api:app --reload
    uvicorn.run(app, host='0.0.0.0', port=8000)
