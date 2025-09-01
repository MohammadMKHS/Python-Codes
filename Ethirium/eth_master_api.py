# eth_master_api.py (Refactored to expose APIRouter)
import os
import json
import subprocess
import sys
from typing import Dict, Any

from fastapi import APIRouter, Query, HTTPException, status

# --- IMPORTANT: Configure Paths to your scripts ---
# These paths are relative to where eth_master_api.py is located.
# They will be correctly resolved by the run_script_subprocess helper.
TRANSACTION_HASH_SCRIPT_PATH = "./Transaction Hash/Transaction_Hash.py"
WALLET_FORENSIC_SCRIPT_PATH = "./Wallet_ID_Monitor_Forensic/Wallet_ID_Monitor_Forensic.py"
WALLET_REPUTATION_SCRIPT_PATH = "./Wallet_Reputation/XenoByte_Wallet_Checker.py"

# --- Define the APIRouter for this module ---
# This router will be included by the main Xenobyte API
ethereum_router = APIRouter(tags=["Ethereum Intelligence"])

# Helper function to run an external Python script as a subprocess
# This function remains within this module, as its paths are relative to this file.
async def run_script_subprocess(script_path: str, args: list) -> Dict[str, Any]:
    """
    Helper function to run an external Python script as a subprocess
    and capture its JSON output and stderr.
    """
    # Ensure the script path is absolute for reliable execution
    # This current_script_dir is the directory of this file (eth_master_api.py)
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    script_abs_path = os.path.join(current_script_dir, script_path)

    if not os.path.exists(script_abs_path):
        # Print error to stderr for debugging purposes when running through master API
        print(f"Error: Script not found at: {script_abs_path}", file=sys.stderr)
        raise FileNotFoundError(f"Script not found at: {script_abs_path}")

    command = [
        sys.executable, # Use the current Python interpreter
        script_abs_path,
        *args,          # Unpack the list of arguments
        "--json" # Use the correct argument that the script supports
    ]

    print(f"[+] Running subprocess command: {' '.join(command)} (from ethereum_router)", file=sys.stderr)

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True, # Raise CalledProcessError for non-zero exit codes
            # Set cwd to the script's directory for relative file access (e.g., wallets_ransomware.txt)
            cwd=os.path.dirname(script_abs_path)
        )

        # Print stderr from the subprocess for debugging
        if process.stderr:
            print(f"[Subprocess STDERR for {script_path}] {process.stderr}", file=sys.stderr)

        # The JSON output is expected in stdout
        return json.loads(process.stdout)

    except FileNotFoundError as e:
        print(f"Error: Script not found - {e}", file=sys.stderr)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"External script not found: {script_path}. Ensure its path is correct.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing external script '{script_path}': {e.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error during external script execution for {script_path}: {e.stderr.strip()}"
        )
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON from external script '{script_path}': {e}\nSTDOUT: {process.stdout}\nSTDERR: {process.stderr}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to parse JSON output from external script {script_path}. Raw output might be invalid: {e}"
        )
    except Exception as e:
        print(f"An unexpected error occurred when running {script_path}: {e}", file=sys.stderr)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred: {e}")


# --- API Endpoints (Modified to use ethereum_router and remove Security dependency) ---
# The Security dependency will be handled by the top-level API that includes this router.

@ethereum_router.get("/transaction-analysis", response_model=Dict[str, Any], summary="Perform Ethereum Transaction Hash Analysis")
async def analyze_ethereum_transaction_hash_endpoint(
    tx_hash: str = Query(..., description="The Ethereum transaction hash for analysis (e.g., '0x123...abc').")
):
    """
    Performs an analysis on a specified Ethereum transaction hash.
    Delegates to `Transaction_Hash.py`.
    """
    if not tx_hash:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'tx_hash' query parameter.")
    
    print(f"\n[+] API Request received for Ethereum transaction analysis: {tx_hash} (via ethereum_router)", file=sys.stderr)
    return await run_script_subprocess(TRANSACTION_HASH_SCRIPT_PATH, ["--tx", tx_hash])


@ethereum_router.get("/wallet-forensic", response_model=Dict[str, Any], summary="Perform Ethereum Wallet Forensic Analysis")
async def perform_ethereum_forensic_analysis_endpoint(
    wallet_address: str = Query(..., description="The Ethereum wallet address for forensic analysis (e.g., '0xabc...123')."),
    max_depth: int = Query(2, description="Maximum tracing depth (e.g., 1, 2, 3, or -1 for full depth). Default is 2.")
):
    """
    Performs a forensic analysis on a specified Ethereum wallet address.
    Delegates to `Wallet_ID_Monitor_Forensic.py`.
    """
    if not wallet_address:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'wallet_address' query parameter.")
    
    if max_depth < -1 or (max_depth == 0 and max_depth != -1):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid 'max_depth'. Must be -1 (full depth) or a positive integer.")

    print(f"\n[+] API Request received for Ethereum wallet forensic analysis: {wallet_address} (Depth: {max_depth}) (via ethereum_router)", file=sys.stderr)
    return await run_script_subprocess(WALLET_FORENSIC_SCRIPT_PATH, [wallet_address, "--depth", str(max_depth)])


@ethereum_router.get("/wallet-reputation", response_model=Dict[str, Any], summary="Check Ethereum Wallet Reputation")
async def check_ethereum_wallet_reputation_endpoint(
    wallet_address: str = Query(..., description="The Ethereum wallet address to check for reputation.")
):
    """
    Checks the reputation of a specified Ethereum wallet address.
    Delegates to `XenoByte_Wallet_Checker.py`.
    """
    if not wallet_address:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing 'wallet_address' query parameter.")
    
    print(f"\n[+] API Request received for Ethereum wallet reputation check: {wallet_address} (via ethereum_router)", file=sys.stderr)
    return await run_script_subprocess(WALLET_REPUTATION_SCRIPT_PATH, [wallet_address])

