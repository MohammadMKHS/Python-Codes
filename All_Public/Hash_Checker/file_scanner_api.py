# file_scanner_api.py
from fastapi import FastAPI, UploadFile, File, HTTPException, Security, Depends, status
from fastapi.security.api_key import APIKeyHeader
from typing import Dict, Any
import secrets # For generating a random API key
import sys
import os
import shutil # For saving uploaded files temporarily
import hashlib # For calculating hashes if not relying solely on the imported function

# Temporarily add the current directory to sys.path to allow importing file_hash_scanner
# In a larger project, you would manage imports using proper Python packaging or virtual environments.
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import the necessary functions from file_hash_scanner.py
try:
    from file_hash_scanner import calculate_file_hashes, check_hash_reputation, get_hash_type
except ImportError as e:
    print(f"ERROR: Could not import functions from file_hash_scanner.py. Ensure the file is in the correct directory: {e}", file=sys.stderr)
    # Exit or raise an exception to prevent the FastAPI app from starting without dependencies
    sys.exit(1)

app = FastAPI(
    title="XenoByte File Scanner API",
    description="API for uploading a file, calculating its hashes, and checking its reputation via AlienVault OTX.",
    version="1.0.0"
)

# --- API Key Configuration ---
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

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
            status_code=status.HTTP_403_FORBIDDEN, detail="Could not validate credentials - Invalid API Key"
        )

@app.post("/api/file_scan", response_model=Dict[str, Any], summary="Upload and Scan File for Reputation")
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

    # Create a temporary file to save the uploaded content
    temp_file_path = f"/tmp/{file.filename}" # Using /tmp for temporary storage on Linux/macOS
    # On Windows, consider: temp_file_path = f"{os.getenv('TEMP')}\\{file.filename}"
    
    try:
        # Save the uploaded file locally
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Calculate hashes using the function from file_hash_scanner.py
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

        # Check hash reputation using the function from file_hash_scanner.py
        analysis_result = check_hash_reputation(sha256_to_check)

        if "error" in analysis_result:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=analysis_result["error"]
            )
        elif analysis_result.get("status") == "not_found":
            # Although not found, we still return the file hashes and a message
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
        # Clean up the temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
