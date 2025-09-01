# apt_api.py
from fastapi import FastAPI, Query, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from Apt_Checkout import (
    get_apt_group_info_from_mitre,
    query_otx_for_apt,
    get_iocs_from_github_repo,
    load_random_wallet_addresses,
    load_mitre_attack_data,
    is_valid_ip, # Added for potential IOC validation
    is_likely_filename # Added for potential IOC validation
)
from typing import List, Dict, Any
import os
import secrets # For generating a random API key

app = FastAPI(
    title="XenoByte Threat Intelligence API",
    description="API for retrieving APT group threat intelligence, including MITRE ATT&CK information, IOCs, and ransomware wallet addresses.",
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
    Initializes MITRE ATT&CK data and prints the generated API key on startup.
    """
    print(f"[*] Generated API Key for this session: {GENERATED_API_KEY}")
    print("[INFO] Initializing MITRE ATT&CK data...")
    if not load_mitre_attack_data():
        print("[ERROR] Failed to load MITRE ATT&CK data. API responses for MITRE might be incomplete.")

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

@app.get("/api/apt", response_model=Dict[str, Any], summary="Get APT Group Threat Intelligence")
async def get_apt_data(
    group: str = Query(..., description="The name of the APT group (e.g., APT28, Fancy Bear, Lazarus Group)."),
    api_key: str = Security(get_api_key)
):
    """
    Retrieves comprehensive threat intelligence for a specified APT group.

    This endpoint gathers information from:
    - MITRE ATT&CK: Details about the intrusion set, including aliases, description, associated software, and techniques.
    - AlienVault OTX: Publicly available Indicators of Compromise (IOCs) related to the group.
    - GitHub (blackorbird/APT_REPORT): Additional IOCs from a public repository.
    - Ransomware Wallet Addresses: A demonstration list of random ransomware wallet addresses.

    **Authentication:** Requires an API key passed in the `X-API-Key` header.
    """
    print(f"\n[+] API Request received for APT group: {group}")

    # 1. Get MITRE info
    mitre_info = get_apt_group_info_from_mitre(group)
    if not mitre_info:
        print(f"    [-] No detailed MITRE group profile found for '{group}'.")

    # 2. Get OTX data (includes IOCs from OTX)
    otx_result = query_otx_for_apt(group)
    otx_error = None
    if isinstance(otx_result, dict) and otx_result.get("error"):
        otx_error = otx_result["error"]
        print(f"    [ERROR] OTX Query failed: {otx_error}")
        otx_iocs = []
    else:
        otx_iocs = otx_result.get('all_extracted_iocs', [])
        print(f"    [+] Found {len(otx_iocs)} IOCs from OTX.")

    # 3. Get GitHub IOCs (from blackorbird/APT_REPORT)
    github_iocs = get_iocs_from_github_repo("blackorbird", "APT_REPORT", group)
    print(f"    [+] Found {len(github_iocs)} IOCs from GitHub.")

    # 4. Load Ransomware Wallet Addresses
    ransomware_wallets = load_random_wallet_addresses(count=15)
    if not ransomware_wallets:
        print(f"    [*] No ransomware wallet addresses loaded from '{RANSOMWARE_WALLETS_FILE}'.")

    # Combine all extracted IOCs from OTX and GitHub
    master_ioc_list = []
    master_ioc_list.extend(otx_iocs)
    master_ioc_list.extend(github_iocs)

    # Categorize and de-duplicate IOCs
    cve_list = set()
    ip_list = set()
    domain_list = set()
    hash_list = set()
    other_list = set()

    for ioc in master_ioc_list:
        ioc_type = ioc.get('type')
        ioc_value = ioc.get('value')
        if not ioc_value:
            continue

        if ioc_type == 'CVE':
            cve_list.add(ioc_value)
        elif ioc_type == 'IPv4':
            ip_list.add(ioc_value)
        elif ioc_type == 'Domain' or ioc_type == 'Hostname':
            domain_value = ioc_value.strip('.').lower()
            if not is_likely_filename(domain_value) and not is_valid_ip(domain_value):
                domain_list.add(domain_value)
        elif ioc_type.startswith('FileHash'):
            hash_list.add(ioc_value)
        else:
            other_list.add(ioc_value)

    # Convert sets back to sorted lists
    categorized_iocs = {
        "cves": sorted(list(cve_list)),
        "ips": sorted(list(ip_list)),
        "domains": sorted(list(domain_list)),
        "hashes": sorted(list(hash_list)),
        "others": sorted(list(other_list))
    }

    # Return a clean JSON response
    return {
        "requested_group": group,
        "mitre_attack_info": mitre_info if mitre_info else "No detailed MITRE ATT&CK information found for this group.",
        "indicators_of_compromise": categorized_iocs,
        "ransomware_wallet_addresses": ransomware_wallets,
        "otx_query_status": "Success" if not otx_error else f"Failed: {otx_error}",
        "disclaimer": "This data is aggregated from various open-source intelligence feeds and MITRE ATT&CK. Always verify critical information from multiple trusted sources."
    }