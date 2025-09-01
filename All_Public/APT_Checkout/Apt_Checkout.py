import requests
import json
import os
import sys
import webbrowser
from datetime import datetime
import time
import re
import random # ADDED: Import random module

# --- API Key Configuration (DIRECTLY EMBEDDED - HIGHLY INSECURE FOR PRODUCTION) ---
# DO NOT SHARE THIS SCRIPT WITH THESE KEYS EMBEDDED!
ALIENVAULT_OTX_API_KEY = "079ae73a74f0ff57a408c5137f3bb4b55b17b99051a568daa21af1f33b893c75"

# --- MITRE ATT&CK Configuration ---
MITRE_ATTACK_ENTERPRISE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_ATTACK_LOCAL_FILE = "enterprise-attack.json"
MITRE_ATTACK_CACHE = None # Will store parsed MITRE data

# Regex for basic IP validation
IP_REGEX = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

def is_valid_ip(ip_str):
    """Simple check if a string looks like an IPv4 address."""
    return re.match(IP_REGEX, ip_str)

# Regex for common file extensions. We will use this to filter domain candidates.
COMMON_FILE_EXTENSIONS = {
    'php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'css', 'js', 'json', 'xml', 'txt',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'zip', 'rar', '7z', 'tar', 'gz',
    'exe', 'dll', 'sys', 'bin', 'sh', 'bat', 'cmd', 'ps1', 'vbs', 'jar', 'py',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'svg', 'webp',
    'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv',
    'bak', 'tmp', 'log', 'ini', 'cfg', 'conf', 'dat', 'db', 'sql', 'sqlite',
    'gzb', 'phpzeb' # Added from user's examples
}

def is_likely_filename(s):
    """
    Checks if a string is likely a filename based on common extensions.
    This is a heuristic and might have false positives/negatives.
    """
    if '.' in s:
        parts = s.split('.')
        if len(parts) > 1:
            extension = parts[-1].lower()
            # Ensure there's at least one non-empty part before the extension
            if parts[0] and extension in COMMON_FILE_EXTENSIONS:
                return True
    return False

# Define the ransomware wallet file name
RANSOMWARE_WALLETS_FILE = "wallets_ransomware.txt"

def load_random_wallet_addresses(count=15):
    """
    Loads a specified number of random ransomware wallet addresses from a file.
    Args:
        count (int): The number of random addresses to return.
    Returns:
        list: A list of random wallet addresses.
    """
    wallet_addresses = []
    if not os.path.exists(RANSOMWARE_WALLETS_FILE):
        print(f"[*] Ransomware wallet addresses file '{RANSOMWARE_WALLETS_FILE}' not found. Skipping this section.")
        return []

    try:
        with open(RANSOMWARE_WALLETS_FILE, 'r', encoding='utf-8') as f:
            # Read all non-empty, non-comment lines
            all_addresses = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            
            # Remove duplicates by converting to set and back to list
            all_addresses = list(set(all_addresses))

            if len(all_addresses) > count:
                wallet_addresses = random.sample(all_addresses, count)
            else:
                wallet_addresses = all_addresses
        print(f"[+] Loaded {len(wallet_addresses)} random ransomware wallet addresses.")
    except Exception as e:
        print(f"ERROR: Failed to load ransomware wallet addresses from '{RANSOMWARE_WALLETS_FILE}': {e}", file=sys.stderr)
    return wallet_addresses


def load_mitre_attack_data():
    """
    Loads MITRE ATT&CK Enterprise data from a local file or downloads it.
    Caches the loaded data.
    """
    global MITRE_ATTACK_CACHE
    if MITRE_ATTACK_CACHE:
        return MITRE_ATTACK_CACHE

    if not os.path.exists(MITRE_ATTACK_LOCAL_FILE):
        print(f"Downloading MITRE ATT&CK Enterprise data from {MITRE_ATTACK_ENTERPRISE_JSON_URL}...")
        try:
            response = requests.get(MITRE_ATTACK_ENTERPRISE_JSON_URL, stream=True, timeout=30)
            response.raise_for_status()
            with open(MITRE_ATTACK_LOCAL_FILE, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Download complete.")
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to download MITRE ATT&CK data: {e}", file=sys.stderr)
            return None
    else:
        print(f"Loading MITRE ATT&CK Enterprise data from local file: {MITRE_ATTACK_LOCAL_FILE}...")

    try:
        with open(MITRE_ATTACK_LOCAL_FILE, 'r', encoding='utf-8') as f:
            MITRE_ATTACK_CACHE = json.load(f)
            print("MITRE ATT&CK data loaded.")
            return MITRE_ATTACK_CACHE
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse local MITRE ATT&CK JSON file: {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"ERROR: An unexpected error occurred while loading MITRE ATT&CK data: {e}", file=sys.stderr)
        return None

def get_apt_group_info_from_mitre(group_name):
    """
    Searches loaded MITRE ATT&CK data for information about an Intrusion Set (APT group).
    Provides deep details including associated software, techniques, and campaigns.
    """
    if not MITRE_ATTACK_CACHE and not load_mitre_attack_data():
        return None

    group_name_lower = group_name.lower()
    
    found_group = None
    for obj in MITRE_ATTACK_CACHE.get('objects', []):
        if obj.get('type') == 'intrusion-set':
            # Check primary name
            if obj.get('name', '').lower() == group_name_lower:
                found_group = obj
                break
            # Check aliases
            if 'x_mitre_aliases' in obj:
                if group_name_lower in [alias.lower() for alias in obj['x_mitre_aliases']]:
                    found_group = obj
                    break
    
    if not found_group:
        return None

    info = {
        "name": found_group.get('name', 'N/A'),
        "description": found_group.get('description', 'No description available from MITRE ATT&CK.'),
        "aliases": ", ".join(found_group.get('x_mitre_aliases', [])) if found_group.get('x_mitre_aliases') else 'N/A',
        "external_id": 'N/A',
        "source_url": '#',
        "country": found_group.get('x_mitre_country', 'N/A'),
        "revoked": found_group.get('revoked', False),
        "created": found_group.get('created', 'N/A'),
        "modified": found_group.get('modified', 'N/A'),
        "citations": [],
        "associated_software": [],
        "techniques_used": [],
        "associated_campaigns": []
    }

    if 'external_references' in found_group:
        for ref in found_group['external_references']:
            if ref.get('source_name') == 'mitre-attack':
                info['external_id'] = ref.get('external_id', 'N/A')
                info['source_url'] = ref.get('url', '#')
            if 'url' in ref:
                citation_desc = ref.get('description', ref.get('url', 'Unknown reference'))
                info['citations'].append({'url': ref['url'], 'description': citation_desc})


    # Find relationships for associated software and techniques
    for relationship in MITRE_ATTACK_CACHE.get('objects', []):
        if relationship.get('type') == 'relationship' and relationship.get('relationship_type') == 'uses':
            source_ref = relationship.get('source_ref')
            target_ref = relationship.get('target_ref')

            if source_ref == found_group['id']:
                # Relationship: Group uses Software or Technique
                for obj in MITRE_ATTACK_CACHE.get('objects', []):
                    if obj.get('id') == target_ref:
                        if obj.get('type') == 'malware' or obj.get('type') == 'tool':
                            software_info = {
                                "name": obj.get('name', 'N/A'),
                                "id": 'N/A',
                                "description": obj.get('description', 'N/A'),
                                "url": '#'
                            }
                            if 'external_references' in obj:
                                for ref in obj['external_references']:
                                    if ref.get('source_name') == 'mitre-attack':
                                        software_info['id'] = ref.get('external_id', 'N/A')
                                        software_info['url'] = ref.get('url', '#')
                            info['associated_software'].append(software_info)
                        elif obj.get('type') == 'attack-pattern':
                            technique_info = {
                                "name": obj.get('name', 'N/A'),
                                "id": 'N/A',
                                "description": obj.get('description', 'N/A'),
                                "url": '#'
                            }
                            if 'external_references' in obj:
                                for ref in obj['external_references']:
                                    if ref.get('source_name') == 'mitre-attack':
                                        technique_info['id'] = ref.get('external_id', 'N/A')
                                        technique_info['url'] = ref.get('url', '#')
                            info['techniques_used'].append(technique_info)
        elif relationship.get('type') == 'relationship' and relationship.get('relationship_type') == 'attributed-to':
            source_ref = relationship.get('source_ref') # Usually campaign
            target_ref = relationship.get('target_ref') # Usually intrusion-set

            if target_ref == found_group['id']:
                # Relationship: Campaign attributed to Group
                for obj in MITRE_ATTACK_CACHE.get('objects', []):
                    if obj.get('id') == source_ref and obj.get('type') == 'campaign':
                        campaign_info = {
                            "name": obj.get('name', 'N/A'),
                            "description": obj.get('description', 'N/A'),
                            "url": '#'
                        }
                        if 'external_references' in obj:
                            for ref in obj['external_references']:
                                if ref.get('source_name') == 'mitre-attack':
                                    campaign_info['url'] = ref.get('url', '#')
                        info['associated_campaigns'].append(campaign_info)

    return info

def query_otx_for_apt(apt_group_name):
    """
    Queries AlienVault OTX for pulses and IOCs associated with an APT group name.
    OTX doesn't have a direct 'APT Group' indicator type, so we search pulses.
    """
    headers = {"X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY}
    
    # Search for pulses containing the APT group name in their description or tags
    search_url = f"https://otx.alienvault.com/api/v1/search/pulses?q={requests.utils.quote(apt_group_name)}"
    
    all_iocs = [] # List to hold all IOCs from OTX
    relevant_pulses = [] # Still fetch pulses, but won't be displayed in report

    try:
        response = requests.get(search_url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data.get('results'):
            for pulse in data['results']:
                # Filter pulses to ensure they are highly relevant to the APT group
                name_match = apt_group_name.lower() in pulse.get('name', '').lower()
                desc_match = apt_group_name.lower() in pulse.get('description', '').lower()
                tag_match = any(apt_group_name.lower() in tag.lower() for tag in pulse.get('tags', []))
                
                if name_match or desc_match or tag_match:
                    relevant_pulses.append(pulse)
                    
                    # Extract indicators from these relevant pulses
                    pulse_id = pulse.get('id')
                    if pulse_id:
                        indicators_url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}/indicators"
                        try:
                            indicators_response = requests.get(indicators_url, headers=headers, timeout=15)
                            indicators_response.raise_for_status()
                            indicators_data = indicators_response.json()
                            if indicators_data.get('results'):
                                for ind in indicators_data['results']:
                                    ind_type = ind.get('type')
                                    ind_value = ind.get('indicator')
                                    if ind_value:
                                        # De-fang the value immediately for better processing
                                        ind_value = re.sub(r'\[\.\]', '.', ind_value)
                                        ind_value = re.sub(r'\[\s*dot\s*\]', '.', ind_value, flags=re.IGNORECASE)
                                        
                                        if ind_type == 'IPv4' and not is_valid_ip(ind_value):
                                            continue # Skip invalid IPs
                                        
                                        # Specific handling for types that can be directly mapped
                                        if ind_type in ['IPv4', 'Domain', 'Hostname', 'FileHash', 'CVE', 'URL']: 
                                            # For URLs, try to extract the domain
                                            if ind_type == 'URL':
                                                # Use the robust domain extraction from extract_iocs_from_line
                                                # to make sure we get a proper domain
                                                temp_iocs = extract_iocs_from_line(ind_value)
                                                domain_from_url = next((ioc['value'] for ioc in temp_iocs if ioc['type'] == 'Domain'), None)
                                                if domain_from_url:
                                                    all_iocs.append({
                                                        'source': 'OTX',
                                                        'type': 'Domain', # Convert URL to Domain
                                                        'value': domain_from_url,
                                                        'description': ind.get('description', '')
                                                    })
                                                else: # If a domain couldn't be extracted, keep as Other for now
                                                    all_iocs.append({
                                                        'source': 'OTX',
                                                        'type': 'Other', 
                                                        'value': f"{ind_type}: {ind_value}",
                                                        'description': ind.get('description', '')
                                                    })
                                            elif ind_type == 'FileHash': # OTX just says 'FileHash', we need to check length for type
                                                if len(ind_value) == 32:
                                                    hash_type = 'FileHash-MD5'
                                                elif len(ind_value) == 40:
                                                    hash_type = 'FileHash-SHA1'
                                                elif len(ind_value) == 64:
                                                    hash_type = 'FileHash-SHA256'
                                                else:
                                                    hash_type = 'FileHash-Unknown' # Fallback for odd lengths
                                                all_iocs.append({
                                                    'source': 'OTX',
                                                    'type': hash_type,
                                                    'value': ind_value,
                                                    'description': ind.get('description', '')
                                                })
                                            else: # For IPv4, Domain, Hostname, CVE directly add
                                                all_iocs.append({
                                                    'source': 'OTX',
                                                    'type': ind_type,
                                                    'value': ind_value,
                                                    'description': ind.get('description', '')
                                                })
                                        else: # Catch any other type OTX returns, categorizing them as 'Other'
                                            all_iocs.append({
                                                'source': 'OTX',
                                                'type': 'Other', 
                                                'value': f"{ind_type}: {ind_value}",
                                                'description': ind.get('description', '')
                                            })
                        except requests.exceptions.RequestException as e:
                            print(f"Warning: Failed to get indicators for pulse {pulse_id}: {e}", file=sys.stderr)
                        except json.JSONDecodeError:
                            print(f"Warning: API returned invalid JSON for pulse indicators {pulse_id}.", file=sys.stderr)

        return {
            "pulses": relevant_pulses, 
            "all_extracted_iocs": all_iocs 
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Intelligence platform API request failed for APT group search '{apt_group_name}'. Ensure your API key is correct and network is available: {e}"}
    except json.JSONDecodeError:
        return {"error": f"Intelligence platform API returned invalid JSON for APT group search '{apt_group_name}'. Response: {response.text[:200]}..."}


def extract_iocs_from_line(line):
    iocs = []
    original_line = line.strip()
    if not original_line or original_line.startswith('#'):
        return iocs

    # Step 1: De-fang the line globally for common defanging techniques
    defanged_line = re.sub(r'\[\.\]', '.', original_line)
    defanged_line = re.sub(r'\[\s*dot\s*\]', '.', defanged_line, flags=re.IGNORECASE)
    defanged_line = re.sub(r'\[\s*at\s*\]', '@', defanged_line, flags=re.IGNORECASE)

    # Regex patterns (order matters for extraction priority)
    # URL pattern that captures the host/domain part explicitly
    url_domain_pattern = r'(?:https?://|ftp://|hxxp://|s?ftp://)([a-zA-Z0-9.-]+)(?:[:/]|$)'
    
    # Bare domain pattern: looks for at least two segments and avoids common file extensions
    # IMPORTANT: Removed the look-behind here to fix the re.error
    # We will now filter potential filenames using is_likely_filename AFTER regex matching.
    bare_domain_pattern = r'\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,20})\b'
    
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    cve_pattern = r'\bCVE-\d{4}-\d{4,}\b'
    
    temp_line = defanged_line # Work on the defanged line

    # To ensure we don't re-process or mis-categorize extracted parts,
    # we'll collect the found IOCs and then clean the line before finding "Other"
    current_iocs_found_in_line = [] # Temporarily store IOCs found in THIS line

    # 1. Handle lines that explicitly label an IOC (e.g., "domain: example.com")
    # This takes precedence and extracts the specific value
    
    # Labeled Domains/URLs/C2 (e.g., "domain: example.com", "C2: http://malware.site/path")
    labeled_domain_match = re.match(r'(?i)\s*(?:domain|host|url|c2)\s*[:：]\s*(.*)', temp_line)
    if labeled_domain_match:
        potential_value = labeled_domain_match.group(1).strip()
        # Try to extract the domain from this potential value (might be a full URL or a bare domain)
        url_match = re.match(url_domain_pattern, potential_value, re.IGNORECASE)
        if url_match:
            domain_val = url_match.group(1).strip('.')
            if not is_valid_ip(domain_val) and not is_likely_filename(domain_val):
                current_iocs_found_in_line.append({'type': 'Domain', 'value': domain_val, 'description': ''})
                temp_line = "" # Mark line as processed for specific IOC
        else: # Try as a bare domain from the labeled value
            bare_domain_match_label = re.match(bare_domain_pattern, potential_value, re.IGNORECASE) # Use the simplified pattern
            if bare_domain_match_label:
                domain_val = bare_domain_match_label.group(1).strip('.')
                if not is_valid_ip(domain_val) and not is_likely_filename(domain_val):
                    current_iocs_found_in_line.append({'type': 'Domain', 'value': domain_val, 'description': ''})
                    temp_line = "" # Mark line as processed for specific IOC
    
    # Labeled Hashes (e.g., "FileHash-MD5: hashvalue")
    labeled_hash_match = re.match(r'(?i)\s*(?:filehash|hash|md5|sha1|sha256)\s*[:：]\s*([a-fA-F0-9]{32,64})\b', temp_line)
    if labeled_hash_match:
        hash_value = labeled_hash_match.group(1)
        if len(hash_value) == 32:
            current_iocs_found_in_line.append({'type': 'FileHash-MD5', 'value': hash_value, 'description': ''})
        elif len(hash_value) == 40:
            current_iocs_found_in_line.append({'type': 'FileHash-SHA1', 'value': hash_value, 'description': ''})
        elif len(hash_value) == 64:
            current_iocs_found_in_line.append({'type': 'FileHash-SHA256', 'value': hash_value, 'description': ''})
        temp_line = "" # Mark line as processed for specific IOC

    # Labeled IPs (e.g., "IP: 1.2.3.4")
    labeled_ip_match = re.match(r'(?i)\s*(?:ip|ipv4)\s*[:：]\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b', temp_line)
    if labeled_ip_match:
        ip_value = labeled_ip_match.group(1)
        if is_valid_ip(ip_value):
            current_iocs_found_in_line.append({'type': 'IPv4', 'value': ip_value, 'description': ''})
            temp_line = "" # Mark line as processed for specific IOC

    # 2. If the line wasn't fully processed by explicit labels, apply general regexes
    
    # Extract URLs/Domains (from full URLs)
    # Using finditer to catch all occurrences
    for match in re.finditer(url_domain_pattern, temp_line, re.IGNORECASE):
        domain = match.group(1).strip('.')
        if not is_valid_ip(domain) and not is_likely_filename(domain):
            if {'type': 'Domain', 'value': domain, 'description': ''} not in current_iocs_found_in_line:
                current_iocs_found_in_line.append({'type': 'Domain', 'value': domain, 'description': ''})

    # Extract bare domains (if not already found as part of a URL)
    # Now that the regex is simpler, the filtering for filenames happens here.
    for match in re.finditer(bare_domain_pattern, temp_line, re.IGNORECASE):
        domain = match.group(1).strip('.')
        if not is_valid_ip(domain) and not is_likely_filename(domain): # This is the crucial filter
            if {'type': 'Domain', 'value': domain, 'description': ''} not in current_iocs_found_in_line:
                current_iocs_found_in_line.append({'type': 'Domain', 'value': domain, 'description': ''})

    # Extract CVEs
    for cve in re.findall(cve_pattern, temp_line):
        if {'type': 'CVE', 'value': cve, 'description': ''} not in current_iocs_found_in_line:
            current_iocs_found_in_line.append({'type': 'CVE', 'value': cve, 'description': ''})

    # Extract IPs
    for ip in re.findall(ipv4_pattern, temp_line):
        if is_valid_ip(ip) and {'type': 'IPv4', 'value': ip, 'description': ''} not in current_iocs_found_in_line:
            current_iocs_found_in_line.append({'type': 'IPv4', 'value': ip, 'description': ''})

    # Extract Hashes (MD5, SHA1, SHA256)
    for h in re.findall(sha256_pattern, temp_line):
        if {'type': 'FileHash-SHA256', 'value': h, 'description': ''} not in current_iocs_found_in_line:
            current_iocs_found_in_line.append({'type': 'FileHash-SHA256', 'value': h, 'description': ''})
    for h in re.findall(sha1_pattern, temp_line):
        if {'type': 'FileHash-SHA1', 'value': h, 'description': ''} not in current_iocs_found_in_line:
            current_iocs_found_in_line.append({'type': 'FileHash-SHA1', 'value': h, 'description': ''})
    for h in re.findall(md5_pattern, temp_line):
        if {'type': 'FileHash-MD5', 'value': h, 'description': ''} not in current_iocs_found_in_line:
            current_iocs_found_in_line.append({'type': 'FileHash-MD5', 'value': h, 'description': ''})

    # Add all collected IOCs from this line to the main list
    iocs.extend(current_iocs_found_in_line)

    # 3. Final "Other" check: if no specific IOCs were identified from the line (either directly or via general regexes),
    # and the line is not just a comment or empty, add it to 'Other'.
    if not current_iocs_found_in_line and original_line.strip() and not original_line.startswith('#'):
        # Attempt to clean specific "Other: " prefixes from the user's input examples
        cleaned_other_value = original_line.strip()
        if cleaned_other_value.lower().startswith("other:"):
            cleaned_other_value = cleaned_other_value[len("other:"):].strip()
        # Further clean up prefixes like "IOC:", "C2:", "SedUploader C2:" if they weren't fully processed
        if re.match(r'(?i)(?:ioc|c2|seduploader c2)\s*[:：]\s*', cleaned_other_value):
            cleaned_other_value = re.sub(r'(?i)(?:ioc|c2|seduploader c2)\s*[:：]\s*', '', cleaned_other_value, 1).strip()

        # Add to other only if it's not empty after all cleaning and not just a single punctuation
        if cleaned_other_value and cleaned_other_value not in {'.', ':', '：'}:
            iocs.append({'type': 'Other', 'value': cleaned_other_value, 'description': 'Unclassified IOC'})

    return iocs


def get_iocs_from_github_repo(owner, repo, apt_name_path):
    github_api_base = f"https://api.github.com/repos/{owner}/{repo}/contents/{apt_name_path}/IOC"
    github_raw_base = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{apt_name_path}/IOC"
    iocs = []

    try:
        # Get list of files in the IOC directory
        response = requests.get(github_api_base)
        response.raise_for_status()
        files_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching file list from GitHub: {e}")
        return []

    for item in files_data:
        if item.get('type') == 'file' and item.get('name', '').endswith('.txt'):
            file_name = item['name']
            raw_file_url = f"{github_raw_base}/{file_name}"

            try:
                file_content_response = requests.get(raw_file_url)
                file_content_response.raise_for_status()
                file_content = file_content_response.text

                # Parse IOCs from each line of the file
                for line in file_content.splitlines():
                    extracted = extract_iocs_from_line(line)
                    for ioc in extracted:
                        ioc['source'] = f'GitHub:{file_name}' # Add source information
                        iocs.append(ioc)
            except requests.exceptions.RequestException as e:
                print(f"Error fetching content for {raw_file_url}: {e}")
                continue
    return iocs


def generate_html_report_apt(apt_group_name, mitre_apt_info, cve_list, ip_list, domain_list, hash_list, other_iocs_list, ransomware_wallets): # MODIFIED: Added ransomware_wallets parameter
    """Generates an HTML report for the given APT group."""
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- CSS Styling ---
    custom_css = """
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto:wght@400;700&display=swap');

    :root {
      --bg-color: #0a0a0a;
      --box-color: #121212;
      --text-color: #00f5d4; /* Your accent greenish-blue */
      --accent: #00ff88;    /* Your bright green accent */
      --footer-bg: #111;
      --footer-text: #ccc;
      --input-bg: #1e1e1e;
      --input-border: #00f5d4;
    }

    body.light-theme {
      --bg-color: #f9f9f9;
      --box-color: #ffffff;
      --text-color: #111;
      --accent: #00c47a;
      --footer-bg: #eaeaea;
      --footer-text: #333;
      --input-bg: #f0f0f0;
      --input-border: #00c47a;
    }

    html, body {
      min-height: 100vh;
      margin: 0;
      padding: 0;
      font-family: 'Roboto', sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      display: flex;
      flex-direction: column;
      transition: background-color 0.4s, color 0.4s;
    }
    .header {
        text-align: center;
        padding: 20px;
        background-color: var(--box-color);
        border-bottom: 2px solid var(--accent);
        box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        z-index: 10;
        position: sticky;
        top: 0;
    }
    h1 {
        margin: 0;
        color: var(--text-color);
        font-family: 'Orbitron', sans-serif;
        font-size: 2.5em;
        text-shadow: 0 0 8px var(--accent);
    }
    .subtitle {
        color: var(--footer-text);
        font-size: 1.1em;
        margin-top: 5px;
    }

    .content-section {
        padding: 20px;
        width: 90%;
        margin: 20px auto;
        background-color: var(--box-color);
        border-radius: 10px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.4);
        line-height: 1.6;
        flex-grow: 1;
        box-sizing: border-box;
    }
    @media (min-width: 1400px) {
        .content-section {
            width: 80%;
        }
    }
    @media (max-width: 768px) {
        .content-section {
            width: 95%;
            padding: 15px;
        }
    }
    .content-section h2, .content-section h3 {
        color: var(--accent);
        border-bottom: 1px solid var(--text-color);
        padding-bottom: 10px;
        margin-top: 30px;
        margin-bottom: 20px;
        font-family: 'Orbitron', sans-serif;
    }
    .content-section p, .content-section ul, .content-section table {
        margin-bottom: 10px;
        color: var(--footer-text);
    }
    .content-section ul {
        padding-left: 25px;
        list-style: disc;
    }
    .content-section ul li {
        margin-bottom: 8px;
    }
    .content-section a {
        color: var(--text-color);
        text-decoration: none;
    }
    .content-section a:hover {
        color: var(--accent);
        text-decoration: underline;
    }

    .xeno-footer {
      flex-shrink: 0;
      background: var(--footer-bg);
      color: var(--footer-text);
      text-align: center;
      font-family: 'Roboto', sans-serif;
      font-size: 0.95rem;
      border-top: 2px solid var(--accent);
      padding: 20px 10px;
      width: 100%;
      margin-top: 40px;
    }

    .xeno-footer a {
      color: var(--text-color);
      text-decoration: none;
      transition: color 0.3s ease;
    }

    .xeno-footer a:hover {
      color: var(--accent);
    }

    .toggle-theme {
      position: absolute;
      top: 20px;
      right: 20px;
      background-color: var(--box-color);
      color: var(--text-color);
      border: 2px solid var(--text-color);
      border-radius: 30px;
      padding: 6px 16px;
      font-size: 0.9rem;
      font-weight: bold;
      cursor: pointer;
      transition: all 0.3s ease;
      z-index: 1000;
    }
    .toggle-theme:hover {
      background-color: var(--accent);
      color: #000;
      border-color: var(--accent);
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
    }
    th, td {
        border: 1px solid var(--text-color);
        padding: 8px;
        text-align: left;
    }
    th {
        background-color: var(--accent);
        color: var(--box-color);
        font-family: 'Orbitron', sans-serif;
    }
    .error-message {
        color: #ff6347; /* Tomato red for errors */
        font-weight: bold;
    }
    """

    report_title = f"XenoByte Threat Intelligence Report for APT Group: {apt_group_name}"
    html_sections = []

    # --- APT Group Information Section (MITRE ATT&CK) ---
    mitre_section = "<h2>APT GROUP INFORMATION</h2>" 
    if mitre_apt_info:
        mitre_section += f"""
        <h3>Details for Intrusion Set (APT Group): <span style="color: var(--accent);">{mitre_apt_info['name']}</span></h3>
        <p><strong>Associated ID:</strong> <a href="{mitre_apt_info['source_url']}" target="_blank" style="color: var(--text-color);">{mitre_apt_info['external_id']}</a></p>
        <p><strong>Aliases:</strong> {mitre_apt_info['aliases']}</p>
        <p><strong>Country (X-MITRE):</strong> {mitre_apt_info['country']}</p>
        <p><strong>Revoked:</strong> {'Yes' if mitre_apt_info['revoked'] else 'No'}</p>
        <p><strong>Created:</strong> {mitre_apt_info['created']}</p>
        <p><strong>Last Modified:</strong> {mitre_apt_info['modified']}</p>
        <p><strong>Description:</strong> {mitre_apt_info['description']}</p>
        """

        if mitre_apt_info['associated_campaigns']:
            mitre_section += "<h3>Associated Campaigns</h3><ul>"
            for campaign in mitre_apt_info['associated_campaigns']:
                mitre_section += f"<li><a href=\"{campaign['url']}\" target=\"_blank\" style=\"color: var(--text-color);\">{campaign['name']}</a><br>"
                if campaign['description'] != 'N/A':
                    mitre_section += f"    <strong>Description:</strong> {campaign['description']}</li>"
            mitre_section += "</ul>"

        if mitre_apt_info['associated_software']:
            mitre_section += "<h3>Associated Software/Tools</h3><ul>"
            for software in mitre_apt_info['associated_software']:
                mitre_section += f"<li><a href=\"{software['url']}\" target=\"_blank\" style=\"color: var(--text-color);\">{software['name']}</a> (ID: {software['id']})<br>"
                if software['description'] != 'N/A':
                    mitre_section += f"    <strong>Description:</strong> {software['description']}</li>"
            mitre_section += "</ul>"

        if mitre_apt_info['techniques_used']:
            mitre_section += "<h3>Commonly Used Techniques (TTPs)</h3><ul>"
            for technique in mitre_apt_info['techniques_used']:
                # Truncate long descriptions for readability in report
                desc = technique['description']
                truncated_desc = f"{desc[:200]}{'...' if len(desc) > 200 else ''}"
                mitre_section += f"<li><a href=\"{technique['url']}\" target=\"_blank\" style=\"color: var(--text-color);\">{technique['name']}</a> (TID:{technique['id']})<br>"
                mitre_section += f"    <strong>Description:</strong> {truncated_desc}</li>"
            mitre_section += "</ul>"

        if mitre_apt_info['citations']:
            mitre_section += "<h3>External Citations/References for Information</h3><ul>"
            for citation in mitre_apt_info['citations']:
                mitre_section += f'<li><a href="{citation["url"]}" target="_blank" style="color: var(--text-color);">{citation["description"]}</a></li>'
            mitre_section += "</ul>"
    else:
        mitre_section += "<p>No specific APT group details found in the primary intelligence source for the provided group name.</p>"
        mitre_section += "<p>Consider manually Browse MITRE ATT&CK for potential matches: <a href=\"https://attack.mitre.org/groups/\" target=\"_blank\" style=\"color: var(--text-color);\">https://attack.mitre.org/groups/</a></p>"
    html_sections.append(mitre_section)

    # --- IOCs Section ---
    iocs_section = "<h2>Indicators of Compromise (IOCs)</h2>"

    if cve_list:
        iocs_section += "<h3>CVEs</h3><ul>"
        for cve in cve_list:
            iocs_section += f"<li>{cve}</li>"
        iocs_section += "</ul>"
    else:
        iocs_section += "<p>No CVEs found.</p>"

    if ip_list:
        iocs_section += "<h3>IP Addresses</h3><ul>"
        for ip in ip_list:
            iocs_section += f"<li>{ip}</li>"
        iocs_section += "</ul>"
    else:
        iocs_section += "<p>No IP addresses found.</p>"

    if domain_list: # Re-added domain list section
        iocs_section += "<h3>Domain Names</h3><ul>"
        for domain in domain_list:
            iocs_section += f"<li>{domain}</li>"
        iocs_section += "</ul>"
    else:
        iocs_section += "<p>No domain names found.</p>"

    if hash_list:
        iocs_section += "<h3>File Hashes</h3><ul>"
        for file_hash in hash_list:
            iocs_section += f"<li>{file_hash}</li>"
        iocs_section += "</ul>"
    else:
        iocs_section += "<p>No file hashes found.</p>"

    if not (cve_list or ip_list or domain_list or hash_list or other_iocs_list):
        iocs_section += "<p>No Indicators of Compromise (IOCs) found from the intelligence feeds.</p>"

    html_sections.append(iocs_section)

    # --- NEW: Ransomware Wallet Addresses Section ---
    ransomware_wallets_section = "<h2>Ransomware Wallet Addresses</h2>" # NEW SECTION
    if ransomware_wallets:
        ransomware_wallets_section += "<p>As a demonstration of advanced capabilities, here are a few cryptocurrency wallet addresses associated with ransomware operations. These can be used for financial tracing in incident response scenarios.</p><ul>"
        for wallet in ransomware_wallets:
            ransomware_wallets_section += f"<li>{wallet}</li>"
        ransomware_wallets_section += "</ul>"
    else:
        ransomware_wallets_section += f"<p>No ransomware wallet addresses loaded. Ensure '{RANSOMWARE_WALLETS_FILE}' exists and contains addresses.</p>"
    html_sections.append(ransomware_wallets_section) # ADD THIS SECTION TO THE REPORT


    # --- External Resources & Manual Research Guidance ---
    external_resources_section = "<h2>Further Investigation & Open-Source Resources</h2>"
    external_resources_section += """
    <p>Comprehensive threat intelligence often requires manual investigation and cross-referencing. Consider the following resources for deeper analysis and to uncover additional indicators:</p>
    <ul>
        <li><a href="https://www.cisa.gov/news-events/alerts-advisories" target="_blank" style="color: var(--text-color);">CISA Alerts & Advisories</a> (Government advisories)</li>
        <li><a href="https://www.mandiant.com/resources/blog" target="_blank" style="color: var(--text-color);">Mandiant (Google Cloud) Threat Research</a> (Industry-leading reports)</li>
        <li><a href="https://www.microsoft.com/en-us/security/business/threat-intelligence" target="_blank" style="color: var(--text-color);">Microsoft Threat Intelligence</a> (Vendor-specific insights)</li>
        <li><a href="https://pulsedive.com/" target="_blank" style="color: var(--text-color);">Pulsedive</a> (Community threat intelligence platform)</li>
        <li><a href="https://www.threatminer.org/" target="_blank" style="color: var(--text-color);">ThreatMiner</a> (Threat intelligence search engine)</li>
        <li><a href="https://bazaar.abuse.ch/" target="_blank" style="color: var(--text-color);">MalwareBazaar</a> (Malware sample database)</li>
        <li><a href="https://urlhaus.abuse.ch/" target="_blank" style="color: var(--text-color);">URLhaus</a> (Malicious URL database)</li>
        <li><a href="https://www.shodan.io/" target="_blank" style="color: var(--text-color);">Shodan</a> (Internet-facing asset search engine)</li>
        <li><a href="https://www.virustotal.com/gui/home/upload" target="_blank" style="color: var(--text-color);">VirusTotal</a> (Malware analysis and IOC scanning)</li>
        <li><a href="https://krebsonsecurity.com/" target="_blank" style="color: var(--text-color);">KrebsOnSecurity</a> (Investigative security journalism)</li>
        <li><a href="https://www.recordedfuture.com/blog" target="_blank" style="color: var(--text-color);">Recorded Future Blog</a> (Threat intelligence insights)</li>
        <li><a href="https://www.cisecurity.org/insights/blog" target="_blank" style="color: var(--text-color);">CIS Blog</a> (Cybersecurity best practices)</li>
    </ul>
    """
    html_sections.append(external_resources_section)

    # --- JavaScript for theme toggling ---
    theme_toggle_js = """
    <script>
        function toggleTheme() {
            document.body.classList.toggle('light-theme');
            let isLight = document.body.classList.contains('light-theme');
            localStorage.setItem('theme', isLight ? 'light' : 'dark');
            document.getElementById('theme-toggle-button').textContent = isLight ? 'Dark Mode' : 'Light Mode';
        }

        // Apply theme on load
        document.addEventListener('DOMContentLoaded', (event) => {
            if (localStorage.getItem('theme') === 'light') {
                document.body.classList.add('light-theme');
                document.getElementById('theme-toggle-button').textContent = 'Dark Mode';
            } else {
                document.getElementById('theme-toggle-button').textContent = 'Light Mode';
            }
        });
    </script>
    """

    full_html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_title}</title>
    <style>
        {custom_css}
    </style>
</head>
<body>
    <button id="theme-toggle-button" class="toggle-theme" onclick="toggleTheme()">Light Mode</button>
    <div class="header">
        <h1>{report_title}</h1>
        <p class="subtitle">Generated by XenoByte Threat Intelligence Platform on {current_time}</p>
    </div>
    <div class="content-section">
        {''.join(html_sections)}
    </div>
    <footer class="xeno-footer">
        <p>&copy; {datetime.now().year} XenoByte Threat Intelligence. All rights reserved.</p>
        <p>Data from various public and open-source intelligence feeds.</p>
    </footer>
    {theme_toggle_js}
</body>
</html>
    """
    return full_html_content

# --- Main Execution Logic ---
def main():
    print("Welcome to XenoByte Threat Intelligence Reporter!")
    print("--------------------------------------------------")

    # Load MITRE data once at the start
    print("\n[INFO] Initializing MITRE ATT&CK data...")
    if not load_mitre_attack_data():
        print("[ERROR] Failed to load MITRE ATT&CK data. Report might be incomplete.", file=sys.stderr)
        # Continue execution but MITRE section will be empty

    apt_group_name = input("Enter APT group name (e.g., APT28, Fancy Bear, Lazarus Group): ").strip()
    if not apt_group_name:
        print("[!] APT group name cannot be empty. Exiting.", file=sys.stderr)
        return

    print(f"\n[+] Gathering intelligence for APT group: {apt_group_name}...")

    # 1. Get MITRE ATT&CK Info
    print("[*] Querying primary intelligence source for group profile...")
    mitre_info = get_apt_group_info_from_mitre(apt_group_name)
    if mitre_info:
        print(f"    [+] Found group profile for {mitre_info['name']}.")
    else:
        print(f"    [-] No detailed group profile found for '{apt_group_name}'.")

    # 2. Get OTX Intelligence (includes IOCs from OTX)
    print("[*] Querying public threat intelligence feeds for associated IOCs...")
    otx_data = query_otx_for_apt(apt_group_name)
    
    # 3. Get GitHub IOCs (from blackorbird/APT_REPORT)
    print(f"[*] Fetching additional IOCs from GitHub repository (https://github.com/blackorbird/APT_REPORT/{apt_group_name}/IOC)...")
    github_iocs = get_iocs_from_github_repo("blackorbird", "APT_REPORT", apt_group_name)

    # 4. Load Ransomware Wallet Addresses (NEW)
    print(f"[*] Loading random ransomware wallet addresses from '{RANSOMWARE_WALLETS_FILE}' (Demo Feature)...")
    ransomware_wallets = load_random_wallet_addresses(count=15) # You can adjust the count here

    # Combine all extracted IOCs from OTX and GitHub
    master_ioc_list = []
    if isinstance(otx_data, dict) and not otx_data.get("error"):
        master_ioc_list.extend(otx_data.get('all_extracted_iocs', []))
    master_ioc_list.extend(github_iocs)

    # Categorize and de-duplicate IOCs
    cve_list = set()
    ip_list = set()
    domain_list = set()
    hash_list = set()
    other_list = set() # For any unclassified or 'other' types

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
            # Normalize domains by removing leading/trailing dots and ensuring lowercase
            domain_value = ioc_value.strip('.').lower()
            if not is_likely_filename(domain_value): # Final check
                domain_list.add(domain_value)
        elif ioc_type.startswith('FileHash'):
            hash_list.add(ioc_value)
        else: # Catch all other types
            other_list.add(ioc_value) # Value is already cleaned in extract_iocs_from_line

    # Convert sets back to sorted lists for consistent display
    cve_list = sorted(list(cve_list))
    ip_list = sorted(list(ip_list))
    domain_list = sorted(list(domain_list))
    hash_list = sorted(list(hash_list))
    other_list = sorted(list(other_list))

    print(f"    [+] Total unique categorized IOCs found: IPs({len(ip_list)}) Domains({len(domain_list)}) Hashes({len(hash_list)}) CVEs({len(cve_list)}) Other({len(other_list)})")

    # Generate and save HTML report
    print("\n[+] Generating HTML report...")
    html_report_content = generate_html_report_apt(
        apt_group_name,
        mitre_info,
        cve_list,
        ip_list,
        domain_list,
        hash_list,
        other_list,
        ransomware_wallets # ADDED: Pass ransomware_wallets to the function
    )

    report_filename = f"XenoByte_Threat_Report_{apt_group_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(html_report_content)
        print(f"[+] Report saved to: {report_filename}")

        # Open report in browser
        print(f"[+] Opening report in browser...")
        webbrowser.open(f"file://{os.path.abspath(report_filename)}")
        print("\n[+] Report generation complete. Enjoy your threat intelligence!")
    except IOError as e:
        print(f"[ERROR] Failed to write report file: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred while opening the report: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()