import requests 
import json
import os
import time

#load API key from .env file
# never hardcore the key in your source code 
from dotenv import load_dotenv
load_dotenv() 

NVD_API_KEY = os.getenv("NVD_API_KEY")

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
#cache folder -stores ApI resposnes locally 
# so you never hit the API twice the same keyword 
CACHE_DIR = os.path.join(os.path.dirname(__file__),"data","cache")


def _get_cache_path(keyword):
    """
       Each keyword gets its own cache file 
       'openssh' → data/cache/openssh.json
    """
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, f"{keyword.replace(' ','_')}.json")

def _load_cache(keyword):
    """
    try to load cached results for this keyword
    Returns list of cve dicts if cache exits , None if not.

    """
    path = _get_cache_path(keyword)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return None 

def _save_cache(keyword,data):
    """ Save API results to cache file.
    NExt time this keyword is queried , we read from file 
    instead of hitting the API
    """
    path = _get_cache_path(keyword)
    with open(path, 'w') as f :
        json.dump(data,f,indent=2)

def _parse_cvss_score(cve_item):
    """
    Extract CVSS score from a CVE item.
    Try V31 first — it is more recent and accurate.
    Fall back to V2 if V31 is not available.
    Return 0.0 if neither exists.

    This is why you identified both V31 and V2 in the response —
    not every CVE has a V31 score, older ones only have V2.
    """
    metrics = cve_item.get("metrics",{})
    v31 = metrics.get("cvssMetricV31", [])
    if v31:
        return v31[0]["cvssData"]["baseScore"]

    # fall back to V2
    v2 = metrics.get("cvssMetricV2", [])
    if v2:
        return v2[0]["cvssData"]["baseScore"]

    return 0.0

def _parse_description(cve_item):
    """
    Extract English description from descriptions list.
    The list can contain multiple languages — we want 'en' only.
    """
    descriptions = cve_item.get("descriptions", [])
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "No description available")
    return "No description available"
    
def _score_to_severity(score):
    """
       
    Convert numeric CVSS score to severity label.
    These thresholds are defined by the official CVSS v3.1 standard.
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score >0.0:
        return "Low"
    else:
        return "Informational"
    
def fetch_cves_from_api(keyword, max_results = 5):
    """
    query the nvd Api for CVEs matching a keyword .

    order of operations:
    1. Check cache- if results exist locally , return them immediatly 
    2. call the nvd api with keyword filter 
    3. PArse response - extract ID , score, description
    4. SAve results to cache 
    5. Return list of CVE dicts 
    returns empty list 
    """
    
    #step 1-check cache first 
    cached =_load_cache(keyword)
    if cached is not None :
        print(f"[API]Cache hit for '{keyword }'-{len(cached)}CVEs loaded locally")
        return cached 
    
    #step 2 -Build APi Request
    headers = {}
    if NVD_API_KEY:
        #with API key :50request per 30 seconds 
        #without API key : 5request per 30 sec .
        headers["apiKey"] = NVD_API_KEY
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "cvssV3Severity": "HIGH",
    }
    try:
        print(f"[API] Querying NVD for '{keyword}'....")
        response = requests.get(
            NVD_BASE_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        # 403 means rate limited — wait and do not crash
        if response.status_code == 403:
            print(f"[API] Rate limited. Waiting 30 seconds...")
            time.sleep(30)
            return []

            # any other non-200 response
        if response.status_code != 200:
            # Try to get the error message from the API's response body
            error_body = "No further details"
            try:
                error_json = response.json()
                error_body = error_json.get('message', error_json)
            except:
                error_body = response.text[:200] # Fallback to raw text
            print(f"[API] API Error {response.status_code} for '{keyword}': {error_body}")
            return []

        # step 3 — parse the response
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        results = []
        for item in vulnerabilities:
            cve_item = item.get("cve", {})

            cve_id = cve_item.get("id", "UNKNOWN")
            score = _parse_cvss_score(cve_item)
            description = _parse_description(cve_item)
            severity = _score_to_severity(score)

            results.append({
                "id": cve_id,
                "service": keyword,
                "description": description,
                "cvss_score": score,
                "severity": severity
            })

        # sort by score descending — highest severity first
        results.sort(key=lambda x: x["cvss_score"], reverse=True)

        # step 4 — save to cache
        _save_cache(keyword, results)
        print(f"[API] Found {len(results)} CVEs for '{keyword}', cached locally")

        return results

    except requests.exceptions.Timeout:
        print(f"[API] Timeout querying NVD for '{keyword}'")
        return []
    except requests.exceptions.ConnectionError:
        print(f"[API] Cannot reach NVD API — are you online?")
        return []
    except Exception as e:
        print(f"[API] Unexpected error for '{keyword}': {e}")
        return []


if __name__ == "__main__":
    # test the API directly
    results = fetch_cves_from_api("openssh", max_results=5)
    print(f"\n[TEST] API returned {len(results)} CVEs:")
    for cve in results:
        print(f"  {cve['id']} | {cve['cvss_score']} | {cve['severity']} | {cve['description'][:60]}")