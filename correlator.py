import os
import sys

# import our own modules
from cve_db import query_local_db
from nvd_api import fetch_cves_from_api

# maps COMMON_SERVICES name → CVE search keyword
# this is the bridge between your scanner and your database
SERVICE_TO_KEYWORD = {
    "SSH":        "openssh",
    "HTTP":       "apache",
    "HTTPS":      "apache",
    "FTP":        "vsftpd",
    "Telnet":     "telnet",
    "SMTP":       "postfix",
    "MySQL":      "mysql",
    "RDP":        "rdp",
    "SMB":        "samba",
    "PostgreSQL": "postgresql",
    "Redis":      "redis",
    "MongoDB":    "mongodb",
    "DNS":        "bind dns",
    "POP3":       "dovecot",
    "IMAP":       "dovecot",
}

# recommendations per service
# your jury will ask what a sysadmin should do about each finding
RECOMMENDATIONS = {
    "SSH":        "Disable root login, enforce key-based authentication, restrict access via firewall, update to latest OpenSSH version.",
    "HTTP":       "Enforce HTTPS with TLS 1.3, disable HTTP. Install and configure a WAF. Keep web server patched.",
    "HTTPS":      "Verify TLS certificate validity, disable TLS 1.0/1.1, enforce HSTS, keep web server patched.",
    "FTP":        "Disable FTP immediately. Replace with SFTP (SSH File Transfer Protocol). FTP transmits credentials in plaintext.",
    "Telnet":     "Disable Telnet immediately. Replace with SSH. Telnet transmits all data including passwords in plaintext.",
    "SMTP":       "Enable TLS for SMTP, configure SPF/DKIM/DMARC records, restrict relay access, keep mail server patched.",
    "MySQL":      "Restrict MySQL to localhost or VPN only. Disable remote root login. Use strong passwords. Keep patched.",
    "RDP":        "Restrict RDP to VPN only. Enable Network Level Authentication. Use strong passwords. Keep Windows patched.",
    "SMB":        "Disable SMBv1 immediately. Restrict SMB to internal network only. Keep Windows/Samba patched.",
    "PostgreSQL": "Restrict to localhost or VPN. Use role-based access control. Disable superuser remote login.",
    "Redis":      "Bind Redis to localhost only. Enable authentication. Never expose Redis to the internet.",
    "MongoDB":    "Enable MongoDB authentication. Bind to localhost. Never expose MongoDB to the internet without auth.",
    "DNS":        "Restrict zone transfers. Enable DNSSEC. Keep BIND patched. Disable recursion for external clients.",
    "POP3":       "Use POP3S (encrypted). Migrate to IMAP over TLS. Keep mail server patched.",
    "IMAP":       "Enforce IMAPS (encrypted). Disable plaintext IMAP. Keep mail server patched.",
}

DEFAULT_RECOMMENDATION = "Review service necessity. Apply latest patches. Restrict access via firewall rules."


def _get_risk_level(score):
    """
    Convert highest CVSS score to risk level.
    Uses official CVSS v3.1 severity thresholds.
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    else:
        return "Informational"


def correlate_port(port_result):
    """
    Take one open port result dict from the scanner.
    Enrich it with CVEs, risk level, and recommendation.
    Returns the enriched dict.

    This is the core of the correlation engine.
    """
    port = port_result["port"]
    service = port_result.get("service", "unknown")

    # step 1 — get the CVE search keyword for this service
    # if service not in our map, we cannot correlate — return as informational
    keyword = SERVICE_TO_KEYWORD.get(service)

    if not keyword:
        port_result["cves"] = []
        port_result["risk_level"] = "Informational"
        port_result["risk_score"] = 0.0
        port_result["recommendation"] = DEFAULT_RECOMMENDATION
        return port_result

    # step 2 — query local database first (fast, no network)
    print(f"[CORRELATE] Port {port} ({service}) → searching local DB for '{keyword}'")
    cves = query_local_db(keyword)

    # step 3 — if local DB has nothing, try the API
    if not cves:
        print(f"[CORRELATE] No local results for '{keyword}' → querying NVD API")
        cves = fetch_cves_from_api(keyword, max_results=5)

    # step 4 — calculate risk from highest CVSS score found
    if cves:
        # cves are already sorted by score descending
        # so first item has the highest score
        highest_score = cves[0]["cvss_score"]
        risk_level = _get_risk_level(highest_score)
    else:
        # no CVEs found in either source
        highest_score = 0.0
        risk_level = "Informational"

    # step 5 — get recommendation for this service
    recommendation = RECOMMENDATIONS.get(service, DEFAULT_RECOMMENDATION)

    # step 6 — attach everything to the port result
    port_result["cves"] = cves
    port_result["risk_level"] = risk_level
    port_result["risk_score"] = highest_score
    port_result["recommendation"] = recommendation

    return port_result


def correlate_all(scan_results):
    """
    Take the full list of scan results.
    Correlate only open ports — closed and filtered have no CVEs.
    Returns enriched list with all ports included.
    """
    enriched = []

    for result in scan_results:
        if result["status"] == "open":
            # enrich open ports with CVE data
            enriched.append(correlate_port(result))
        else:
            # pass through closed/filtered unchanged
            enriched.append(result)

    return enriched


if __name__ == "__main__":
    # simulate scanner output to test correlator independently
    fake_scan_results = [
        {"port": 22,  "status": "open",     "service": "SSH",  "banner": "SSH-2.0-OpenSSH_6.6.1"},
        {"port": 80,  "status": "open",     "service": "HTTP", "banner": "Apache/2.4.49"},
        {"port": 443, "status": "filtered", "service": "HTTPS","banner": ""},
        {"port": 23,  "status": "open",     "service": "Telnet","banner": ""},
    ]

    print("[TEST] Running correlation on simulated scan results...\n")
    results = correlate_all(fake_scan_results)

    for r in results:
        if r["status"] == "open":
            print(f"\nPort {r['port']} — {r['service']}")
            print(f"  Risk     : {r['risk_level']} ({r['risk_score']})")
            print(f"  CVEs     : {len(r['cves'])} found")
            for cve in r['cves'][:2]:
                print(f"    {cve['id']} | {cve['cvss_score']} | {cve['description'][:50]}")
            print(f"  Recommend: {r['recommendation'][:60]}...")