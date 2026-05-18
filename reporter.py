import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


def generate_report(scan_results, host, ip, start_port, end_port, output_path="report.html"):
    """
    Take enriched scan results and generate a professional HTML report.
    
    scan_results: full list from scanner including open/closed/filtered
    host: target hostname
    ip: resolved IP address
    output_path: where to save the HTML file
    """

    # filter only open ports for the report
    open_ports = [r for r in scan_results if r["status"] == "open"]

    # count risk levels for the summary stats and chart
    critical_count = sum(1 for r in open_ports if r.get("risk_level") == "Critical")
    high_count     = sum(1 for r in open_ports if r.get("risk_level") == "High")
    medium_count   = sum(1 for r in open_ports if r.get("risk_level") == "Medium")
    low_count      = sum(1 for r in open_ports if r.get("risk_level") == "Low")
    info_count     = sum(1 for r in open_ports if r.get("risk_level") == "Informational")

    # count total CVEs across all open ports
    total_cves = sum(len(r.get("cves", [])) for r in open_ports)

    # build the template context — everything the template can access
    context = {
        "target":        host,
        "ip":            ip,
        "scan_date":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "start_port":    start_port,
        "end_port":      end_port,
        "total_scanned": end_port - start_port + 1,
        "open_count":    len(open_ports),
        "total_cves":    total_cves,
        "critical_count": critical_count,
        "high_count":    high_count,
        "medium_count":  medium_count,
        "low_count":     low_count,
        "info_count":    info_count,
        "open_ports":    open_ports,
    }

    # load the template from the templates folder
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("./report_template.html")

    # render — this replaces all {{ variables }} with real data
    html = template.render(**context)

    # write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[REPORT] Report saved to: {output_path}")
    return output_path


if __name__ == "__main__":
    # test with fake data
    fake_results = [
        {
            "port": 22, "status": "open", "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu",
            "risk_level": "Critical", "risk_score": 9.8,
            "recommendation": "Disable root login, enforce key-based auth.",
            "cves": [
                {"id": "CVE-2023-38408", "cvss_score": 9.8,
                 "severity": "Critical", "description": "RCE via ssh-agent"},
                {"id": "CVE-2021-41617", "cvss_score": 7.0,
                 "severity": "High", "description": "Privilege escalation in sshd"},
            ]
        },
        {
            "port": 80, "status": "open", "service": "HTTP",
            "banner": "Apache/2.4.49",
            "risk_level": "Critical", "risk_score": 9.8,
            "recommendation": "Enforce HTTPS, keep Apache patched.",
            "cves": [
                {"id": "CVE-2021-41773", "cvss_score": 9.8,
                 "severity": "Critical", "description": "Path traversal RCE in Apache 2.4.49"},
            ]
        },
        {"port": 443, "status": "filtered", "service": "HTTPS", "banner": ""},
    ]

    generate_report(fake_results, "scanme.nmap.org", "45.33.32.156", 1, 100)