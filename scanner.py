import socket
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from correlator import correlate_all
from reporter import generate_report



def resolve_host(host):
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        return None


def grab_banner(host, port , timeout=1.5):
    """ After confirming a port is open , attemppt to read the service banner 
        some services send banners immedialty (ssh, smtp, ftp)
        others need a propt first (HTTP)
        Returns the banner string or empty string if non available """
    try:
        sock = socket.create_connection((host,port), timeout= timeout)
        # HTTP needs a request before it respinds 
        # all other services we just listen first 
        if port in [80, 8080, 8443, 443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        #recv(1024) reads up to 1024 bytes of response 
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner 
    except Exception:
        return ""


def scan_port(host, port, timeout=1.5):
    """
    Attempt TCP connection .if open , attempt banner grab .
    returns a dict with port, status, and a banner
    phase 2 returns a dict instad of a string
    so we can store structured data for the report later .
    """
    try:
        sock = socket.create_connection((host,port), timeout=timeout)
        sock.close()
        #port is open - now try to get the banner 
        banner = grab_banner(host, port , timeout )
        return {
            "port" : port,
            "status" : "open",
            "banner" : banner,

        }
    except ConnectionRefusedError:
        return { "port": port , "status" : "closed", "banner":""}
    except socket.timeout:
        return { "port": port , "status" : "filtered", "banner":""}
    except OSError as e:
        return { "port": port , "status" : "filtered", "banner":""}
        

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}


def main():
    # argparse builds your command line interface
    # each add_argument defines one flag the user can pass
    parser = argparse.ArgumentParser(
        description="TCP Connect Port Scanner"
    )
    parser.add_argument(
        "--host",
        required=True,
        help="Target hostname or IP address"
    )
    parser.add_argument(
        "--start-port",
        type=int,
        default=1,
        help="First port to scan (default: 1)"
    )
    parser.add_argument(
        "--end-port",
        type=int,
        default=100,
        help="Last port to scan (default: 100)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Seconds to wait per port (default: 1.5)"
    )
    parser.add_argument("--threads", type=int , default = 100,
                        help="Number of concurrent threads (default: 100)")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show closed and filtered ports too"
    )
    parser.add_argument(
    "--report",
    help="Save HTML report to this file (e.g. report.html)"
    )
    args = parser.parse_args()

    # validate port range before touching the network
    if args.start_port > args.end_port:
        print("[ERROR] start-port cannot be greater than end-port")
        sys.exit(1)
    if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
        print("[ERROR] Ports must be between 1 and 65535")
        sys.exit(1)
    if args.threads < 1 or args.threads > 500:
            print("[ERROR] Threads must be between 1 and 500")
            sys.exit(1)

    # resolve hostname once — not once per port
    ip = resolve_host(args.host)
    if ip is None:
        print(f"[ERROR] Cannot resolve hostname: {args.host}")
        sys.exit(1)

    # print scan header
    print(f"\n[INFO] Target   : {args.host} ({ip})")
    print(f"[INFO] Ports    : {args.start_port} - {args.end_port}")
    print(f"[INFO] Threads  : {args.threads}")
    print(f"[INFO] Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    """     print(f"\n{'PORT':<8} {'STATUS':<12}")
    print("-" * 22) """
    
    
    ports_to_scan = range(args.start_port, args.end_port + 1)
    results = []

    """  # counters for the summary
        open_ports = []
        filtered_count = 0
        closed_count = 0

    """
    # the actual scan loop
    #threadPOOLEXcevutor runs scna_port on every port simulanesously 
    # execuotr.submit() sends one port to a worker thread 
    # it returns a future immedialtly without waiting 
    #we collect all futures first , then retreive results 
    with ThreadPoolExecutor(max_workers=args.threads)as executor:
        futures = {
            executor.submit(scan_port, args.host ,port, args.timeout):port
            for port in ports_to_scan 
        }
        #retreive results as each thread completes 
        for future in futures :
            result = future.result()
            results.append(result)
        
    # sort by port number — threads finish in random order
    # without this sort, port 443 might appear before port 22
    results.sort(key=lambda x: x["port"])
    for r in results:
       r["service"] = COMMON_SERVICES.get(r["port"], "unknown")
    
    print("\n[INFO] Running CVE correlation on open ports...")
    results = correlate_all(results)

    print(f"\n{'PORT':<8} {'SERVICE':<12} {'STATUS':<12} {'BANNER'}")
    print("-" * 60)

    open_ports = []
    filtered_count = 0
    closed_count = 0

    for r in results :
        # Fix:
        service = COMMON_SERVICES.get(r["port"], "unknown")
        
        if r["status"] == "open":
            open_ports.append(r)
            # truncate banner to 40 chars so it fits terminal
            banner_display = r["banner"][:40] if r["banner"] else ""
            print(f"{r['port']:<8}{service:<12}{'open':<12}{banner_display}")

           #     print CVE findings
            if r.get("cves"):
                print(f"{'':8}Risk     : {r['risk_level']} (CVSS {r['risk_score']})")
                print(f"{'':8}CVEs     : {len(r['cves'])} found")
                for cve in r["cves"][:3]:
                    print(f"{'':8}  {cve['id']:<18} {cve['cvss_score']:<6} {cve['description'][:45]}")
                print(f"{'':8}Recommend: {r['recommendation'][:55]}...")
            else:
                print(f"{'':8}Risk     : Informational — no CVEs found")

        elif r["status"] == "filtered":
            filtered_count += 1
            # only print filtered if verbose mode is on
            if args.verbose:
                 print(f"{r['port']:<8}{service:<12}{'filtered':<12}")
        else:
            closed_count += 1
            # only print closed if verbose mode is on
            if args.verbose:
                print(f"{r['port']:<8} {service:<12} {'closed':<12}")

            

    # summary after scan finishes
    total = args.end_port - args.start_port + 1
    print(f"\n{'='*60}")
    print(f"[SUMMARY] Scanned  : {total} ports")
    print(f"[SUMMARY] Open     : {len(open_ports)}")
    print(f"[SUMMARY] Filtered : {filtered_count}")
    print(f"[SUMMARY] Closed   : {closed_count}")
    print(f"[INFO]    Finished : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.report:
        generate_report(results, args.host, ip, args.start_port, args.end_port, args.report)

# this block means: only run main() if this file is executed directly
# not if it is imported by another file (which Phase 3 will do)
if __name__ == "__main__":
    
    main()
    