import sqlite3
import os
DB_PATH = os.path.join(os.path.dirname(__file__), "data","vuluns.db")

def init_db():
    """
    Create the database file and table if they do not exist .
    safe to call multiple times - craete table if not exists 
    means it skips creation if the table already exists 


    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id          TEXT PRIMARY KEY,
            service     TEXT NOT NULL,
            description TEXT NOT NULL,
            cvss_score  REAL NOT NULL,
            severity    TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")

def seed_db():
    """
    Insert the curated CVE dataset into the database.
    Uses INSERT OR IGNORE so running this twice never creates duplicates.
    INSERT OR IGNORE = if a row with this PRIMARY KEY already exists, skip it.
    """

    cve_data = [
        # format: (CVE_ID, service_keyword, description, cvss_score, severity)
        ("CVE-2016-6515",  "openssh",    "DoS via long passwords in OpenSSH before 7.3", 5.3, "Medium"),
        ("CVE-2023-38408", "openssh",    "Remote code execution via ssh-agent forwarding", 9.8, "Critical"),
        ("CVE-2021-41617", "openssh",    "Privilege escalation flaw in sshd", 7.0, "High"),
        ("CVE-2021-41773", "apache",     "Path traversal and RCE in Apache 2.4.49", 9.8, "Critical"),
        ("CVE-2021-42013", "apache",     "Path traversal bypass in Apache 2.4.49 and 2.4.50", 9.8, "Critical"),
        ("CVE-2022-22720", "apache",     "HTTP request smuggling in Apache 2.4", 9.8, "Critical"),
        ("CVE-2011-2523",  "vsftpd",     "Backdoor command execution in vsftpd 2.3.4", 10.0, "Critical"),
        ("CVE-2021-3618",  "vsftpd",     "ALPACA attack allows cross-protocol response", 7.4, "High"),
        ("CVE-2014-0160",  "openssl",    "Heartbleed memory disclosure vulnerability", 7.5, "High"),
        ("CVE-2022-0778",  "openssl",    "Infinite loop DoS in OpenSSL certificate parsing", 7.5, "High"),
        ("CVE-2022-1292",  "openssl",    "RCE via c_rehash script in OpenSSL", 9.8, "Critical"),
        ("CVE-2012-1182",  "samba",      "Remote code execution in Samba before 3.6.3", 10.0, "Critical"),
        ("CVE-2017-7494",  "samba",      "SambaCry RCE in Samba 3.5.0 and above", 9.8, "Critical"),
        ("CVE-2019-9193",  "postgresql", "RCE via COPY TO/FROM PROGRAM as superuser", 7.2, "High"),
        ("CVE-2022-1552",  "postgresql", "Privilege escalation via autovacuum in PostgreSQL", 8.8, "High"),
        
        # === 35 ADDITIONS (Total: 50) ===
        ("CVE-2020-15778", "openssh",    "Command injection in scp recursive copy via backticks", 7.8, "High"),
        ("CVE-2019-6111",  "openssh",    "scp client file overwrite via malicious server responses", 5.8, "Medium"),
        ("CVE-2021-28041", "openssh",    "ssh-agent double-free vulnerability causing potential code execution", 5.5, "Medium"),
        ("CVE-2021-44790", "apache",     "Buffer overflow in mod_lua allows remote code execution", 9.8, "Critical"),
        ("CVE-2022-31813", "apache",     "HTTP request smuggling via Transfer-Encoding header parsing flaw", 7.5, "High"),
        ("CVE-2020-11984", "apache",     "Uninitialized memory use in mod_proxy_ftp causes DoS", 7.5, "High"),
        ("CVE-2023-25690", "apache",     "mod_proxy request smuggling enables cache poisoning", 6.1, "Medium"),
        ("CVE-2021-3450",  "openssl",    "CA certificate check bypass enables man-in-the-middle attacks", 7.5, "High"),
        ("CVE-2022-3358",  "openssl",    "KDF implementation DoS via crafted EC keys", 7.4, "High"),
        ("CVE-2020-1971",  "openssl",    "NULL pointer dereference in EDIPARTYNAME parsing", 5.9, "Medium"),
        ("CVE-2023-0464",  "openssl",    "Excessive resource consumption during certificate verification", 5.3, "Medium"),
        ("CVE-2021-44142", "samba",      "Out-of-bounds heap read in vfs_fruit module", 6.5, "Medium"),
        ("CVE-2020-10730", "samba",      "SMB1 negotiation DoS via crafted memory exhaustion", 7.5, "High"),
        ("CVE-2022-2031",  "samba",      "Heap-based buffer overflow enables remote code execution", 9.8, "Critical"),
        ("CVE-2021-2307",  "mysql",      "Privilege escalation via malformed authentication requests", 8.8, "High"),
        ("CVE-2022-21245", "mysql",      "Replication component DoS via crafted binary logs", 6.5, "Medium"),
        ("CVE-2020-14765", "mysql",      "Information disclosure via crafted privilege requests", 4.9, "Medium"),
        ("CVE-2023-21912", "mysql",      "DML component DoS via malicious SQL queries", 7.2, "High"),
        ("CVE-2020-25695", "postgresql", "Insufficient privilege checks in pg_upgrade", 8.1, "High"),
        ("CVE-2021-23214", "postgresql", "SSL connection downgrade enables MITM SQL injection", 7.5, "High"),
        ("CVE-2022-2625",  "postgresql", "CREATE EXTENSION privilege escalation via untrusted schemas", 6.5, "Medium"),
        ("CVE-2022-24735", "redis",      "Lua sandbox escape via integer overflow", 9.8, "Critical"),
        ("CVE-2021-32762", "redis",      "Heap overflow in memory management allows code execution", 8.8, "High"),
        ("CVE-2022-3647",  "redis",      "Lua debugger infinite loop causes denial of service", 7.5, "High"),
        ("CVE-2021-23017", "nginx",      "DNS resolver buffer overflow enables remote code execution", 9.8, "Critical"),
        ("CVE-2022-41741", "nginx",      "Memory corruption in mp4 streaming module", 7.5, "High"),
        ("CVE-2023-44487", "nginx",      "HTTP/2 Rapid Reset protocol abuse causes DoS", 7.5, "High"),
        ("CVE-2020-1938",  "tomcat",     "GhostCat file read and potential code execution via AJP", 9.8, "Critical"),
        ("CVE-2021-25329", "tomcat",     "Session ID information disclosure via predictable values", 5.3, "Medium"),
        ("CVE-2022-42252", "tomcat",     "HTTP request smuggling via malformed chunked encoding", 6.5, "Medium"),
        ("CVE-2023-23617", "jenkins",    "Path traversal in plugin upload endpoint", 7.5, "High"),
        ("CVE-2021-21684", "jenkins",    "Sandbox bypass via crafted Groovy scripts", 7.2, "High"),
        ("CVE-2019-10149", "exim",       "Heap buffer overflow enables remote code execution", 9.8, "Critical"),
        ("CVE-2020-28008", "exim",       "Authentication buffer overflow enables privilege escalation", 7.5, "High"),
        ("CVE-2021-39226", "telnet",     "Stack-based buffer overflow in telnetd enables RCE", 9.8, "Critical")
    ]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executemany("""
            INSERT OR IGNORE INTO cves (id, service, description, cvss_score, severity)
            VALUES (?, ?, ?, ?, ?)
        """, cve_data)

    conn.commit()
    conn.close()
    print(f"[DB] Seeded {len(cve_data)} CVEs into database.")


def query_local_db(service_keyword):
    """
    Search the local database for CVEs matching a service keyword.
    service_keyword examples: 'openssh', 'apache', 'vsftpd'
    Returns a list of dicts, one per CVE found.
    Returns empty list if nothing found — never crashes.
    """
    conn = sqlite3.connect(DB_PATH)

    # row_factory makes fetchall() return dicts instead of tuples
    # without this you get (CVE-2016-6515, openssh, ...) 
    # with this you get {"id": "CVE-2016-6515", "service": "openssh", ...}
    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    # ? placeholder prevents SQL injection
    # LOWER() makes the search case-insensitive
    cursor.execute("""
        SELECT * FROM cves
        WHERE LOWER(service) = LOWER(?)
        ORDER BY cvss_score DESC
    """, (service_keyword,))

    rows = cursor.fetchall()
    conn.close()

    # convert Row objects to plain dicts
    return [dict(row) for row in rows]


if __name__ == "__main__":
    # running this file directly initializes and seeds the database
    init_db()
    seed_db()

    # quick test
    results = query_local_db("openssh")
    print(f"\n[TEST] Found {len(results)} CVEs for openssh:")
    for cve in results:
        print(f"  {cve['id']} | CVSS: {cve['cvss_score']} | {cve['severity']} | {cve['description']}")