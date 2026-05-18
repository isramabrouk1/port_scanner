-- cve/cve_db.sql
-- Run: sqlite3 cve.db < cve_db.sql

-- Drop existing table if re-running
DROP TABLE IF EXISTS cves;

-- Create CVE table
CREATE TABLE cves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    service TEXT NOT NULL,
    affected_version TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    references TEXT,
    created_date TEXT
);

-- Create index for fast service/version lookups
CREATE INDEX idx_service_version ON cves(service, affected_version);
CREATE INDEX idx_cvss ON cves(cvss_score DESC);

-- ============================================================================
-- OPENSSH CVEs (8 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2018-15473', 'ssh', 'OpenSSH <=7.7', 5.3, 'MEDIUM', 'OpenSSH through 7.7 allows remote attackers to enumerate valid usernames via timing differences in authentication attempts.', 'https://nvd.nist.gov/vuln/detail/CVE-2018-15473', '2018-08-15'),
('CVE-2021-41617', 'ssh', 'OpenSSH <8.8', 7.0, 'HIGH', 'ssh-agent in OpenSSH before 8.8 has a privilege escalation vulnerability due to improper handling of PKCS#11 providers on Unix systems.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41617', '2021-10-14'),
('CVE-2020-15778', 'ssh', 'OpenSSH <8.4p1', 7.8, 'HIGH', 'scp in OpenSSH before 8.4p1 allows command injection via backtick characters in destination paths when using recursive copies.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-15778', '2020-08-26'),
('CVE-2019-6111', 'ssh', 'OpenSSH 6.2-7.9', 5.8, 'MEDIUM', 'scp client in OpenSSH 6.2 through 7.9 does not properly verify file names, allowing malicious servers to overwrite arbitrary files in the client filesystem.', 'https://nvd.nist.gov/vuln/detail/CVE-2019-6111', '2019-01-10'),
('CVE-2016-20012', 'ssh', 'OpenSSH <7.2', 5.9, 'MEDIUM', 'OpenSSH before 7.2 has a duplicate signature check vulnerability in ssh-rsa that could allow signature verification bypass under specific conditions.', 'https://nvd.nist.gov/vuln/detail/CVE-2016-20012', '2021-12-08'),
('CVE-2023-38408', 'ssh', 'OpenSSH <9.3p2', 8.1, 'HIGH', 'Remote code execution via PKCS#11 provider loading in ssh-agent when using specific library paths on Unix systems.', 'https://nvd.nist.gov/vuln/detail/CVE-2023-38408', '2023-07-19'),
('CVE-2020-14145', 'ssh', 'OpenSSH <8.4', 5.3, 'MEDIUM', 'Observable discrepancy in OpenSSH before 8.4 allows remote attackers to enumerate valid usernames via timing side-channel in authentication.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-14145', '2020-09-23'),
('CVE-2021-28041', 'ssh', 'OpenSSH <8.5', 5.5, 'MEDIUM', 'Double-free vulnerability in ssh-agent allows local users to cause denial of service or potentially execute code via crafted PKCS#11 provider.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-28041', '2021-03-02');

-- ============================================================================
-- APACHE HTTP SERVER CVEs (7 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2021-41773', 'http', 'Apache 2.4.49', 7.5, 'HIGH', 'Path traversal vulnerability via encoded slashes in URLs allows remote attackers to access files outside document root.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773', '2021-10-05'),
('CVE-2021-42013', 'http', 'Apache 2.4.50', 9.8, 'CRITICAL', 'Path traversal and remote code execution via crafted URL in Apache 2.4.50 when mod_cgi is enabled.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013', '2021-10-07'),
('CVE-2022-31813', 'http', 'Apache 2.4.53', 7.5, 'HIGH', 'Request smuggling vulnerability via malformed Transfer-Encoding headers allows request queue poisoning.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-31813', '2022-06-14'),
('CVE-2021-44790', 'http', 'Apache 2.4.51', 9.8, 'CRITICAL', 'Buffer overflow in mod_lua multipart parser allows remote code execution via crafted POST requests.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44790', '2021-12-20'),
('CVE-2020-11984', 'http', 'Apache 2.4.0-2.4.43', 7.5, 'HIGH', 'mod_proxy_ftp use of uninitialized value allows remote attackers to cause denial of service or information disclosure.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-11984', '2020-07-09'),
('CVE-2019-10092', 'http', 'Apache 2.4.0-2.4.39', 7.5, 'HIGH', 'mod_remoteip with certain configurations allows request smuggling via malformed headers.', 'https://nvd.nist.gov/vuln/detail/CVE-2019-10092', '2019-07-11'),
('CVE-2023-25690', 'http', 'Apache 2.4.55', 6.1, 'MEDIUM', 'mod_proxy request smuggling via improper header validation allows cache poisoning attacks.', 'https://nvd.nist.gov/vuln/detail/CVE-2023-25690', '2023-02-21');

-- ============================================================================
-- VSFTPD / FTP CVEs (4 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2011-2523', 'ftp', 'vsftpd 2.3.4', 10.0, 'CRITICAL', 'Backdoor command execution vulnerability allows remote attackers to execute arbitrary code via crafted USER command.', 'https://nvd.nist.gov/vuln/detail/CVE-2011-2523', '2011-07-03'),
('CVE-2015-1419', 'ftp', 'vsftpd <3.0.3', 5.0, 'MEDIUM', 'Denial of service via crafted FTP commands that cause resource exhaustion in connection handling.', 'https://nvd.nist.gov/vuln/detail/CVE-2015-1419', '2015-02-18'),
('CVE-2021-33560', 'ftp', 'ProFTPD <1.3.7a', 7.5, 'HIGH', 'mod_sftp allows remote attackers to cause denial of service via crafted SSH2_MSG_CHANNEL_REQUEST packets.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-33560', '2021-06-15'),
('CVE-2020-9273', 'ftp', 'ProFTPD <1.3.6b', 7.5, 'HIGH', 'mod_copy module allows unauthorized file copy via SITE CPFR/CPTO commands without authentication.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-9273', '2020-03-11');

-- ============================================================================
-- MYSQL CVEs (4 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2021-2307', 'mysql', 'MySQL 8.0.25 and earlier', 8.8, 'HIGH', 'Server: Security: Privileges subcomponent vulnerability allows high privileged attacker with network access to compromise MySQL via multiple vectors.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-2307', '2021-04-20'),
('CVE-2022-21245', 'mysql', 'MySQL 8.0.27 and earlier', 6.5, 'MEDIUM', 'Server: Replication subcomponent vulnerability allows high privileged attacker with network access to cause denial of service.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-21245', '2022-01-18'),
('CVE-2020-14765', 'mysql', 'MySQL 8.0.20 and earlier', 4.9, 'MEDIUM', 'Server: Security: Privileges subcomponent vulnerability allows high privileged attacker to read unauthorized data via crafted requests.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-14765', '2020-07-14'),
('CVE-2023-21912', 'mysql', 'MySQL 8.0.32 and earlier', 7.2, 'HIGH', 'Server: DML subcomponent vulnerability allows authenticated attacker to cause denial of service via crafted SQL queries.', 'https://nvd.nist.gov/vuln/detail/CVE-2023-21912', '2023-01-17');

-- ============================================================================
-- POSTGRESQL CVEs (3 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2020-25695', 'postgresql', 'PostgreSQL <11.10, <12.5, <13.1', 8.1, 'HIGH', 'Insufficient privilege checks in pg_upgrade and CREATE EXTENSION allow authenticated users to execute arbitrary SQL functions.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-25695', '2020-11-12'),
('CVE-2021-23214', 'postgresql', 'PostgreSQL <11.14, <12.9, <13.5', 7.5, 'HIGH', 'Man-in-the-middle attackers can inject SQL commands via SSL connection downgrade during authentication handshake.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-23214', '2021-11-11'),
('CVE-2022-2625', 'postgresql', 'PostgreSQL <14.4, <13.7, <12.11', 6.5, 'MEDIUM', 'Certain uses of CREATE EXTENSION with untrusted schemas allow privilege escalation via crafted extension scripts.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-2625', '2022-08-11');

-- ============================================================================
-- REDIS CVEs (3 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2022-24735', 'redis', 'Redis <6.2.7, <7.0.0', 9.8, 'CRITICAL', 'Integer overflow in Lua sandbox escape allows remote code execution via crafted Lua script when using specific commands.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-24735', '2022-04-05'),
('CVE-2021-32762', 'redis', 'Redis <6.2.5', 8.8, 'HIGH', 'Integer overflow in heap management allows authenticated users to cause denial of service or potentially execute code via crafted commands.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-32762', '2021-08-03'),
('CVE-2022-3647', 'redis', 'Redis <7.0.5', 7.5, 'HIGH', 'Specially crafted Lua script can cause denial of service via infinite loop when Lua debugger is enabled.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-3647', '2022-10-04');

-- ============================================================================
-- SMB / SAMBA CVEs (3 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2017-7494', 'smb', 'Samba 3.5.0-4.6.4', 9.8, 'CRITICAL', 'Remote code execution via uploading shared library to writable share and loading it via named pipe (EternalRed).', 'https://nvd.nist.gov/vuln/detail/CVE-2017-7494', '2017-05-24'),
('CVE-2020-10730', 'smb', 'Samba <4.12.5', 7.5, 'HIGH', 'Denial of service via crafted SMB1 negotiation request causing memory exhaustion in smbd process.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-10730', '2020-08-11'),
('CVE-2021-44142', 'smb', 'Samba <4.15.4', 6.5, 'MEDIUM', 'Out-of-bounds heap read in vfs_fruit module allows authenticated users to cause information disclosure or denial of service.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44142', '2022-01-25');

-- ============================================================================
-- OPENSSL CVEs (4 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2022-0778', 'openssl', 'OpenSSL <1.1.1n, <3.0.2', 7.5, 'HIGH', 'Infinite loop in BN_mod_sqrt parsing invalid certificates causes denial of service via crafted X.509 certificate.', 'https://nvd.nist.gov/vuln/detail/CVE-2022-0778', '2022-03-15'),
('CVE-2021-3450', 'openssl', 'OpenSSL <1.1.1k', 7.5, 'HIGH', 'CA certificate check bypass in X509_verify_cert() allows man-in-the-middle attacks via malformed certificate chains.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-3450', '2021-03-25'),
('CVE-2020-1971', 'openssl', 'OpenSSL <1.1.1i', 5.9, 'MEDIUM', 'NULL pointer dereference in EDIPARTYNAME parsing causes denial of service via crafted certificate.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-1971', '2020-12-08'),
('CVE-2023-0464', 'openssl', 'OpenSSL <3.0.8', 5.3, 'MEDIUM', 'Excessive resource consumption in certificate verification via policy constraints allows denial of service.', 'https://nvd.nist.gov/vuln/detail/CVE-2023-0464', '2023-02-07');

-- ============================================================================
-- TELNET / LEGACY CVEs (2 total)
-- ============================================================================
INSERT INTO cves (cve_id, service, affected_version, cvss_score, severity, description, references, created_date) VALUES
('CVE-2021-39226', 'telnet', 'Linux telnetd', 9.8, 'CRITICAL', 'Stack-based buffer overflow in telnetd allows remote unauthenticated code execution via crafted environment variables.', 'https://nvd.nist.gov/vuln/detail/CVE-2021-39226', '2021-09-14'),
('CVE-2020-10188', 'telnet', 'telnet-ssl <0.17.2', 8.1, 'HIGH', 'Use-after-free vulnerability in telnet client allows remote attackers to execute arbitrary code via crafted server responses.', 'https://nvd.nist.gov/vuln/detail/CVE-2020-10188', '2020-04-22');