/* Sample case file shown when the dashboard can't reach a live API.
 * Shaped exactly like the real /stats, /assets, /vulnerabilities and /chains
 * responses, and built from the CVEs that ship in app/data/cve_catalog.json —
 * so switching to a live backend changes nothing about how the UI reads it. */
window.DEMO = (function () {
  const now = new Date();
  const daysAgo = (n) => new Date(now.getTime() - n * 86400000).toISOString();

  const assets = [
    { id: 1, ip_address: "10.0.1.10", hostname: "web01.corp.local", os: "Linux 5.x", internet_facing: true,  first_seen: daysAgo(9), last_seen: daysAgo(0), vulnerability_count: 3, max_risk_score: 10.0 },
    { id: 2, ip_address: "10.0.1.20", hostname: "ftp01.corp.local", os: "Linux 4.x", internet_facing: false, first_seen: daysAgo(9), last_seen: daysAgo(1), vulnerability_count: 2, max_risk_score: 9.8 },
    { id: 3, ip_address: "10.0.1.30", hostname: "app01.corp.local", os: "Linux 5.x", internet_facing: false, first_seen: daysAgo(6), last_seen: daysAgo(0), vulnerability_count: 2, max_risk_score: 10.0 },
    { id: 4, ip_address: "10.0.2.15", hostname: "vpn-gw.corp.local", os: "FreeBSD (pfSense)", internet_facing: true, first_seen: daysAgo(14), last_seen: daysAgo(2), vulnerability_count: 1, max_risk_score: 8.5 },
    { id: 5, ip_address: "10.0.1.40", hostname: "db01.corp.local", os: "Linux 5.x", internet_facing: false, first_seen: daysAgo(14), last_seen: daysAgo(3), vulnerability_count: 1, max_risk_score: 3.1 },
  ];

  const vulnerabilities = [
    { id: 1, asset_id: 1, cve_id: "CVE-2021-41773", title: "Apache HTTP Server 2.4.49 path traversal and remote code execution", description: "Path normalization flaw allows traversal outside the document root; with mod_cgi enabled it leads to RCE.", cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: "critical", port: 80, protocol: "tcp", service_name: "http", product: "http_server", version: "2.4.49", tags: ["rce", "path-traversal"], sources: ["nmap"], epss: 0.94, in_kev: true, risk_score: 10.0, first_seen: daysAgo(9), last_seen: daysAgo(0) },
    { id: 2, asset_id: 1, cve_id: "CVE-2019-0211", title: "Apache HTTP Server local privilege escalation (scoreboard)", description: "A child worker process can execute code with the privileges of the parent (root) via the scoreboard.", cvss_score: 7.8, cvss_vector: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", severity: "high", port: null, protocol: null, service_name: null, product: "http_server", version: "2.4.38", tags: ["privesc"], sources: ["nessus"], epss: 0.05, in_kev: false, risk_score: 7.8, first_seen: daysAgo(9), last_seen: daysAgo(0) },
    { id: 3, asset_id: 1, cve_id: null, title: "TLS certificate is self-signed", description: "The service presents a self-signed certificate; clients cannot verify identity without manual trust.", cvss_score: 3.1, cvss_vector: null, severity: "low", port: 443, protocol: "tcp", service_name: "https", product: null, version: null, tags: [], sources: ["nmap"], epss: null, in_kev: false, risk_score: 3.1, first_seen: daysAgo(9), last_seen: daysAgo(0) },

    { id: 4, asset_id: 2, cve_id: "CVE-2011-2523", title: "vsftpd 2.3.4 backdoor command execution", description: "The vsftpd 2.3.4 download was backdoored; a crafted username opens a root shell on TCP 6200.", cvss_score: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: "critical", port: 21, protocol: "tcp", service_name: "ftp", product: "vsftpd", version: "2.3.4", tags: ["rce", "backdoor"], sources: ["nmap", "nessus"], epss: 0.21, in_kev: false, risk_score: 9.8, first_seen: daysAgo(9), last_seen: daysAgo(1) },
    { id: 5, asset_id: 2, cve_id: null, title: "Anonymous FTP login enabled", description: "The FTP service accepts anonymous authentication, exposing directory contents without credentials.", cvss_score: 5.0, cvss_vector: null, severity: "medium", port: 21, protocol: "tcp", service_name: "ftp", product: "vsftpd", version: "2.3.4", tags: [], sources: ["nessus"], epss: null, in_kev: false, risk_score: 5.0, first_seen: daysAgo(9), last_seen: daysAgo(1) },

    { id: 6, asset_id: 3, cve_id: "CVE-2021-44228", title: "Apache Log4j2 JNDI lookup remote code execution (Log4Shell)", description: "Unsanitized JNDI lookups in logged strings allow remote code execution via attacker-controlled LDAP.", cvss_score: 10.0, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", severity: "critical", port: 8080, protocol: "tcp", service_name: "http", product: "log4j", version: "2.14.1", tags: ["rce"], sources: ["nessus"], epss: 0.97, in_kev: true, risk_score: 10.0, first_seen: daysAgo(6), last_seen: daysAgo(0) },
    { id: 7, asset_id: 3, cve_id: "CVE-2021-4034", title: "Polkit pkexec local privilege escalation (PwnKit)", description: "A memory-corruption flaw in pkexec lets any local user obtain full root privileges.", cvss_score: 7.8, cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity: "high", port: null, protocol: null, service_name: null, product: "polkit", version: "0.105", tags: ["privesc"], sources: ["nessus"], epss: 0.88, in_kev: true, risk_score: 8.8, first_seen: daysAgo(6), last_seen: daysAgo(0) },

    { id: 8, asset_id: 4, cve_id: "CVE-2014-0160", title: "OpenSSL TLS heartbeat information disclosure (Heartbleed)", description: "A missing bounds check in the TLS heartbeat extension lets remote attackers read process memory, exposing keys and credentials.", cvss_score: 7.5, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", severity: "high", port: 443, protocol: "tcp", service_name: "https", product: "openssl", version: "1.0.1f", tags: ["info-disclosure"], sources: ["nmap"], epss: 0.33, in_kev: true, risk_score: 8.5, first_seen: daysAgo(14), last_seen: daysAgo(2) },

    { id: 9, asset_id: 5, cve_id: null, title: "SMB signing not required", description: "The host accepts unsigned SMB sessions, allowing relay attacks against it.", cvss_score: 3.1, cvss_vector: null, severity: "low", port: 445, protocol: "tcp", service_name: "smb", product: null, version: null, tags: [], sources: ["nessus"], epss: null, in_kev: false, risk_score: 3.1, first_seen: daysAgo(14), last_seen: daysAgo(3) },
  ];

  const chains = [
    {
      id: "chain-1", rule: "lateral-movement",
      title: "Pivot from 10.0.1.10 (web01.corp.local) to 10.0.1.20 (ftp01.corp.local)",
      risk_score: 10.0, severity: "critical",
      explanation: "web01.corp.local is internet-facing and vulnerable to an Apache path-traversal RCE (CVE-2021-41773). Once compromised it sits in the same 10.0.1.0/24 as ftp01.corp.local, which runs a backdoored vsftpd 2.3.4 (CVE-2011-2523) on port 21 and is not directly exposed — a classic pivot path.",
      assets: [{ id: 1, ip_address: "10.0.1.10" }, { id: 2, ip_address: "10.0.1.20" }],
      steps: [
        { order: 1, role: "initial-access", asset_id: 1, ip_address: "10.0.1.10", vulnerability_id: 1, cve_id: "CVE-2021-41773", title: "Apache HTTP Server 2.4.49 path traversal and remote code execution", risk_score: 10.0 },
        { order: 2, role: "lateral-movement", asset_id: 2, ip_address: "10.0.1.20", vulnerability_id: 4, cve_id: "CVE-2011-2523", title: "vsftpd 2.3.4 backdoor command execution", risk_score: 9.8 },
      ],
    },
    {
      id: "chain-2", rule: "foothold-to-privesc",
      title: "Remote foothold to root on 10.0.1.30 (app01.corp.local)",
      risk_score: 9.3, severity: "critical",
      explanation: "app01.corp.local exposes a Log4Shell JNDI injection on port 8080 (CVE-2021-44228), giving remote code execution as the service account. The same host also runs a vulnerable Polkit pkexec (CVE-2021-4034, PwnKit), which hands that foothold full root.",
      assets: [{ id: 3, ip_address: "10.0.1.30" }],
      steps: [
        { order: 1, role: "initial-access", asset_id: 3, ip_address: "10.0.1.30", vulnerability_id: 6, cve_id: "CVE-2021-44228", title: "Apache Log4j2 JNDI lookup remote code execution (Log4Shell)", risk_score: 10.0 },
        { order: 2, role: "privilege-escalation", asset_id: 3, ip_address: "10.0.1.30", vulnerability_id: 7, cve_id: "CVE-2021-4034", title: "Polkit pkexec local privilege escalation (PwnKit)", risk_score: 8.8 },
      ],
    },
    {
      id: "chain-3", rule: "exploited-on-exposed-service",
      title: "Known-exploited flaw directly reachable on 10.0.2.15 (vpn-gw.corp.local)",
      risk_score: 7.8, severity: "high",
      explanation: "vpn-gw.corp.local is internet-facing and runs an OpenSSL build vulnerable to Heartbleed (CVE-2014-0160), which is on CISA's Known Exploited Vulnerabilities list — attackers do not need to discover this one, they already have tooling for it.",
      assets: [{ id: 4, ip_address: "10.0.2.15" }],
      steps: [
        { order: 1, role: "initial-access", asset_id: 4, ip_address: "10.0.2.15", vulnerability_id: 8, cve_id: "CVE-2014-0160", title: "OpenSSL TLS heartbeat information disclosure (Heartbleed)", risk_score: 8.5 },
      ],
    },
  ];

  const by_severity = { critical: 3, high: 3, medium: 1, low: 2 };

  const stats = {
    assets: assets.length,
    vulnerabilities: vulnerabilities.length,
    by_severity,
    known_exploited: vulnerabilities.filter((v) => v.in_kev).length,
    chains: chains.length,
    critical_chains: chains.filter((c) => c.severity === "critical").length,
  };

  return { stats, assets, vulnerabilities, chains };
})();
