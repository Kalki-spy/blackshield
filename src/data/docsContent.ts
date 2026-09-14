// Documentation content for BlackShield.
// Every entry here describes something that actually exists in the codebase —
// the route it lives at, the backend endpoint it calls, and the inputs the
// page actually renders. Nothing here is invented; update this file when a
// tool's inputs or endpoint change so the docs don't drift from the code.

export interface DocSection {
  heading: string;
  body: string[];
  list?: string[];
}

export interface DocEntry {
  slug: string;
  title: string;
  category: string;
  summary: string;
  route?: string;
  endpoint?: string;
  sections: DocSection[];
}

export interface DocCategory {
  id: string;
  label: string;
  entries: DocEntry[];
}

export const docCategories: DocCategory[] = [
  {
    id: "getting-started",
    label: "Getting Started",
    entries: [
      {
        slug: "introduction",
        title: "Introduction to BlackShield",
        category: "getting-started",
        summary: "What BlackShield is and how the platform is organized.",
        sections: [
          {
            heading: "Overview",
            body: [
              "BlackShield is a cybersecurity platform combining a set of hands-on security tools (reconnaissance, web security testing, credential auditing, defensive analysis) with a training area for CTF challenges, guided scenarios, and an AI assistant.",
              "Every tool in the dashboard talks to a real backend service — results come from actually running the scan or check you configure, not from static sample data.",
            ],
          },
        ],
      },
      {
        slug: "accessing-the-platform",
        title: "Accessing the Platform",
        category: "getting-started",
        summary: "How authentication works and where to sign in.",
        route: "/auth",
        sections: [
          {
            heading: "Authentication",
            body: [
              "Access to the dashboard requires an account. The Auth page supports both signing in and creating a new account (email and password), with client-side validation on email format and a minimum password length on sign-up.",
              "Dashboard routes are protected — visiting a dashboard URL without an active session redirects you to Auth first.",
            ],
          },
        ],
      },
      {
        slug: "dashboard-overview",
        title: "Dashboard Overview",
        category: "getting-started",
        summary: "What you see after signing in.",
        route: "/dashboard",
        sections: [
          {
            heading: "Overview",
            body: [
              "The dashboard home shows an activity timeline and platform status. It also carries the Red / Blue / Explorer mode switcher visible throughout the dashboard sidebar — this doesn't change which tools are available, it's a UI mode for framing your current focus (offense, defense, or general exploration).",
            ],
          },
        ],
      },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    entries: [
      {
        slug: "navigation",
        title: "Navigation",
        category: "platform",
        summary: "How the dashboard sidebar is organized.",
        sections: [
          {
            heading: "Overview",
            body: [
              "The dashboard sidebar is split into Main (Dashboard, All Tools), a single Security Tools section with tools grouped by category, Training (CTFs, Scenarios, AI Assistant), and Account (Profile, Settings).",
            ],
            list: ["Reconnaissance", "Web Security", "Security Testing", "Credential Security", "Defensive Analysis"],
          },
        ],
      },
      {
        slug: "profile",
        title: "Profile",
        category: "platform",
        summary: "Your account page.",
        route: "/dashboard/profile",
        sections: [{ heading: "Overview", body: ["Your account details live here."] }],
      },
      {
        slug: "settings",
        title: "Settings",
        category: "platform",
        summary: "Platform and account settings.",
        route: "/dashboard/settings",
        sections: [{ heading: "Overview", body: ["Platform-level and account settings live here."] }],
      },
    ],
  },
  {
    id: "reconnaissance",
    label: "Network & Reconnaissance",
    entries: [
      {
        slug: "network-analyzer",
        title: "Network Analyzer",
        category: "reconnaissance",
        summary: "General network analysis for a single host.",
        route: "/dashboard/tools/network-analyzer",
        endpoint: "GET /network/analyze?host=",
        sections: [
          { heading: "Overview", body: ["Runs a network analysis pass against a single hostname or IP address."] },
          { heading: "Inputs", body: [], list: ["Target hostname or IP address"] },
          { heading: "Workflow", body: ["Enter a host, run the analysis, and review the returned results in the page."] },
        ],
      },
      {
        slug: "port-scanner",
        title: "Port Scanner",
        category: "reconnaissance",
        summary: "Scans a host for open ports.",
        route: "/dashboard/tools/port-scanner",
        endpoint: "POST /network/portscan",
        sections: [
          { heading: "Overview", body: ["Scans a target host across a port range or explicit port list."] },
          {
            heading: "Inputs",
            body: [],
            list: ["Host or IP address", "Ports — a range (e.g. 1-1024) or comma-separated list (e.g. 80,443); left blank scans common ports"],
          },
        ],
      },
      {
        slug: "nmap-scanner",
        title: "Nmap Scanner",
        category: "reconnaissance",
        summary: "Nmap-driven scan with selectable scan types.",
        route: "/dashboard/tools/nmap",
        endpoint: "POST /scan",
        sections: [
          { heading: "Overview", body: ["Runs an Nmap scan against one or more targets with a selectable scan type."] },
          {
            heading: "Inputs",
            body: [],
            list: [
              "Target(s) — IP, CIDR range, or hostname (e.g. 192.168.1.1, 10.0.0.0/24, scanme.nmap.org)",
              "Ports — explicit list, blank uses defaults",
              "Scan type: SYN Scan (-sS, fast stealth half-open scan), Version Detection (-sV, probes services for versions), OS Detection (-O, OS fingerprinting), or Aggressive (-A, OS + version + scripts + traceroute)",
            ],
          },
          { heading: "Results", body: ["Returns discovered ports with service/version details depending on the selected scan type."] },
        ],
      },
      {
        slug: "directory-scanner",
        title: "Directory Scanner",
        category: "reconnaissance",
        summary: "Web content discovery via wordlist brute-force (Gobuster-style).",
        route: "/dashboard/tools/directory-scanner",
        endpoint: "GET /scan",
        sections: [
          { heading: "Overview", body: ["Brute-forces directories and files on a target URL using a wordlist, in the style of Gobuster."] },
          {
            heading: "Inputs",
            body: [],
            list: ["Target URL", "Extensions to check (e.g. php,html,txt,js)", "Thread count (adjustable via slider)"],
          },
          { heading: "Results", body: ["Returns discovered paths, flagging sensitive paths where relevant."] },
        ],
      },
      {
        slug: "subdomain-finder",
        title: "Subdomain Finder",
        category: "reconnaissance",
        summary: "Enumerates subdomains for a domain.",
        route: "/dashboard/tools/subdomain-finder",
        endpoint: "GET /find?domain=",
        sections: [
          { heading: "Overview", body: ["Enumerates subdomains for a given domain."] },
          { heading: "Inputs", body: [], list: ["Domain (e.g. example.com or www.example.com)"] },
          { heading: "Results", body: ["Returns each discovered subdomain along with its resolved IP and reverse DNS where available."] },
        ],
      },
    ],
  },
  {
    id: "web-security",
    label: "Web Security",
    entries: [
      {
        slug: "sql-injection-scanner",
        title: "SQL Injection Scanner",
        category: "web-security",
        summary: "SQLMap-style scan of URL parameters for SQL injection.",
        route: "/dashboard/tools/sqli-scanner",
        endpoint: "GET /scan",
        sections: [
          { heading: "Overview", body: ["Tests URL parameters for SQL injection, in the style of SQLMap."] },
          { heading: "Inputs", body: [], list: ["Target URL with parameters (e.g. https://example.com/page?id=1&user=admin)", "Specific parameters to test (comma-separated, optional)"] },
        ],
      },
      {
        slug: "ssl-analyzer",
        title: "SSL Analyzer",
        category: "web-security",
        summary: "Analyzes a site's TLS/SSL configuration.",
        route: "/dashboard/tools/ssl-analyzer",
        endpoint: "GET /analyze?url=",
        sections: [
          { heading: "Overview", body: ["Analyzes the TLS/SSL configuration of a target URL."] },
          { heading: "Inputs", body: [], list: ["Target URL (e.g. example.com)"] },
        ],
      },
      {
        slug: "ssl-inspector",
        title: "SSL Inspector",
        category: "web-security",
        summary: "Inspects the certificate and TLS setup for a host and port.",
        route: "/dashboard/tools/ssl-inspector",
        endpoint: "POST /ssl/inspect",
        sections: [
          { heading: "Overview", body: ["Inspects the TLS certificate and configuration for a specific host and port."] },
          { heading: "Inputs", body: [], list: ["Hostname (e.g. example.com)", "Port (defaults to 443)"] },
        ],
      },
      {
        slug: "sniper",
        title: "Sniper — Automatic Exploiter",
        category: "web-security",
        summary: "Automated exploitation scan with selectable mode and intensity.",
        route: "/dashboard/tools/sniper",
        endpoint: "GET /scan",
        sections: [
          { heading: "Overview", body: ["Runs an automated exploitation-style scan against a target with a configurable mode and intensity."] },
          {
            heading: "Inputs",
            body: [],
            list: [
              "Target — URL or IP (e.g. https://target.com or 192.168.1.1)",
              "Mode",
              "Intensity: Low (12 ports, fastest), Medium (20 ports, balanced), or High (all 34 ports, thorough)",
            ],
          },
        ],
      },
    ],
  },
  {
    id: "security-testing",
    label: "Security Testing",
    entries: [
      {
        slug: "metasploit",
        title: "Metasploit Scanner",
        category: "security-testing",
        summary: "Metasploit-style scan against a target IP or hostname.",
        route: "/dashboard/tools/metasploit",
        endpoint: "POST /scan",
        sections: [
          { heading: "Overview", body: ["Runs a Metasploit-style scan against a target, with additional options available via the options toggle."] },
          { heading: "Inputs", body: [], list: ["Target IP or hostname (e.g. 192.168.1.1 or example.com)"] },
          { heading: "Results", body: ["Returns discovered ports and service banners."] },
        ],
      },
      {
        slug: "firewall-tester",
        title: "Firewall Rule Tester",
        category: "security-testing",
        summary: "Tests connectivity and audits pasted firewall rules.",
        route: "/dashboard/tools/firewall-tester",
        endpoint: "POST /firewall/test, POST /firewall/analyze",
        sections: [
          { heading: "Overview", body: ["Tests reachability of a host/port range and can separately audit a pasted set of iptables/ufw rules."] },
          {
            heading: "Inputs",
            body: [],
            list: ["Host or IP", "Ports — range or list (blank = all common)", "Firewall rules to audit — pasted iptables/ufw rule text"],
          },
        ],
      },
      {
        slug: "ddos-simulator",
        title: "DDoS Simulator & Detector",
        category: "security-testing",
        summary: "Controlled traffic simulation against a fixed sandbox target, with live detection.",
        route: "/dashboard/tools/ddos-simulator",
        endpoint: "POST /ddos/simulate, GET /ddos/live, POST /ddos/stop",
        sections: [
          {
            heading: "Overview",
            body: [
              "This tool is a controlled security simulation, not an open attack tool. Traffic is only ever generated against a designated internal sandbox target — the backend rejects any other target with an error, so there is no way to point simulated traffic at an arbitrary host.",
            ],
          },
          { heading: "Inputs", body: [], list: ["Simulation duration (seconds)", "Packet rate (packets per second)", "Attack profile"] },
          { heading: "Results", body: ["Live detection alerts and protocol breakdown are shown while the simulation runs."] },
          {
            heading: "Safety / Authorization",
            body: [
              "The sandbox target is fixed and cannot be changed from the UI. The backend enforces this independently of the frontend — requests naming any other target are refused before any traffic is generated.",
            ],
          },
        ],
      },
    ],
  },
  {
    id: "credential-security",
    label: "Credential Security",
    entries: [
      {
        slug: "hashcat",
        title: "Hashcat",
        category: "credential-security",
        summary: "Attempts to crack a hash against a wordlist.",
        route: "/dashboard/tools/hashcat",
        endpoint: "POST /crack",
        sections: [
          { heading: "Overview", body: ["Attempts to crack a submitted hash using a wordlist, in the style of Hashcat."] },
          { heading: "Inputs", body: [], list: ["Hash to crack", "Wordlist — one candidate password per line"] },
        ],
      },
      {
        slug: "password-auditor",
        title: "Password Auditor",
        category: "credential-security",
        summary: "Audits password strength, singly or in bulk.",
        route: "/dashboard/tools/password-auditor",
        endpoint: "POST /password/analyze, POST /password/bulk",
        sections: [
          { heading: "Overview", body: ["Analyzes password strength for a single password or a bulk list."] },
          { heading: "Inputs", body: [], list: ["A single password, or a list of passwords (one per line) for bulk analysis"] },
        ],
      },
    ],
  },
  {
    id: "defensive-analysis",
    label: "Defensive Analysis",
    entries: [
      {
        slug: "ids-analyzer",
        title: "Intrusion Detection System (IDS) Analyzer",
        category: "defensive-analysis",
        summary: "Scans a URL or uploaded file for suspicious indicators.",
        route: "/dashboard/tools/ids-analyzer",
        endpoint: "POST /scan",
        sections: [
          { heading: "Overview", body: ["Scans either a URL or an uploaded file for indicators of malicious activity."] },
          { heading: "Inputs", body: [], list: ["URL to scan, or a file upload"] },
          { heading: "Results", body: ["Report can be copied or downloaded as JSON directly from the page."] },
        ],
      },
      {
        slug: "cve-scanner",
        title: "CVE Vulnerability Scanner",
        category: "defensive-analysis",
        summary: "Looks up known CVEs for named software, singly or in bulk.",
        route: "/dashboard/tools/cve-scanner",
        endpoint: "POST /cve/scan, POST /cve/bulk",
        sections: [
          { heading: "Overview", body: ["Looks up known CVEs for a piece of software, optionally scoped to a version."] },
          { heading: "Inputs", body: [], list: ["Software name (e.g. apache, log4j, openssl)", "Version (optional)", "Bulk mode accepts multiple software/version pairs"] },
        ],
      },
    ],
  },
  {
    id: "training",
    label: "Training",
    entries: [
      { slug: "ctf", title: "CTF", category: "training", summary: "Capture-the-flag challenges.", route: "/dashboard/ctf", sections: [{ heading: "Overview", body: ["Capture-the-flag style challenges within the platform."] }] },
      { slug: "scenarios", title: "Scenarios", category: "training", summary: "Guided training scenarios.", route: "/dashboard/scenarios", sections: [{ heading: "Overview", body: ["Guided training scenarios."] }] },
      { slug: "ai-assistant", title: "AI Assistant", category: "training", summary: "In-platform assistant for training support.", route: "/dashboard/ai-assistant", sections: [{ heading: "Overview", body: ["An in-platform assistant available from the dashboard."] }] },
    ],
  },
];

export const allDocEntries: DocEntry[] = docCategories.flatMap((c) => c.entries);

export function getDocEntry(slug: string): DocEntry | undefined {
  return allDocEntries.find((e) => e.slug === slug);
}
