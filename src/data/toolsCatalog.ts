// Tool catalog for the Tools directory page.
// Descriptions and routes are sourced from the actual pages/endpoints — see
// /src/data/docsContent.ts for the fuller per-tool documentation.

import {
  Network, Radar as PortIcon, Crosshair, FolderSearch, Globe2, ShieldAlert,
  Lock, ShieldCheck, Target, Bug, KeySquare, KeyRound, Eye, AlertOctagon,
} from "lucide-react";

export type ToolStatus = "available" | "requires-scope" | "sandbox-only";

export interface ToolEntry {
  name: string;
  description: string;
  route: string;
  icon: typeof Network;
  status: ToolStatus;
}

export interface ToolCategory {
  id: string;
  label: string;
  tools: ToolEntry[];
}

export const toolsCatalog: ToolCategory[] = [
  {
    id: "reconnaissance",
    label: "Reconnaissance",
    tools: [
      { name: "Network Analyzer", description: "Discover devices, map topology and identify active hosts on a network.", route: "/dashboard/tools/network-analyzer", icon: Network, status: "available" },
      { name: "Port Scanner", description: "Detect open ports and identify running services on target systems.", route: "/dashboard/tools/port-scanner", icon: PortIcon, status: "available" },
      { name: "Nmap", description: "Advanced host discovery and service/version detection engine.", route: "/dashboard/tools/nmap", icon: Crosshair, status: "available" },
      { name: "Directory Scanner", description: "Find hidden directories and files exposed on a web server.", route: "/dashboard/tools/directory-scanner", icon: FolderSearch, status: "available" },
      { name: "Subdomain Finder", description: "Enumerate subdomains to expand attack-surface visibility.", route: "/dashboard/tools/subdomain-finder", icon: Globe2, status: "available" },
    ],
  },
  {
    id: "web-security",
    label: "Web Security",
    tools: [
      { name: "SQL Injection Scanner", description: "Detect injectable parameters and endpoints across web applications.", route: "/dashboard/tools/sqli-scanner", icon: ShieldAlert, status: "available" },
      { name: "SSL Analyzer", description: "Check certificate validity, protocol support and cipher strength.", route: "/dashboard/tools/ssl-analyzer", icon: Lock, status: "available" },
      { name: "SSL Inspector", description: "Deep inspection of certificate chains and TLS handshake behaviour.", route: "/dashboard/tools/ssl-inspector", icon: ShieldCheck, status: "available" },
      { name: "Sniper", description: "Run a focused, targeted assessment against a single endpoint.", route: "/dashboard/tools/sniper", icon: Target, status: "available" },
    ],
  },
  {
    id: "security-testing",
    label: "Security Testing",
    tools: [
      { name: "Metasploit", description: "Authorized exploitation framework for validating vulnerabilities.", route: "/dashboard/tools/metasploit", icon: Bug, status: "requires-scope" },
      { name: "Firewall Tester", description: "Evaluate firewall rules and access-control effectiveness.", route: "/dashboard/tools/firewall-tester", icon: ShieldCheck, status: "available" },
      { name: "DDoS Simulation", description: "Controlled resilience testing against traffic-flood patterns.", route: "/dashboard/tools/ddos-simulator", icon: AlertOctagon, status: "sandbox-only" },
    ],
  },
  {
    id: "credential-security",
    label: "Credential Security",
    tools: [
      { name: "Hashcat", description: "High-performance password hash auditing engine.", route: "/dashboard/tools/hashcat", icon: KeySquare, status: "available" },
      { name: "Password Auditor", description: "Assess password strength against policy and known weaknesses.", route: "/dashboard/tools/password-auditor", icon: KeyRound, status: "available" },
    ],
  },
  {
    id: "defensive-analysis",
    label: "Defensive Analysis",
    tools: [
      { name: "IDS Analyzer", description: "Review intrusion-detection alerts and traffic for gaps in coverage.", route: "/dashboard/tools/ids-analyzer", icon: Eye, status: "available" },
      { name: "CVE Scanner", description: "Correlate detected software with known CVE vulnerabilities.", route: "/dashboard/tools/cve-scanner", icon: AlertOctagon, status: "available" },
    ],
  },
];

export const totalToolCount = toolsCatalog.reduce((sum, cat) => sum + cat.tools.length, 0);

export const statusLabel: Record<ToolStatus, string> = {
  available: "Available",
  "requires-scope": "Requires scope",
  "sandbox-only": "Sandbox only",
};

export const statusClass: Record<ToolStatus, string> = {
  available: "border-success/40 text-success",
  "requires-scope": "border-border text-muted-foreground",
  "sandbox-only": "border-warning/40 text-warning",
};
