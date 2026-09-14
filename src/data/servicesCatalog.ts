// Service category pages shown at /services/:slug.
// These mirror the same six tool categories used in the sidebar, Tools
// directory, and landing page — no invented services, only what the
// platform actually does. Sample findings are explicitly labeled as
// illustrative, not real scan output (there's no cross-tool findings
// store yet — see /dashboard which explains the same thing).

import { toolsCatalog } from "./toolsCatalog";

export interface ServiceStep { title: string; desc: string }
export interface ServiceCapability { title: string; desc: string }
export interface SampleFinding { severity: "Critical" | "High" | "Medium" | "Informational"; finding: string; endpoint: string; tool: string }

export interface ServiceCategory {
  slug: string;
  title: string;
  tagline: string;
  atAGlance: { includedTools: number; duration: string; skillLevel: string; output: string };
  capabilities: ServiceCapability[];
  sampleFindings: SampleFinding[];
}

const STEPS: ServiceStep[] = [
  { title: "Add target", desc: "Provide a URL, domain, or IP within your authorized scope." },
  { title: "Select checks", desc: "Choose which tool and parameters to run against the target." },
  { title: "Review evidence", desc: "Inspect the request/response data behind each result." },
  { title: "Export findings", desc: "Share a structured report with your team." },
];

export const serviceCategories: ServiceCategory[] = [
  {
    slug: "reconnaissance",
    title: "Reconnaissance",
    tagline: "Map networks and enumerate assets before testing begins — hosts, ports, services and subdomains, all in one workflow.",
    atAGlance: { includedTools: 5, duration: "10-30 min per target", skillLevel: "Beginner-Intermediate", output: "Host & asset inventory" },
    capabilities: [
      { title: "Host discovery", desc: "Identify live hosts and resolve DNS records for a target domain or IP range." },
      { title: "Port & service scanning", desc: "Probe common and custom port ranges with service/version fingerprinting." },
      { title: "Subdomain enumeration", desc: "Combine certificate transparency logs with DNS brute-force to map attack surface." },
      { title: "Content discovery", desc: "Brute-force hidden directories and files with configurable wordlists." },
      { title: "Configurable scan depth", desc: "Choose scan type and intensity depending on the authorization scope of your engagement." },
      { title: "Exportable reports", desc: "Generate a shareable report for stakeholders or downstream analysis." },
    ],
    sampleFindings: [
      { severity: "Informational", finding: "12 open ports discovered", endpoint: "10.0.0.15", tool: "Port Scanner" },
      { severity: "Medium",        finding: "Outdated service banner exposes version", endpoint: "10.0.0.15:21", tool: "Nmap" },
      { severity: "Informational", finding: "18 subdomains resolved",   endpoint: "example.com", tool: "Subdomain Finder" },
    ],
  },
  {
    slug: "web-security",
    title: "Web Security Testing",
    tagline: "Identify exposure, misconfigurations and injection vulnerabilities across web applications and services before they are exploited.",
    atAGlance: { includedTools: 4, duration: "15-40 min per target", skillLevel: "Intermediate", output: "Ranked findings report" },
    capabilities: [
      { title: "Parameter-level testing", desc: "Inspect individual query parameters, headers and form fields for injectable behaviour." },
      { title: "TLS configuration review", desc: "Validate certificate chains, protocol versions and cipher strength against current standards." },
      { title: "Evidence-backed findings", desc: "Every finding includes request/response evidence and a suggested remediation path." },
      { title: "Configurable scan depth", desc: "Choose passive or active checks depending on the authorization scope of your engagement." },
      { title: "Severity-ranked output", desc: "Findings are classified Critical through Informational using a consistent scoring model." },
      { title: "Exportable reports", desc: "Generate a shareable report for stakeholders or downstream remediation tracking." },
    ],
    sampleFindings: [
      { severity: "Critical",      finding: "SQL injection in login parameter",  endpoint: "/api/v1/auth/login", tool: "SQL Injection Scanner" },
      { severity: "High",          finding: "Deprecated TLS 1.0 accepted",       endpoint: "app.example.com:443", tool: "SSL Analyzer" },
      { severity: "Informational", finding: "Certificate expires in 27 days",    endpoint: "app.example.com:443", tool: "SSL Inspector" },
    ],
  },
  {
    slug: "security-testing",
    title: "Security Testing",
    tagline: "Run controlled attacks and resilience checks to validate defenses end to end, from exploit matching to sandboxed traffic simulation.",
    atAGlance: { includedTools: 3, duration: "10-60 min per target", skillLevel: "Advanced", output: "Exploit & resilience report" },
    capabilities: [
      { title: "CVE-matched scanning", desc: "Correlate open ports and service banners against known vulnerability databases." },
      { title: "Firewall rule auditing", desc: "Test live port reachability and review pasted iptables/ufw rules for misconfigurations." },
      { title: "Sandboxed simulation", desc: "Generate controlled traffic patterns against a fixed internal target — never a live host." },
      { title: "Evidence-backed findings", desc: "Every finding includes the exact signal that triggered it and a suggested fix." },
      { title: "Configurable scan depth", desc: "Choose scan mode and intensity depending on the authorization scope of your engagement." },
      { title: "Exportable reports", desc: "Generate a shareable report for stakeholders or downstream remediation tracking." },
    ],
    sampleFindings: [
      { severity: "Critical", finding: "Exposed service matches known CVE",       endpoint: "10.0.0.22:445", tool: "Metasploit" },
      { severity: "High",     finding: "Overly permissive ACCEPT rule on :3389",  endpoint: "10.0.0.22",     tool: "Firewall Tester" },
      { severity: "Medium",   finding: "SYN flood pattern detected in sandbox",   endpoint: "internal-sandbox", tool: "DDoS Simulator" },
    ],
  },
  {
    slug: "credential-security",
    title: "Credential Security",
    tagline: "Audit password strength and hash resilience to strengthen authentication posture before attackers test it for you.",
    atAGlance: { includedTools: 2, duration: "1-10 min per target", skillLevel: "Beginner", output: "Credential strength report" },
    capabilities: [
      { title: "Hash cracking", desc: "Attempt wordlist and mutation-based attacks against a submitted hash." },
      { title: "Entropy analysis", desc: "Score password strength using entropy and estimated crack time." },
      { title: "Policy compliance checks", desc: "Flag passwords that fail common length, character, and reuse policies." },
      { title: "Bulk auditing", desc: "Run the same checks across a list of passwords or hashes at once." },
      { title: "Local-only analysis", desc: "Passwords are analyzed in the browser session and never stored." },
      { title: "Exportable reports", desc: "Generate a shareable report for stakeholders or downstream remediation tracking." },
    ],
    sampleFindings: [
      { severity: "High",          finding: "Password cracked via wordlist attack", endpoint: "submitted hash", tool: "Hashcat" },
      { severity: "Medium",        finding: "Password reused a common pattern",     endpoint: "submitted password", tool: "Password Auditor" },
      { severity: "Informational", finding: "Estimated crack time: under 1 hour",   endpoint: "submitted password", tool: "Password Auditor" },
    ],
  },
  {
    slug: "defensive-analysis",
    title: "Defensive Analysis",
    tagline: "Evaluate detection coverage and correlate known vulnerabilities to understand what your defenses would actually catch.",
    atAGlance: { includedTools: 2, duration: "5-20 min per target", skillLevel: "Intermediate", output: "Detection & CVE report" },
    capabilities: [
      { title: "Multi-engine scanning", desc: "Scan URLs or files across dozens of detection engines for malicious indicators." },
      { title: "CVE correlation", desc: "Look up known vulnerabilities for named software, optionally scoped to a version." },
      { title: "Bulk software audit", desc: "Check multiple software/version pairs against the CVE database in one pass." },
      { title: "Evidence-backed findings", desc: "Every finding lists which engine or database entry triggered it." },
      { title: "Filterable results", desc: "Narrow engine or CVE results by category or severity to focus a review." },
      { title: "Exportable reports", desc: "Generate a shareable report for stakeholders or downstream remediation tracking." },
    ],
    sampleFindings: [
      { severity: "Critical",      finding: "File flagged malicious by multiple engines", endpoint: "uploaded file", tool: "IDS Analyzer" },
      { severity: "High",          finding: "Known CVE matches installed software version", endpoint: "apache 2.4.49", tool: "CVE Scanner" },
      { severity: "Informational", finding: "URL flagged clean across all engines",        endpoint: "example.com", tool: "IDS Analyzer" },
    ],
  },
  {
    slug: "security-training",
    title: "Security Training",
    tagline: "Practice real techniques in safe, isolated environments — capture-the-flag challenges, guided scenarios, and an AI assistant.",
    atAGlance: { includedTools: 3, duration: "Self-paced", skillLevel: "All levels", output: "Completed challenges" },
    capabilities: [
      { title: "CTF challenges", desc: "Solve capture-the-flag style challenges directly inside the platform." },
      { title: "Guided scenarios", desc: "Work through structured training scenarios at your own pace." },
      { title: "AI assistant", desc: "Get contextual help while working through tools or challenges." },
      { title: "No real-world targets", desc: "All training content runs in isolated, sandboxed environments." },
      { title: "Progress at your pace", desc: "Nothing is timed or scored against other users." },
      { title: "Same platform, same tools", desc: "Training uses the same tool set you use for real assessments." },
    ],
    sampleFindings: [],
  },
];

export function getServiceBySlug(slug: string) {
  return serviceCategories.find((s) => s.slug === slug);
}

export function toolsForCategory(slug: string) {
  const cat = toolsCatalog.find((c) => c.id === slug);
  return cat ? cat.tools : [];
}

export const workflowSteps = STEPS;
