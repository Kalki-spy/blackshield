// Guided training scenarios — real step-by-step walkthroughs you can
// actually follow using the tools in this platform, not fake placeholder
// content. Progress is tracked locally per account (checking off steps),
// since there's no backend for scenario progress yet.

export interface ScenarioStep {
  title: string;
  instruction: string;
}

export interface Scenario {
  id: string;
  title: string;
  category: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  summary: string;
  steps: ScenarioStep[];
}

export const scenarios: Scenario[] = [
  {
    id: "recon-basics",
    title: "Reconnaissance Fundamentals",
    category: "Reconnaissance",
    difficulty: "Beginner",
    summary: "Walk through a basic recon workflow against an authorized target using the platform's own tools.",
    steps: [
      { title: "Resolve and ping the target", instruction: "Open Network Analyzer and run it against a target you're authorized to test. Note the resolved IP and whether it's reachable." },
      { title: "Enumerate open ports", instruction: "Open Port Scanner against the same target. Record which ports are open and what services they claim to run." },
      { title: "Run a deeper Nmap scan", instruction: "Use Nmap's Version Detection scan type on the open ports you found to identify service versions." },
      { title: "Check for subdomains", instruction: "If the target is a domain, run Subdomain Finder to see what else is exposed under it." },
      { title: "Summarize your findings", instruction: "Write a short summary: what's exposed, what looks worth investigating further, and why." },
    ],
  },
  {
    id: "web-app-assessment",
    title: "Web Application Assessment Walkthrough",
    category: "Web Security",
    difficulty: "Intermediate",
    summary: "Practice a structured approach to assessing a web application's attack surface.",
    steps: [
      { title: "Map the content", instruction: "Run Directory Scanner against the target URL to discover hidden paths and files." },
      { title: "Check TLS configuration", instruction: "Run SSL Analyzer, then SSL Inspector for a deeper look at the certificate and cipher configuration." },
      { title: "Test for injection points", instruction: "Identify a URL with query parameters and run SQL Injection Scanner against it." },
      { title: "Review the findings together", instruction: "Compare what Directory Scanner, SSL Analyzer, and SQL Injection Scanner each flagged — do any findings connect to each other?" },
    ],
  },
  {
    id: "credential-hygiene",
    title: "Credential Hygiene Audit",
    category: "Credential Security",
    difficulty: "Beginner",
    summary: "Understand how weak passwords and hashes actually fail under attack.",
    steps: [
      { title: "Audit a password", instruction: "Pick a password you think is 'pretty good' and run it through Password Auditor. Read the entropy and estimated crack time." },
      { title: "Try to crack a sample hash", instruction: "Use Hashcat's sample hashes (or your own MD5/SHA1 hash of a common word) and see how quickly a wordlist attack finds it." },
      { title: "Compare weak vs strong", instruction: "Run a second password through Password Auditor — this time a long random passphrase — and compare the results." },
      { title: "Write down what changed", instruction: "Note which specific factors (length, symbols, dictionary words) moved the needle most." },
    ],
  },
  {
    id: "defensive-triage",
    title: "Defensive Triage Basics",
    category: "Defensive Analysis",
    difficulty: "Intermediate",
    summary: "Practice the workflow of checking whether something is actually dangerous before reacting.",
    steps: [
      { title: "Scan a suspicious URL or file", instruction: "Use IDS Analyzer on a URL or file you want to check — this queries multiple detection engines at once." },
      { title: "Check installed software against CVEs", instruction: "Pick a piece of software and version you use, and run it through CVE Scanner to see known vulnerabilities." },
      { title: "Prioritize what you found", instruction: "If CVE Scanner returned multiple results, sort them by severity and CVSS score — which would you patch first, and why?" },
    ],
  },
  {
    id: "controlled-simulation",
    title: "Controlled Simulation & Firewall Testing",
    category: "Security Testing",
    difficulty: "Advanced",
    summary: "Understand resilience testing without ever touching a real production target.",
    steps: [
      { title: "Test firewall reachability", instruction: "Run Firewall Tester's Port Probe against a target you're authorized to test." },
      { title: "Audit a rule set", instruction: "Paste a sample set of iptables or ufw rules into Firewall Tester's Rule Audit tab and review what it flags." },
      { title: "Run a sandboxed DDoS simulation", instruction: "Open DDoS Simulator and run a short simulation — note that it only ever targets the fixed internal sandbox, never a real host." },
      { title: "Read the detection alerts", instruction: "Review what the live detection panel flagged during the simulation and why." },
    ],
  },
];
