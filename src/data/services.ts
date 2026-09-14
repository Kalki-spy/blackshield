import { Shield, Bug, Lock, Globe, Server, Code, Eye, Wifi, Database, FileSearch, AlertTriangle, Terminal, Cpu, KeyRound, ShieldCheck, Network, Swords, ShieldHalf, Compass } from "lucide-react";

export interface SubService {
  id: string;
  title: string;
  description: string;
  icon: any;
}

export interface Service {
  id: string;
  title: string;
  description: string;
  icon: any;
  color: string;
  subServices: SubService[];
}

export const services: Service[] = [
  {
    id: "red-team",
    title: "Red Team",
    description: "Offensive security operations — simulate real-world attacks to find and exploit vulnerabilities before adversaries do.",
    icon: Swords,
    color: "text-destructive",
    subServices: [
      { id: "web-app-pentest", title: "Web App Pentesting", description: "OWASP Top 10, SQL injection, XSS, CSRF testing", icon: Globe },
      { id: "network-pentest", title: "Network Pentesting", description: "Internal & external network vulnerability assessment", icon: Network },
      { id: "mobile-pentest", title: "Mobile App Pentesting", description: "iOS & Android application security testing", icon: Cpu },
      { id: "api-pentest", title: "API Security Testing", description: "REST, GraphQL, and SOAP API vulnerability assessment", icon: Code },
      { id: "social-engineering", title: "Social Engineering", description: "Phishing campaigns, pretexting, and physical access testing", icon: Eye },
      { id: "malware-dev", title: "Malware Development", description: "Custom payload creation for evasion testing", icon: Bug },
      { id: "wireless-attacks", title: "Wireless Attacks", description: "WiFi penetration testing, rogue AP, and deauth attacks", icon: Wifi },
      { id: "physical-pentest", title: "Physical Pentesting", description: "Badge cloning, lock picking, and facility intrusion testing", icon: Lock },
    ],
  },
  {
    id: "blue-team",
    title: "Blue Team",
    description: "Defensive security operations — detect, respond, and recover from threats to protect your infrastructure.",
    icon: ShieldHalf,
    color: "text-primary",
    subServices: [
      { id: "soc-monitoring", title: "SOC Monitoring", description: "24/7 security operations center and alert triage", icon: Eye },
      { id: "incident-response", title: "Incident Response", description: "Rapid breach containment and recovery procedures", icon: AlertTriangle },
      { id: "digital-forensics", title: "Digital Forensics", description: "Evidence collection, analysis, and chain-of-custody", icon: FileSearch },
      { id: "threat-hunting", title: "Threat Hunting", description: "Proactive search for hidden threats in your environment", icon: FileSearch },
      { id: "siem-setup", title: "SIEM Configuration", description: "Log aggregation, correlation rules, and dashboards", icon: Database },
      { id: "cloud-security", title: "Cloud Security", description: "AWS, Azure, GCP hardening and misconfiguration detection", icon: Server },
      { id: "ids-ips", title: "IDS/IPS Setup", description: "Intrusion detection and prevention system configuration", icon: Shield },
      { id: "ir-planning", title: "IR Planning", description: "Incident response plan development and tabletop exercises", icon: Terminal },
    ],
  },
  {
    id: "explorer",
    title: "Explorer",
    description: "Learn, train, and level up — hands-on labs, CTF challenges, certifications, and threat intelligence resources.",
    icon: Compass,
    color: "text-cyan",
    subServices: [
      { id: "ctf-challenges", title: "CTF Challenges", description: "Capture the Flag competitions and practice labs", icon: Terminal },
      { id: "security-awareness", title: "Security Awareness", description: "Employee phishing and social engineering training", icon: Eye },
      { id: "secure-dev", title: "Secure Development", description: "Secure coding practices and DevSecOps training", icon: Code },
      { id: "cert-prep", title: "Certification Prep", description: "OSCP, CEH, CompTIA Security+ preparation courses", icon: ShieldCheck },
      { id: "dark-web-monitoring", title: "Dark Web Monitoring", description: "Monitor dark web for leaked credentials and data", icon: Globe },
      { id: "malware-analysis", title: "Malware Analysis", description: "Reverse engineering and behavioral analysis of malware", icon: Bug },
      { id: "ioc-feeds", title: "IoC Feeds", description: "Indicators of Compromise data feeds and alerts", icon: AlertTriangle },
      { id: "threat-intel", title: "Threat Intelligence", description: "Real-time threat landscape briefings and reports", icon: KeyRound },
    ],
  },
];
