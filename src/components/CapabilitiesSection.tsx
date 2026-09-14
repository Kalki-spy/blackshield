import { Link } from "react-router-dom";
import {
  Network, Globe, Crosshair, KeyRound, Eye, GraduationCap,
} from "lucide-react";

interface Capability {
  title: string;
  description: string;
  icon: typeof Network;
  items: { label: string; to: string }[];
  size: "lg" | "sm";
}

const capabilities: Capability[] = [
  {
    title: "Reconnaissance",
    description: "Map networks and enumerate assets before testing begins.",
    icon: Network,
    size: "lg",
    items: [
      { label: "Network Analyzer", to: "/dashboard/tools/network-analyzer" },
      { label: "Port Scanner", to: "/dashboard/tools/port-scanner" },
      { label: "Nmap", to: "/dashboard/tools/nmap" },
    ],
  },
  {
    title: "Web Security Testing",
    description: "Identify exposure and misconfigurations across web services.",
    icon: Globe,
    size: "lg",
    items: [
      { label: "Directory Scanner", to: "/dashboard/tools/directory-scanner" },
      { label: "Subdomain Finder", to: "/dashboard/tools/subdomain-finder" },
      { label: "SQL Injection Scanner", to: "/dashboard/tools/sqli-scanner" },
    ],
  },
  {
    title: "Penetration Testing",
    description: "Run controlled attacks to validate defenses end to end.",
    icon: Crosshair,
    size: "lg",
    items: [
      { label: "Metasploit", to: "/dashboard/tools/metasploit" },
      { label: "Firewall Tester", to: "/dashboard/tools/firewall-tester" },
      { label: "DDoS Simulation", to: "/dashboard/tools/ddos-simulator" },
    ],
  },
  {
    title: "Credential Security",
    description: "Audit passwords and hashes to strengthen authentication posture.",
    icon: KeyRound,
    size: "sm",
    items: [
      { label: "Hashcat", to: "/dashboard/tools/hashcat" },
      { label: "Password Auditor", to: "/dashboard/tools/password-auditor" },
    ],
  },
  {
    title: "Defensive Analysis",
    description: "Evaluate detection coverage and correlate known vulnerabilities.",
    icon: Eye,
    size: "sm",
    items: [
      { label: "IDS Analyzer", to: "/dashboard/tools/ids-analyzer" },
      { label: "CVE Scanner", to: "/dashboard/tools/cve-scanner" },
    ],
  },
  {
    title: "Security Training",
    description: "Practice real techniques in safe, isolated environments.",
    icon: GraduationCap,
    size: "sm",
    items: [
      { label: "CTF Scenarios", to: "/dashboard/ctf" },
      { label: "Training Modules", to: "/dashboard/scenarios" },
    ],
  },
];

export function CapabilitiesSection() {
  const large = capabilities.filter((c) => c.size === "lg");
  const small = capabilities.filter((c) => c.size === "sm");

  return (
    <section id="services" className="bg-card py-20">
      <div className="container mx-auto px-6 max-w-[1280px] flex flex-col gap-16">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-4 flex flex-col gap-4">
            <h2 className="font-sans font-bold text-[30px] leading-9 text-foreground">What you can do</h2>
            <p className="text-muted-foreground text-base leading-6">
              BlackShield combines reconnaissance, web security testing and penetration testing in one place.
            </p>
          </div>
          <div className="lg:col-span-8 grid grid-cols-1 sm:grid-cols-3 gap-6">
            {large.map((c) => (
              <div key={c.title} className="bg-background border border-border rounded-lg p-6 flex flex-col gap-1 shadow-[0px_4px_6px_rgba(0,0,0,0.3)]">
                <c.icon className="h-6 w-6 text-primary mb-3" />
                <h3 className="font-sans font-semibold text-base text-foreground">{c.title}</h3>
                <p className="text-sm text-muted-foreground pt-0.5 pb-2">{c.description}</p>
                <ul className="flex flex-col gap-2">
                  {c.items.map((item) => (
                    <li key={item.label}>
                      <Link to={item.to} className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                        {item.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          {small.map((c) => (
            <div key={c.title} className="bg-background border border-border rounded-lg p-6 flex flex-col gap-2">
              <h4 className="font-sans font-semibold text-base text-foreground">{c.title}</h4>
              <p className="text-sm text-muted-foreground">{c.description}</p>
              <ul className="flex flex-col gap-2 pt-1">
                {c.items.map((item) => (
                  <li key={item.label}>
                    <Link to={item.to} className="text-sm text-muted-foreground hover:text-foreground transition-colors">
                      {item.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
