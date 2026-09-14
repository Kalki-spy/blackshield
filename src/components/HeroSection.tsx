import { ArrowRight, Radar, ScanLine, ScanSearch, ShieldAlert, ShieldCheck, Terminal } from "lucide-react";
import { useNavigate, Link } from "react-router-dom";

const THREAT_LOG = [
  { time: "14:02:11", text: "[SCAN] 192.168.1.42 port 443 open", tone: "muted" as const },
  { time: "14:02:14", text: "[CRIT] CVE-2024-3094 detected", tone: "critical" as const },
  { time: "14:02:18", text: "[AUTH] brute-force blocked (src 10.0.0.5)", tone: "muted" as const },
];

export function HeroSection() {
  const navigate = useNavigate();

  return (
    <section className="relative overflow-hidden border-b border-border">
      <div
        className="absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "linear-gradient(180deg, hsl(var(--background)) 3%, transparent 3%), linear-gradient(90deg, hsl(var(--background)) 3%, transparent 3%)",
          backgroundSize: "24px 24px",
        }}
      />

      <div className="relative container mx-auto px-6 py-24 md:py-32 grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
        {/* Left column — copy + CTAs + live threat log */}
        <div className="flex flex-col gap-6">
          <h1 className="font-sans font-bold text-4xl md:text-5xl lg:text-[60px] leading-[1.05] text-foreground">
            Security analysis and controlled attack simulation in one workspace.
          </h1>

          <p className="text-lg text-muted-foreground max-w-xl leading-relaxed">
            Analyse exposed services, identify vulnerabilities and review security findings from a
            single operational workspace built for penetration testers and security teams.
          </p>

          <div className="flex flex-wrap items-center gap-4 pt-2 pb-2">
            <button
              onClick={() => navigate("/auth")}
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-medium text-base px-6 py-3 rounded-md transition-colors"
            >
              Start free workspace
            </button>
            <Link
              to="/docs"
              className="flex items-center gap-1 text-muted-foreground hover:text-foreground text-base py-3 transition-colors"
            >
              View documentation
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="bg-card border border-border rounded-md p-[17px] max-w-md flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-primary" />
              <span className="font-sans font-semibold text-xs text-muted-foreground tracking-[0.6px] uppercase">
                Live threat log
              </span>
            </div>
            <div className="flex flex-col gap-2">
              {THREAT_LOG.map((line) => (
                <div key={line.text} className="flex gap-3 font-mono text-xs">
                  <span className="text-muted-foreground/40 shrink-0">{line.time}</span>
                  <span className={line.tone === "critical" ? "text-destructive" : "text-muted-foreground"}>
                    {line.text}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: workspace preview panel (replaces the decorative Figma
            illustration — see chat notes on reproducing hand-drawn art) */}
        <div className="hidden lg:flex justify-center items-start pt-4">
          <div className="w-full max-w-[480px] bg-card border border-border rounded-lg shadow-2xl overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-secondary">
              <span className="h-2.5 w-2.5 rounded-full bg-destructive" />
              <span className="h-2.5 w-2.5 rounded-full bg-warning" />
              <span className="h-2.5 w-2.5 rounded-full bg-success" />
              <span className="ml-2 text-xs font-mono text-muted-foreground">workspace — sandbox-03</span>
            </div>
            <div className="p-5 flex flex-col gap-4">
              <div className="flex items-center gap-3 text-sm">
                <ScanSearch className="h-4 w-4 text-primary" />
                <span className="text-foreground font-medium">Nmap</span>
                <span className="ml-auto font-mono text-xs text-muted-foreground">45%</span>
              </div>
              <div className="h-1 rounded-full bg-muted overflow-hidden">
                <div className="h-full w-[45%] bg-primary rounded-full" />
              </div>
              <div className="flex items-center gap-3 text-sm pt-2">
                <ShieldAlert className="h-4 w-4 text-destructive" />
                <span className="text-foreground font-medium">Critical finding</span>
              </div>
              <p className="text-xs text-muted-foreground font-mono pl-7 -mt-2">
                SQL injection in login parameter
              </p>
              <div className="flex items-center gap-3 text-sm pt-2">
                <Terminal className="h-4 w-4 text-muted-foreground" />
                <span className="text-foreground font-medium">3 scans active</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
