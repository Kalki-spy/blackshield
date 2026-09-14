import { useState } from "react";
import {
  Terminal, Loader2, Search, XCircle,
  CheckCircle, AlertTriangle, Shield, Copy, Download,
  Globe, Wifi, Filter, AlertCircle, Settings
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/metasploit";

type ScanType = "full" | "quick";
type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface CVE {
  id: string; name: string; severity: Severity; cvss: number;
  desc: string; port: number; service: string;
}
interface PortInfo {
  port: number; service: string; state: string; banner: string;
  cves: CVE[]; http_info?: Record<string, string | number>;
}
interface ScanResult {
  target: string; ip: string; scan_type: string; ports_scanned: number;
  open_ports: number; scan_time: number; ports: PortInfo[]; cves: CVE[];
  total_cves: number; critical: number; high: number; medium: number;
  risk_score: number; risk_level: string; http_info: Record<string, string | number>;
}

const SCAN_STEPS: [number, string][] = [
  [8,  "Resolving target..."],
  [18, "Running port scan..."],
  [40, "Probing open services..."],
  [60, "Matching CVE database..."],
  [78, "Grabbing HTTP fingerprints..."],
  [90, "Calculating risk score..."],
];

const sevColor = (s: Severity) => {
  switch (s) {
    case "CRITICAL": return "bg-destructive/20 text-destructive border-destructive/40";
    case "HIGH":     return "bg-orange-500/20 text-orange-400 border-orange-500/40";
    case "MEDIUM":   return "bg-warning/20 text-warning border-warning/40";
    case "LOW":      return "bg-muted text-muted-foreground border-border";
  }
};

const riskColor = (level: string) => {
  switch (level) {
    case "CRITICAL": return "text-destructive border-destructive/50 bg-destructive/10";
    case "HIGH":     return "text-orange-400 border-orange-500/50 bg-orange-500/10";
    case "MEDIUM":   return "text-warning border-warning/50 bg-warning/10";
    case "LOW":      return "text-primary border-primary/50 bg-primary/10";
    case "CLEAN":    return "text-success border-success/50 bg-success/10";
    default:         return "text-muted-foreground border-border bg-muted";
  }
};

export default function MetasploitTool() {
  const [target, setTarget]           = useState("");
  const [scanType, setScanType]       = useState<ScanType>("quick");
  const [showOptions, setShowOptions] = useState(false);
  const [filterSev, setFilterSev]     = useState<"all" | Severity>("all");

  const [scanning, setScanning]       = useState(false);
  const [progress, setProgress]       = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error, setError]             = useState("");
  const [result, setResult]           = useState<ScanResult | null>(null);
  const [copied, setCopied]           = useState(false);

  async function handleScan() {
    const t = target.trim();
    if (!t) return;
    setError(""); setResult(null); setScanning(true); setProgress(0); setFilterSev("all");

    let si = 0;
    const tick = setInterval(() => {
      if (si < SCAN_STEPS.length) {
        setProgress(SCAN_STEPS[si][0]);
        setProgressMsg(SCAN_STEPS[si][1]);
        si++;
      }
    }, scanType === "quick" ? 1500 : 2500);

    try {
      const res  = await fetch(`${BACKEND}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t, scan_type: scanType }),
      });
      const data = await res.json();
      clearInterval(tick);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Scan complete.");
      await new Promise(r => setTimeout(r, 200));
      setResult(data as ScanResult);
    } catch (e: any) {
      clearInterval(tick);
      setError(e.message || "Failed to reach backend. Is metasploit_server.py running?");
    } finally {
      setScanning(false);
    }
  }

  const filteredCVEs = result?.cves.filter(c =>
    filterSev === "all" ? true : c.severity === filterSev
  ) ?? [];

  function exportJSON() {
    if (!result) return;
    const blob = new Blob(
      [JSON.stringify({ ...result, timestamp: new Date().toISOString() }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `msf-scan-${result.target}.json`;
    a.click();
  }

  function copyReport() {
    if (!result) return;
    const lines = [
      `Target: ${result.target} (${result.ip})`,
      `Risk: ${result.risk_level} (score: ${result.risk_score}/100)`,
      `Open Ports: ${result.open_ports}`,
      `CVEs Found: ${result.total_cves} (${result.critical} critical, ${result.high} high)`,
      "",
      "Open Ports:",
      ...result.ports.map(p => `  ${p.port}/tcp  ${p.service}  ${p.banner || ""}`),
      "",
      "CVEs:",
      ...result.cves.map(c => `  [${c.severity}] ${c.id} — ${c.name} (port ${c.port})`),
    ].join("\n");
    navigator.clipboard.writeText(lines).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Security Testing" tool="Metasploit" />
      <ToolHeader title="Metasploit Scanner" description="Port scanning, service fingerprinting, and CVE vulnerability matching" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Scan configuration"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !target.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Scan"}
                </RunButton>
              }
            >
              <Field label="Target IP or hostname">
                <ToolInput
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="192.168.1.1 or example.com"
                  disabled={scanning}
                />
              </Field>

              <button onClick={() => setShowOptions(v => !v)} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start">
                <Settings className="h-3.5 w-3.5" /> Scan options
              </button>

              {showOptions && (
                <div>
                  <label className="block text-xs font-medium text-muted-foreground mb-1.5">Scan type</label>
                  <div className="flex gap-2">
                    {(["quick", "full"] as ScanType[]).map(s => (
                      <button
                        key={s}
                        onClick={() => setScanType(s)}
                        className={`px-3 py-1.5 rounded text-[11px] font-mono font-bold border transition-colors ${
                          scanType === s ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                        }`}
                      >
                        {s === "quick" ? "QUICK (7 ports)" : "FULL (21 ports)"}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />}

            {result && (
              <div
                className={`bg-card border-2 rounded-md p-4 flex flex-col gap-2 ${riskColor(result.risk_level)}`}
              >
                <div className="flex items-center gap-3">
                  <Shield className="h-6 w-6 shrink-0" />
                  <div>
                    <p className="text-[10px] uppercase tracking-widest opacity-80">Risk level</p>
                    <p className="text-lg font-bold">{result.risk_level}</p>
                  </div>
                  <p className="ml-auto text-2xl font-bold">{result.risk_score}<span className="text-sm font-normal">/100</span></p>
                </div>
                <div className="flex gap-2 pt-1">
                  <SecondaryButton onClick={copyReport}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}</SecondaryButton>
                  <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> Export</SecondaryButton>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="Scanner capabilities">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Port Scanning",       "Probes 7–21 common TCP ports for open services"],
                    ["CVE Matching",        "Matches open services against 30+ known vulnerabilities"],
                    ["HTTP Fingerprinting", "Detects server software, missing security headers, HSTS"],
                    ["Risk Scoring",        "Calculates 0–100 risk score based on severity distribution"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Terminal className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-foreground">{title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </ResultsCard>
            )}

            {result && (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><Wifi className="h-4 w-4 text-primary" /><span className="text-xl font-bold text-foreground">{result.open_ports}</span></div>
                    <p className="text-[11px] text-muted-foreground">Open ports</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><AlertTriangle className="h-4 w-4 text-destructive" /><span className="text-xl font-bold text-foreground">{result.critical}</span></div>
                    <p className="text-[11px] text-destructive">Critical CVEs</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><AlertCircle className="h-4 w-4 text-orange-400" /><span className="text-xl font-bold text-foreground">{result.high}</span></div>
                    <p className="text-[11px] text-orange-400">High CVEs</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><Shield className="h-4 w-4 text-foreground/70" /><span className="text-xl font-bold text-foreground">{result.ports_scanned}</span></div>
                    <p className="text-[11px] text-muted-foreground">Ports scanned</p>
                  </div>
                </div>

                <div className="bg-card border border-border rounded-md p-4 flex items-center gap-3 flex-wrap">
                  <Globe className="h-4 w-4 text-primary shrink-0" />
                  <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Target</span>
                  <span className="font-mono text-sm text-foreground">{result.target}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono text-sm text-primary">{result.ip}</span>
                  <span className="ml-auto text-[10px] text-muted-foreground">Scanned in {result.scan_time}s</span>
                </div>

                {result.http_info && Object.keys(result.http_info).length > 0 && (
                  <ResultsCard title="HTTP fingerprint">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2 p-4">
                      {Object.entries(result.http_info).map(([k, v]) => (
                        <div key={k} className="p-2 rounded-md bg-muted/20 border border-border">
                          <p className="text-[9px] text-muted-foreground uppercase tracking-wider">{k.replace(/_/g, " ")}</p>
                          <p className={`font-mono text-xs mt-0.5 ${
                            v === "missing" ? "text-orange-400" : v === "present" ? "text-success" : "text-foreground"
                          }`}>{String(v) || "—"}</p>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard title="Open ports">
                  {result.ports.length === 0 ? (
                    <p className="text-sm text-muted-foreground p-4">No open ports found.</p>
                  ) : (
                    <div className="p-4 space-y-1">
                      <div className="grid grid-cols-12 gap-2 px-3 py-1.5">
                        <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Port</span>
                        <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Service</span>
                        <span className="col-span-5 text-[10px] text-muted-foreground uppercase tracking-widest">Banner</span>
                        <span className="col-span-3 text-[10px] text-muted-foreground uppercase tracking-widest">CVEs</span>
                      </div>
                      {result.ports.map((p, i) => (
                        <div key={i} className="grid grid-cols-12 gap-2 items-center px-3 py-2.5 rounded-md bg-muted/20 border border-border hover:border-primary/20 transition-colors">
                          <div className="col-span-2">
                            <span className="font-mono text-sm font-bold text-primary">{p.port}</span>
                            <span className="font-mono text-[10px] text-muted-foreground">/tcp</span>
                          </div>
                          <div className="col-span-2"><span className="font-mono text-xs text-foreground">{p.service}</span></div>
                          <div className="col-span-5 min-w-0">
                            <span className="font-mono text-[10px] text-muted-foreground truncate block" title={p.banner}>{p.banner || "—"}</span>
                          </div>
                          <div className="col-span-3">
                            {p.cves.length > 0 ? (
                              <span className="flex items-center gap-1 text-[10px] font-mono text-destructive">
                                <AlertTriangle className="h-3 w-3" /> {p.cves.length} CVE{p.cves.length > 1 ? "s" : ""}
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono text-success flex items-center gap-1"><CheckCircle className="h-3 w-3" /> Clean</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </ResultsCard>

                {result.cves.length > 0 && (
                  <ResultsCard
                    title={`Vulnerability report (${result.total_cves} CVEs)`}
                    meta={
                      <div className="flex items-center gap-1 p-1 rounded-md bg-muted/40 border border-border">
                        <Filter className="h-3 w-3 text-muted-foreground ml-1" />
                        {(["all", "CRITICAL", "HIGH", "MEDIUM"] as const).map(f => (
                          <button
                            key={f}
                            onClick={() => setFilterSev(f)}
                            className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold transition-colors ${
                              filterSev === f ? "bg-primary/20 text-primary border border-primary/30" : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            {f}
                          </button>
                        ))}
                      </div>
                    }
                  >
                    <div className="p-4 space-y-2 max-h-[500px] overflow-y-auto">
                      {filteredCVEs.map((cve, i) => (
                        <div key={i} className="p-3 rounded-md bg-muted/10 border border-border hover:border-primary/20 transition-colors">
                          <div className="flex items-start gap-3">
                            <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border shrink-0 mt-0.5 ${sevColor(cve.severity)}`}>{cve.severity}</span>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-mono text-xs font-bold text-foreground">{cve.id}</span>
                                <span className="font-mono text-xs text-primary">{cve.name}</span>
                                <span className="ml-auto font-mono text-[10px] text-muted-foreground">CVSS {cve.cvss} · port {cve.port}/{cve.service}</span>
                              </div>
                              <p className="text-xs text-muted-foreground mt-1">{cve.desc}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}
              </>
            )}
          </>
        }
      />
    </div>
  );
}
