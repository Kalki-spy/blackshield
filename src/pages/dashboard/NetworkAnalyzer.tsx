import { useState } from "react";
import {
  Globe, Server, Shield, CheckCircle, AlertTriangle, XCircle,
  Loader2, Download, Copy, BarChart2, Lock, Network,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton, Tag,
} from "@/components/tool/ToolUI";
import { useAuth } from "@/contexts/AuthContext";

const BACKEND = "/api";

interface Finding {
  item: string;
  status: "secure" | "warning" | "vulnerable";
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}
interface PortResult {
  port: number; open: boolean; service: string;
  latency: number | null; risk: "low" | "medium" | "high";
}
interface DnsRecord { type: string; value: string }
interface HopResult {
  hop: number; ip: string | null; host: string | null;
  rtt_ms: number | null; status: "intermediate" | "reached" | "timeout";
}
interface NetworkAnalysis {
  host: string; ip: string; timestamp: string;
  dns:  { records: DnsRecord[]; error: string | null };
  ping: { reachable: boolean; min_ms: number | null; avg_ms: number | null; max_ms: number | null; loss_pct: number; error?: string | null; raw?: string; method?: string; note?: string };
  ports:      PortResult[];
  traceroute: HopResult[];
  findings:   Finding[];
  error?: string;
}

const StatusIcon = ({ status }: { status: string }) => {
  if (status === "secure")     return <CheckCircle   className="h-4 w-4 text-success" />;
  if (status === "warning")    return <AlertTriangle className="h-4 w-4 text-warning" />;
  if (status === "vulnerable") return <XCircle       className="h-4 w-4 text-destructive" />;
  return <Shield className="h-4 w-4 text-muted-foreground" />;
};

const statusBadge = (s: string) => {
  if (s === "secure")     return "bg-success/10 text-success border border-success/30";
  if (s === "warning")    return "bg-warning/10 text-warning border border-warning/30";
  if (s === "vulnerable") return "bg-destructive/10 text-destructive border border-destructive/30";
  return "bg-muted text-muted-foreground";
};

const severityBadge = (s: string) => {
  if (s === "low")      return "bg-primary/10 text-primary border border-primary/30";
  if (s === "medium")   return "bg-warning/10 text-warning border border-warning/30";
  if (s === "high")     return "bg-orange-500/10 text-orange-400 border border-orange-500/30";
  if (s === "critical") return "bg-destructive/10 text-destructive border border-destructive/30";
  return "";
};

export default function NetworkAnalyzer() {
  const { user } = useAuth();
  const [hostInput,   setHostInput]   = useState("");
  const [scanning,    setScanning]    = useState(false);
  const [progress,    setProgress]    = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error,       setError]       = useState("");
  const [result,      setResult]      = useState<NetworkAnalysis | null>(null);
  const [showReport,  setShowReport]  = useState(false);
  const [copied,      setCopied]      = useState(false);

  const steps: [number, string][] = [
    [15, "Resolving hostname..."],
    [30, "Running DNS lookup..."],
    [50, "Pinging host..."],
    [70, "Scanning common ports (parallel)..."],
    [88, "Tracing network path..."],
  ];

  async function handleAnalyze() {
    const host = hostInput.trim();
    if (!host) return;
    setError(""); setResult(null); setShowReport(false);
    setScanning(true); setProgress(0); setProgressMsg("");

    let si = 0;
    const tick = setInterval(() => {
      if (si < steps.length) { setProgress(steps[si][0]); setProgressMsg(steps[si][1]); si++; }
    }, 1800);

    try {
      const r    = await fetch(`${BACKEND}/network/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, user_id: user?.id }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — is ddos_server.py running? Try restarting npm run dev");
      const data: NetworkAnalysis = JSON.parse(text);
      if (data.error) throw new Error(data.error);
      setProgress(100); setProgressMsg("Analysis complete.");
      await new Promise(r2 => setTimeout(r2, 400));
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Failed to reach backend. Is ddos_server.py running on port 8775?");
    } finally {
      clearInterval(tick);
      setScanning(false);
    }
  }

  function exportJSON() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `network-analysis-${result.host}.json`; a.click();
  }

  function copyReport() {
    if (!result) return;
    const lines = [
      `Network Analysis: ${result.host} (${result.ip})`,
      `Timestamp: ${result.timestamp}`,
      "",
      "FINDINGS:",
      ...result.findings.map(f => `[${f.status.toUpperCase()}] ${f.item} — ${f.description}`),
      "",
      "OPEN PORTS:",
      ...result.ports.filter(p => p.open).map(p => `  ${p.port}/${p.service}  ${p.latency ?? ""}ms`),
    ].join("\n");
    navigator.clipboard.writeText(lines).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 2000);
    });
  }

  const summary = result?.findings.reduce(
    (a, f) => { a[f.status] = (a[f.status] || 0) + 1; return a; },
    { secure: 0, warning: 0, vulnerable: 0 } as Record<string, number>
  ) ?? { secure: 0, warning: 0, vulnerable: 0 };

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Reconnaissance" tool="Network Analyzer" />
      <ToolHeader
        title="Network Analyzer"
        description="DNS lookup · Ping & RTT · Port scan · Traceroute · Security findings"
      />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Target host"
              description="Enter a hostname or IP address to analyze."
              footer={
                <RunButton onClick={handleAnalyze} disabled={scanning || !hostInput.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                  {scanning ? "Analyzing..." : "Run analysis"}
                </RunButton>
              }
            >
              <Field label="Host">
                <ToolInput
                  value={hostInput}
                  onChange={e => setHostInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleAnalyze()}
                  placeholder="example.com or 192.168.1.1"
                  disabled={scanning}
                />
              </Field>
              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && (
              <StatusCard
                status="Running"
                message={progressMsg}
                progress={progress}
                elapsed=""
              />
            )}

            {result && (
              <div className="bg-card border border-border rounded-md p-4 flex flex-col gap-3">
                <div className="flex items-center gap-3">
                  <div className="h-10 w-10 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                    <Server className="h-5 w-5 text-primary" />
                  </div>
                  <div className="min-w-0">
                    <p className="font-mono text-sm font-bold text-foreground truncate">{result.host}</p>
                    <p className="font-mono text-xs text-muted-foreground truncate">{result.ip}</p>
                  </div>
                </div>
                <span className={`self-start px-2.5 py-1 rounded-md text-xs font-mono font-bold border ${
                  result.ping.reachable
                    ? "bg-success/10 text-success border-success/30"
                    : "bg-destructive/10 text-destructive border-destructive/30"
                }`}>
                  {result.ping.reachable ? "● REACHABLE" : "○ UNREACHABLE"}
                </span>
                {result.ping.reachable && result.ping.avg_ms != null && (
                  <div className="grid grid-cols-3 gap-2">
                    {([
                      ["Min", result.ping.min_ms, "text-success"],
                      ["Avg", result.ping.avg_ms, "text-primary"],
                      ["Max", result.ping.max_ms, "text-orange-400"],
                    ] as [string, number|null, string][]).map(([label, val, cls]) => (
                      <div key={label} className="p-2 rounded-md bg-muted/30 border border-border text-center">
                        <p className={`font-mono text-sm font-bold ${cls}`}>{val != null ? `${val}ms` : "—"}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{label} RTT</p>
                      </div>
                    ))}
                  </div>
                )}
                {result.ping.reachable && result.ping.avg_ms == null && result.ping.note && (
                  <div className="p-2.5 rounded-md bg-muted/20 border border-border">
                    <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">
                      Reachability note
                    </p>
                    <p className="text-xs text-muted-foreground">{result.ping.note}</p>
                  </div>
                )}
                {!result.ping.reachable && (result.ping.error || result.ping.raw) && (
                  <div className="p-2.5 rounded-md bg-muted/20 border border-border">
                    <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">
                      Why ping reported unreachable
                    </p>
                    {result.ping.error && (
                      <p className="text-xs text-destructive font-mono mb-1">{result.ping.error}</p>
                    )}
                    {result.ping.raw && (
                      <pre className="text-[10px] text-muted-foreground font-mono whitespace-pre-wrap break-words">{result.ping.raw}</pre>
                    )}
                  </div>
                )}
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="What we analyze">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["DNS Records",   "A, AAAA, PTR resolution and reverse lookup"],
                    ["Ping / RTT",    "ICMP reachability, min/avg/max round-trip time"],
                    ["Port Scanning", "20 common ports tested in parallel with service ID"],
                    ["Traceroute",    "Hop-by-hop network path to the target host"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Network className="h-4 w-4 text-primary mt-0.5 shrink-0" />
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
                <ResultsCard
                  title="Findings"
                  meta={
                    <div className="flex gap-2">
                      <SecondaryButton onClick={() => setShowReport(r => !r)}>
                        <BarChart2 className="h-3.5 w-3.5" /> {showReport ? "Hide report" : "Full report"}
                      </SecondaryButton>
                      <SecondaryButton onClick={exportJSON}>
                        <Download className="h-3.5 w-3.5" /> Export
                      </SecondaryButton>
                      <SecondaryButton onClick={copyReport}>
                        <Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}
                      </SecondaryButton>
                    </div>
                  }
                >
                  <div className="flex gap-6 px-4 pt-4">
                    {([
                      ["secure",     summary.secure,     "text-success"],
                      ["warning",    summary.warning,    "text-warning"],
                      ["vulnerable", summary.vulnerable, "text-destructive"],
                    ] as [string, number, string][]).map(([label, val, cls]) => (
                      <div key={label}>
                        <div className={`font-mono text-xl font-bold ${cls}`}>{val}</div>
                        <div className="text-[10px] text-muted-foreground capitalize">{label}</div>
                      </div>
                    ))}
                  </div>
                  <div className="space-y-2 p-4">
                    {result.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/10 border border-border hover:border-primary/30 transition-colors">
                        <div className="mt-0.5"><StatusIcon status={f.status} /></div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className="font-mono text-sm font-semibold text-foreground">{f.item}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${statusBadge(f.status)}`}>{f.status.toUpperCase()}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${severityBadge(f.severity)}`}>{f.severity.toUpperCase()}</span>
                          </div>
                          <p className="text-xs text-muted-foreground">{f.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </ResultsCard>

                {result.dns.records.length > 0 && (
                  <ResultsCard title="DNS records">
                    <div className="flex flex-wrap gap-2 p-4">
                      {result.dns.records.map((rec, i) => (
                        <Tag key={i}>{rec.type} {rec.value}</Tag>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard title="Port scan results" meta={`${result.ports.filter(p => p.open).length} open`}>
                  <div className="space-y-1.5 p-4">
                    {result.ports.filter(p => p.open).map(p => (
                      <div key={p.port} className={`flex items-center gap-3 p-2.5 rounded-md border ${
                        p.risk==="high"?"bg-destructive/5 border-destructive/20":
                        p.risk==="medium"?"bg-warning/5 border-warning/20":
                        "bg-muted/20 border-border"
                      }`}>
                        <span className="font-mono text-xs font-bold text-foreground w-14">:{p.port}</span>
                        <span className="font-mono text-xs text-muted-foreground w-24">{p.service}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                          p.risk==="high"?"bg-destructive/10 text-destructive border border-destructive/30":
                          p.risk==="medium"?"bg-warning/10 text-warning border border-warning/30":
                          "bg-success/10 text-success border border-success/30"
                        }`}>OPEN</span>
                        {p.latency != null && <span className="text-xs font-mono text-muted-foreground ml-auto">{p.latency.toFixed(1)} ms</span>}
                        {p.risk==="high" && <AlertTriangle className="h-3.5 w-3.5 text-destructive ml-1 shrink-0" />}
                      </div>
                    ))}
                    {result.ports.filter(p => !p.open).slice(0, 5).map(p => (
                      <div key={p.port} className="flex items-center gap-3 p-2.5 rounded-md bg-muted/10 border border-border/50 opacity-40">
                        <span className="font-mono text-xs text-muted-foreground w-14">:{p.port}</span>
                        <span className="font-mono text-xs text-muted-foreground w-24">{p.service}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-muted text-muted-foreground border border-border">CLOSED</span>
                      </div>
                    ))}
                  </div>
                </ResultsCard>

                <ResultsCard title="Network path — traceroute">
                  <div className="space-y-1.5 p-4">
                    {result.traceroute.map((hop, i) => (
                      <div key={i} className={`flex items-center gap-3 p-2.5 rounded-md border ${
                        hop.status==="reached"?"bg-success/5 border-success/20":"bg-muted/20 border-border"
                      }`}>
                        <span className="font-mono text-xs text-muted-foreground w-6 text-center">{hop.hop}</span>
                        <div className={`h-2 w-2 rounded-full shrink-0 ${
                          hop.status==="timeout"?"bg-muted-foreground/30":hop.status==="reached"?"bg-success":"bg-primary"
                        }`} />
                        <span className="font-mono text-xs text-foreground flex-1 truncate">{hop.host ?? hop.ip ?? "* * *"}</span>
                        {hop.ip && hop.ip !== hop.host && <span className="font-mono text-[10px] text-muted-foreground hidden sm:block">{hop.ip}</span>}
                        {hop.rtt_ms != null
                          ? <span className="font-mono text-xs text-primary ml-auto">{hop.rtt_ms} ms</span>
                          : <span className="font-mono text-xs text-muted-foreground/50 ml-auto">timeout</span>}
                        {hop.status==="reached" && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-success/10 text-success border border-success/30">DEST</span>
                        )}
                      </div>
                    ))}
                  </div>
                </ResultsCard>

                {showReport && (
                  <ResultsCard title="Network security report">
                    <div className="p-4 space-y-4">
                      <p className="text-xs text-muted-foreground">
                        Generated {new Date().toLocaleString()} · <span className="font-mono text-primary">{result.host} ({result.ip})</span>
                      </p>
                      <div className="grid grid-cols-4 gap-3">
                        {([
                          ["Checks",     result.findings.length, "text-foreground"],
                          ["Secure",     summary.secure,         "text-success"],
                          ["Warnings",   summary.warning,        "text-warning"],
                          ["Vulnerable", summary.vulnerable,     "text-destructive"],
                        ] as [string, number, string][]).map(([label, val, cls]) => (
                          <div key={label} className="bg-muted/30 rounded-md p-3 border border-border text-center">
                            <div className={`font-mono text-xl font-bold ${cls}`}>{val}</div>
                            <div className="text-[10px] text-muted-foreground mt-1">{label}</div>
                          </div>
                        ))}
                      </div>
                      <div className="space-y-2">
                        <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide">Recommendations</p>
                        {([
                          ["Close risky ports", "Disable Telnet (23), FTP (21), RDP (3389), VNC (5900) if not required. Use SSH tunnels instead.", "text-destructive", "bg-destructive/5 border-destructive/20", Lock],
                          ["Firewall rules",    "Apply allowlist-based ingress rules. Only expose ports required for public services.",             "text-warning","bg-warning/5 border-warning/20", Shield],
                          ["Best practices",    "Enable DDoS protection at edge, use rate-limiting, configure ICMP filtering and SYN cookies.",     "text-primary",  "bg-primary/5 border-primary/20",   CheckCircle],
                        ] as [string, string, string, string, any][]).map(([title, desc, tc, bg, Icon]) => (
                          <div key={title} className={`flex gap-3 p-3 rounded-md border ${bg}`}>
                            <Icon className={`h-4 w-4 ${tc} mt-0.5 shrink-0`} />
                            <div>
                              <p className={`text-xs font-semibold ${tc} mb-0.5`}>{title}</p>
                              <p className="text-xs text-muted-foreground">{desc}</p>
                            </div>
                          </div>
                        ))}
                      </div>
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
