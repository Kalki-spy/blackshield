import { useState } from "react";
import { Shield, Server, AlertTriangle, CheckCircle, XCircle, Loader2, Code } from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  ToolTextarea, RunButton, ErrorBox, ResultsCard,
} from "@/components/tool/ToolUI";

const BACKEND = "/api";

interface PortProbe { port: number; state: string; latency_ms: number | null; service: string }
interface FwFinding { port: number; service: string; severity: string; issue: string; recommendation: string }
interface TestResult {
  host: string; timestamp: string;
  results: PortProbe[]; findings: FwFinding[];
  summary: { open: number; closed: number; filtered: number; critical_findings: number };
}
interface RuleIssue { line: number; severity: string; issue: string }
interface ParsedRule { line: number; raw: string; action: string | null; port: number | null; issue: string | null }
interface AnalyzeResult {
  parsed: ParsedRule[]; issues: RuleIssue[];
  total_rules: number; accept_rules: number; drop_rules: number;
}
type Tab = "probe" | "rules";

const stateCls = (s: string) => {
  if (s === "open")     return "text-destructive border-destructive/30 bg-destructive/10";
  if (s === "filtered") return "text-warning border-warning/30 bg-warning/10";
  return "text-success border-success/30 bg-success/10";
};

export default function FirewallTester() {
  const [tab, setTab]           = useState<Tab>("probe");
  const [host, setHost]         = useState("");
  const [ports, setPorts]       = useState("");
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<TestResult | null>(null);
  const [rules, setRules]       = useState("");
  const [analyzed, setAnalyzed] = useState<AnalyzeResult | null>(null);
  const [error, setError]       = useState("");

  async function runProbe() {
    const h = host.trim(); if (!h) return;
    setError(""); setResult(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/firewall/test`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host: h, ports: ports.trim() || undefined }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setResult(d);
    } catch (e: any) { setError(e.message || "Failed to reach firewall_server.py (port 8777)"); }
    finally { setLoading(false); }
  }

  async function runAnalyze() {
    if (!rules.trim()) return;
    setError(""); setAnalyzed(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/firewall/analyze`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setAnalyzed(d);
    } catch (e: any) { setError(e.message || "Failed to reach firewall_server.py (port 8777)"); }
    finally { setLoading(false); }
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Security Testing" tool="Firewall Tester" />
      <ToolHeader title="Firewall Rule Tester" description="Live port state probing · Misconfiguration detection · Rule auditing" />

      <div className="flex gap-1 p-1 rounded-md bg-muted/30 border border-border w-fit">
        {(["probe", "rules"] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => { setTab(t); setError(""); }}
            className={`flex items-center gap-1.5 px-4 py-2 rounded text-xs font-medium transition-colors ${
              tab === t ? "bg-primary/20 border border-primary/40 text-primary" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "probe" ? <><Server className="h-3.5 w-3.5" /> Port Probe</> : <><Code className="h-3.5 w-3.5" /> Rule Audit</>}
          </button>
        ))}
      </div>

      <TwoColumn
        left={
          tab === "probe" ? (
            <ConfigCard
              title="Port probe configuration"
              footer={
                <RunButton onClick={runProbe} disabled={loading || !host.trim()}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
                  {loading ? "Probing..." : "Run probe"}
                </RunButton>
              }
            >
              <Field label="Host or IP">
                <ToolInput value={host} onChange={e => setHost(e.target.value)} onKeyDown={e => e.key === "Enter" && !loading && runProbe()} placeholder="Host or IP" disabled={loading} />
              </Field>
              <Field label="Ports" hint="Blank scans all common ports">
                <ToolInput value={ports} onChange={e => setPorts(e.target.value)} placeholder="80,443 or 1-1024" disabled={loading} />
              </Field>
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          ) : (
            <ConfigCard
              title="Firewall rules"
              description="Paste iptables or ufw rules to audit."
              footer={
                <RunButton onClick={runAnalyze} disabled={loading || !rules.trim()}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Code className="h-4 w-4" />}
                  {loading ? "Analyzing..." : "Audit rules"}
                </RunButton>
              }
            >
              <ToolTextarea
                value={rules}
                onChange={e => setRules(e.target.value)}
                rows={10}
                placeholder={"# Paste your iptables or ufw rules here\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 3389 -j ACCEPT\n-A INPUT -j DROP"}
                className="text-xs"
              />
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          )
        }
        right={
          <>
            {tab === "probe" && !result && (
              <ResultsCard title="Results">
                <div className="py-14 text-center text-sm text-muted-foreground">Run a probe to see port states here.</div>
              </ResultsCard>
            )}
            {tab === "rules" && !analyzed && (
              <ResultsCard title="Results">
                <div className="py-14 text-center text-sm text-muted-foreground">Paste rules and audit to see findings here.</div>
              </ResultsCard>
            )}

            {result && tab === "probe" && (
              <>
                <div className="grid grid-cols-4 gap-2">
                  {([
                    ["Open",     result.summary.open,     "text-destructive"],
                    ["Closed",   result.summary.closed,   "text-success"],
                    ["Filtered", result.summary.filtered, "text-warning"],
                    ["Issues",   result.summary.critical_findings, result.summary.critical_findings > 0 ? "text-destructive" : "text-success"],
                  ] as [string, number, string][]).map(([l, v, c]) => (
                    <div key={l} className="bg-card border border-border rounded-md p-3 text-center">
                      <div className={`font-mono text-xl font-bold ${c}`}>{v}</div>
                      <div className="text-[10px] text-muted-foreground mt-1">{l}</div>
                    </div>
                  ))}
                </div>

                {result.findings.length > 0 && (
                  <ResultsCard title="Misconfigurations found">
                    <div className="p-4 space-y-2">
                      {result.findings.map((f, i) => (
                        <div key={i} className={`p-3 rounded-md border ${f.severity === "critical" ? "bg-destructive/5 border-destructive/25" : "bg-warning/5 border-warning/20"}`}>
                          <div className="flex items-center gap-2 mb-1">
                            {f.severity === "critical" ? <XCircle className="h-4 w-4 text-destructive" /> : <AlertTriangle className="h-4 w-4 text-warning" />}
                            <span className="font-mono text-sm font-bold text-foreground">:{f.port} {f.service}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ml-auto ${f.severity === "critical" ? "bg-destructive/10 text-destructive border border-destructive/30" : "bg-warning/10 text-warning border border-warning/30"}`}>{f.severity.toUpperCase()}</span>
                          </div>
                          <p className="text-xs text-muted-foreground">{f.issue}</p>
                          <p className="text-[10px] text-primary mt-1">↳ {f.recommendation}</p>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard title={`Port states — ${result.host}`}>
                  <div className="p-4 space-y-1.5">
                    {result.results.map(p => (
                      <div key={p.port} className="flex items-center gap-3 p-2.5 rounded-md bg-muted/20 border border-border hover:border-primary/20 transition-colors">
                        <div className={`h-2 w-2 rounded-full shrink-0 ${p.state === "open" ? "bg-destructive" : p.state === "filtered" ? "bg-warning" : "bg-success"}`} />
                        <span className="font-mono text-sm font-bold text-foreground w-14">:{p.port}</span>
                        <span className="font-mono text-xs text-muted-foreground w-28">{p.service}</span>
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${stateCls(p.state)}`}>{p.state.toUpperCase()}</span>
                        {p.latency_ms != null && <span className="font-mono text-xs text-muted-foreground ml-auto">{p.latency_ms} ms</span>}
                      </div>
                    ))}
                  </div>
                </ResultsCard>
              </>
            )}

            {analyzed && tab === "rules" && (
              <>
                <div className="grid grid-cols-3 gap-2">
                  {([
                    ["Total rules",   analyzed.total_rules,  "text-foreground"],
                    ["ACCEPT rules",  analyzed.accept_rules, "text-warning"],
                    ["DROP / REJECT", analyzed.drop_rules,   "text-success"],
                  ] as [string, number, string][]).map(([l, v, c]) => (
                    <div key={l} className="bg-card border border-border rounded-md p-3 text-center">
                      <div className={`font-mono text-xl font-bold ${c}`}>{v}</div>
                      <div className="text-[10px] text-muted-foreground mt-1">{l}</div>
                    </div>
                  ))}
                </div>

                {analyzed.issues.length > 0 ? (
                  <ResultsCard title={`Rule issues (${analyzed.issues.length})`}>
                    <div className="p-4 space-y-2">
                      {analyzed.issues.map((iss, i) => (
                        <div key={i} className={`p-3 rounded-md border ${iss.severity === "critical" ? "bg-destructive/5 border-destructive/25" : "bg-orange-500/5 border-orange-500/20"}`}>
                          <div className="flex items-center gap-2 mb-1">
                            <XCircle className={`h-4 w-4 ${iss.severity === "critical" ? "text-destructive" : "text-orange-400"}`} />
                            <span className="font-mono text-xs text-muted-foreground">Line {iss.line}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ml-auto ${iss.severity === "critical" ? "bg-destructive/10 text-destructive border border-destructive/30" : "bg-orange-500/10 text-orange-400 border border-orange-500/30"}`}>{iss.severity.toUpperCase()}</span>
                          </div>
                          <p className="text-xs text-destructive font-mono">{iss.issue}</p>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                ) : (
                  <div className="bg-card border border-border rounded-md p-4 flex items-center gap-3">
                    <CheckCircle className="h-5 w-5 text-success" />
                    <p className="text-sm text-success">No obvious rule misconfigurations detected</p>
                  </div>
                )}

                <ResultsCard title="Parsed rules">
                  <div className="p-4 space-y-1">
                    {analyzed.parsed.map(r => (
                      <div key={r.line} className={`flex items-center gap-3 p-2 rounded-md font-mono text-xs border ${r.issue ? "bg-destructive/5 border-destructive/20" : "bg-muted/10 border-border/50"}`}>
                        <span className="text-muted-foreground/60 w-8 text-right">{r.line}</span>
                        {r.action && <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${r.action === "ACCEPT" ? "bg-warning/10 text-warning border-warning/30" : "bg-success/10 text-success border-success/30"}`}>{r.action}</span>}
                        {r.port && <span className="text-primary">:{r.port}</span>}
                        <span className="text-muted-foreground truncate flex-1">{r.raw}</span>
                        {r.issue && <AlertTriangle className="h-3.5 w-3.5 text-destructive shrink-0" />}
                      </div>
                    ))}
                  </div>
                </ResultsCard>
              </>
            )}
          </>
        }
      />
    </div>
  );
}
