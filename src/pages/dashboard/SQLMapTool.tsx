import { useState } from "react";
import {
  Database, Loader2, XCircle,
  CheckCircle, AlertTriangle, Download,
  Copy, ExternalLink, AlertCircle, Globe,
  Settings, Zap,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/sqlmap";

type Severity = "critical" | "high" | "medium" | "low";
type InjType  = "error_based" | "boolean_blind" | "time_based" | "union_based" | "stacked" | "out_of_band";

interface ParamResult {
  name:          string;
  vulnerable:    boolean;
  finding_count: number;
}

interface Finding {
  parameter:      string;
  payload:        string;
  injection_type: InjType;
  description:    string;
  evidence:       string;
  status_code:    number;
  response_time:  number;
  injected_url:   string;
  severity:       Severity;
  risk:           string;
}

interface ScanResponse {
  target:          string;
  hostname:        string;
  baseline_status: number;
  baseline_time:   number;
  db_detected:     string;
  params_tested:   ParamResult[];
  total_payloads:  number;
  total_findings:  number;
  vulnerable:      boolean;
  findings:        Finding[];
}

const SCAN_STEPS: [number, string][] = [
  [8,  "Resolving target..."],
  [18, "Fetching baseline response..."],
  [30, "Testing error-based payloads..."],
  [45, "Testing boolean-blind payloads..."],
  [60, "Testing time-based payloads..."],
  [72, "Testing UNION-based payloads..."],
  [82, "Analysing responses..."],
  [88, "Correlating findings..."],
];

const SEV_STYLE: Record<Severity, { badge: string; dot: string; label: string }> = {
  critical: { badge: "bg-destructive/10 text-destructive border-destructive/30",          dot: "bg-destructive",    label: "CRITICAL" },
  high:     { badge: "bg-orange-500/10 text-orange-400 border-orange-500/30", dot: "bg-orange-400", label: "HIGH"     },
  medium:   { badge: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning", label: "MEDIUM"   },
  low:      { badge: "bg-primary/10 text-primary border-primary/30",       dot: "bg-primary",   label: "LOW"      },
};

const INJ_LABEL: Record<InjType, string> = {
  error_based:   "Error-Based",
  boolean_blind: "Boolean Blind",
  time_based:    "Time-Based Blind",
  union_based:   "UNION-Based",
  stacked:       "Stacked Queries",
  out_of_band:   "Out-of-Band",
};

const INJ_COLOR: Record<InjType, string> = {
  error_based:   "text-destructive",
  boolean_blind: "text-orange-400",
  time_based:    "text-warning",
  union_based:   "text-purple-400",
  stacked:       "text-destructive",
  out_of_band:   "text-destructive",
};

export default function SQLMapTool() {
  const [targetUrl,    setTargetUrl]    = useState("");
  const [paramList,    setParamList]    = useState("");
  const [level,        setLevel]        = useState(2);
  const [showOptions,  setShowOptions]  = useState(false);
  const [scanning,     setScanning]     = useState(false);
  const [progress,     setProgress]     = useState(0);
  const [progressMsg,  setProgressMsg]  = useState("");
  const [error,        setError]        = useState("");
  const [result,       setResult]       = useState<ScanResponse | null>(null);
  const [activeParam,  setActiveParam]  = useState<string | null>(null);
  const [copied,       setCopied]       = useState(false);

  async function handleScan() {
    const url = targetUrl.trim();
    if (!url) return;

    setError(""); setResult(null); setScanning(true);
    setProgress(0); setActiveParam(null);

    let si = 0;
    let currentPct = 0;

    const tick = setInterval(() => {
      if (si < SCAN_STEPS.length) {
        currentPct = SCAN_STEPS[si][0];
        setProgress(currentPct);
        setProgressMsg(SCAN_STEPS[si][1]);
        si++;
      }
    }, 3000);

    const nudge = setInterval(() => {
      if (currentPct >= 88 && currentPct < 99) {
        currentPct += 1;
        setProgress(p => Math.min(p + 1, 99));
        setProgressMsg("Waiting for injection tests to complete...");
      }
    }, 5000);

    try {
      const params = new URLSearchParams({ url, level: String(level) });
      if (paramList.trim()) params.set("params", paramList.trim());

      const res  = await fetch(`${BACKEND}/scan?${params}`);
      const data = await res.json();
      clearInterval(tick);
      clearInterval(nudge);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Scan complete.");
      await new Promise(r => setTimeout(r, 300));
      setResult(data as ScanResponse);
    } catch (e: unknown) {
      clearInterval(tick);
      clearInterval(nudge);
      const msg = e instanceof Error ? e.message : "Failed to reach backend. Is sqlmap_server.py running?";
      setError(msg);
    } finally {
      setScanning(false);
    }
  }

  const shownFindings = result?.findings.filter(
    f => !activeParam || f.parameter === activeParam
  ) ?? [];

  function exportJSON() {
    if (!result) return;
    const blob = new Blob(
      [JSON.stringify({ ...result, timestamp: new Date().toISOString() }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `sqli-${result.hostname}.json`;
    a.click();
  }

  function copyPayloads() {
    if (!result) return;
    const text = result.findings
      .map(f => `[${f.parameter}] ${f.injection_type}: ${f.payload}`)
      .join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const critCount = result?.findings.filter(f => f.severity === "critical").length ?? 0;
  const highCount = result?.findings.filter(f => f.severity === "high").length ?? 0;

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Web Security" tool="SQL Injection Scanner" />
      <ToolHeader title="SQL Injection Scanner" description="Automatic detection — error-based, boolean blind, time-based & UNION" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Scan configuration"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !targetUrl.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Scan"}
                </RunButton>
              }
            >
              <Field label="Target URL with parameters">
                <ToolInput
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="https://example.com/page?id=1&user=admin"
                  disabled={scanning}
                />
              </Field>

              <button onClick={() => setShowOptions(v => !v)} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start">
                <Settings className="h-3.5 w-3.5" /> Scan options
              </button>

              {showOptions && (
                <div className="flex flex-col gap-4">
                  <Field label="Parameters" hint="Comma-separated, blank = auto-detect">
                    <ToolInput value={paramList} onChange={e => setParamList(e.target.value)} placeholder="id, user, search" />
                  </Field>
                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">
                      Scan level: <span className="text-primary">{["", "LOW", "MEDIUM", "HIGH"][level]}</span>
                    </label>
                    <div className="flex gap-1">
                      {[1, 2, 3].map(l => (
                        <button
                          key={l}
                          onClick={() => setLevel(l)}
                          className={`flex-1 py-1.5 rounded text-[10px] font-mono font-bold border transition-colors ${
                            level === l ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {["LOW", "MEDIUM", "HIGH"][l - 1]}
                        </button>
                      ))}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-1">
                      {level === 1 && "10 payloads — fastest, basic detection"}
                      {level === 2 && "20 payloads — balanced speed and coverage"}
                      {level === 3 && "All payloads — thorough but slower"}
                    </p>
                  </div>
                </div>
              )}

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />}

            {result && (
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Zap className="h-4 w-4 text-primary" /><span className="text-lg font-bold text-foreground">{result.total_payloads}</span></div>
                  <p className="text-[11px] text-muted-foreground">Payloads tested</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Database className="h-4 w-4 text-primary" /><span className="text-lg font-bold text-foreground">{result.params_tested.length}</span></div>
                  <p className="text-[11px] text-primary">Parameters</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><AlertCircle className="h-4 w-4 text-destructive" /><span className="text-lg font-bold text-foreground">{critCount}</span></div>
                  <p className="text-[11px] text-destructive">Critical</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><AlertTriangle className="h-4 w-4 text-orange-400" /><span className="text-lg font-bold text-foreground">{highCount}</span></div>
                  <p className="text-[11px] text-orange-400">High</p>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="Detection methods">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Error-Based",      "Triggers DB error messages to confirm injection and fingerprint DB engine"],
                    ["Boolean Blind",    "Compares true/false responses to detect blind injection points"],
                    ["Time-Based Blind", "Uses SLEEP/WAITFOR delays to confirm blind injection via timing"],
                    ["UNION-Based",      "Attempts UNION SELECT to directly extract database content"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Database className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-foreground">{title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="mx-4 mb-4 p-3 rounded-md bg-warning/5 border border-warning/20 flex gap-2">
                  <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
                  <p className="text-xs text-muted-foreground">
                    <span className="text-warning font-semibold">URL must include query parameters</span>
                    {" "}— e.g. <span className="font-mono text-foreground">https://target.com/page?id=1</span>
                  </p>
                </div>
              </ResultsCard>
            )}

            {result && (
              <>
                <div className={`bg-card border-l-4 rounded-md p-4 flex items-center gap-4 ${
                  result.vulnerable ? "border-l-destructive bg-destructive/5" : "border-l-success bg-success/5"
                }`}>
                  {result.vulnerable
                    ? <XCircle className="h-8 w-8 text-destructive shrink-0" />
                    : <CheckCircle className="h-8 w-8 text-success shrink-0" />}
                  <div className="flex-1 min-w-0">
                    <p className={`font-mono text-lg font-bold ${result.vulnerable ? "text-destructive" : "text-success"}`}>
                      {result.vulnerable ? "VULNERABLE" : "No Injection Detected"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {result.vulnerable
                        ? `${result.total_findings} injection point${result.total_findings !== 1 ? "s" : ""} confirmed across ${result.params_tested.filter(p => p.vulnerable).length} parameter${result.params_tested.filter(p => p.vulnerable).length !== 1 ? "s" : ""}`
                        : `Tested ${result.total_payloads} payloads across ${result.params_tested.length} parameter${result.params_tested.length !== 1 ? "s" : ""} — clean`}
                    </p>
                  </div>
                  {result.db_detected !== "Unknown" && (
                    <div className="px-3 py-1.5 rounded-md bg-purple-500/10 border border-purple-500/30 shrink-0">
                      <p className="text-[10px] text-muted-foreground">DB Engine</p>
                      <p className="font-mono text-sm font-bold text-purple-400">{result.db_detected}</p>
                    </div>
                  )}
                </div>

                <div className="bg-card border border-border rounded-md p-4 flex items-center gap-3 flex-wrap">
                  <Globe className="h-4 w-4 text-primary shrink-0" />
                  <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Target</span>
                  <span className="font-mono text-xs text-foreground truncate max-w-xs" title={result.target}>{result.target}</span>
                  <div className="ml-auto flex gap-4 text-[10px] shrink-0">
                    <span className="text-muted-foreground">Status: <span className="text-success">{result.baseline_status}</span></span>
                    <span className="text-muted-foreground">RT: <span className="text-primary">{result.baseline_time}s</span></span>
                    <span className="text-muted-foreground">Level: <span className="text-primary">{["", "LOW", "MEDIUM", "HIGH"][level]}</span></span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setActiveParam(null)}
                    className={`px-3 py-1 rounded-md text-xs font-mono font-bold border transition-colors ${
                      !activeParam ? "bg-primary/20 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                    }`}
                  >
                    ALL PARAMS
                  </button>
                  {result.params_tested.map(p => (
                    <button
                      key={p.name}
                      onClick={() => setActiveParam(activeParam === p.name ? null : p.name)}
                      className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-mono font-bold border transition-colors ${
                        activeParam === p.name
                          ? "bg-primary/20 text-primary border-primary/30"
                          : p.vulnerable ? "bg-orange-500/10 text-orange-400 border-orange-500/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                      }`}
                    >
                      {p.vulnerable && <span className="h-1.5 w-1.5 rounded-full bg-orange-400" />}
                      {p.name}
                      {p.vulnerable && <span className="opacity-60">×{p.finding_count}</span>}
                    </button>
                  ))}
                </div>

                {result.total_findings > 0 && (
                  <ResultsCard
                    title="Injection points"
                    meta={
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-muted-foreground">({shownFindings.length} shown)</span>
                        <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> JSON</SecondaryButton>
                        <SecondaryButton onClick={copyPayloads}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy payloads"}</SecondaryButton>
                      </div>
                    }
                  >
                    <div className="p-4 space-y-3">
                      {shownFindings.map((f, i) => {
                        const sev = SEV_STYLE[f.severity] ?? SEV_STYLE.low;
                        return (
                          <div key={i} className="rounded-md border border-border bg-muted/10 overflow-hidden hover:border-primary/20 transition-colors">
                            <div className="flex items-center gap-3 px-4 py-2.5 border-b border-border/50 flex-wrap">
                              <span className={`h-2 w-2 rounded-full shrink-0 ${sev.dot}`} />
                              <span className="font-mono text-sm font-bold text-foreground">?<span className="text-primary">{f.parameter}</span>=</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${sev.badge}`}>{sev.label}</span>
                              <span className={`text-xs font-mono font-semibold ${INJ_COLOR[f.injection_type] ?? "text-muted-foreground"}`}>
                                {INJ_LABEL[f.injection_type] ?? f.injection_type}
                              </span>
                              <span className="ml-auto text-[10px] text-muted-foreground shrink-0">{f.status_code} · {f.response_time}s</span>
                            </div>
                            <div className="px-4 py-3 space-y-2">
                              <div>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Payload</p>
                                <div className="px-3 py-2 rounded bg-background border border-border font-mono text-xs text-destructive/90 break-all">{f.payload}</div>
                              </div>
                              <div className="grid grid-cols-2 gap-3">
                                <div>
                                  <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-0.5">Evidence</p>
                                  <p className="text-xs text-foreground">{f.evidence}</p>
                                </div>
                                <div>
                                  <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-0.5">Risk</p>
                                  <p className="text-xs text-foreground">{f.risk}</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-2 min-w-0">
                                <p className="text-[10px] text-muted-foreground uppercase tracking-widest shrink-0">URL</p>
                                <a href={f.injected_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-[10px] font-mono text-primary hover:text-primary/80 truncate">
                                  {f.injected_url.length > 80 ? f.injected_url.slice(0, 80) + "…" : f.injected_url}
                                  <ExternalLink className="h-3 w-3 shrink-0" />
                                </a>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </ResultsCard>
                )}

                {result.total_findings === 0 && (
                  <div className="bg-card border border-border rounded-md p-8 flex flex-col items-center gap-3 text-center">
                    <CheckCircle className="h-10 w-10 text-success" />
                    <p className="text-sm font-bold text-foreground">No SQL Injection Detected</p>
                    <p className="text-xs text-muted-foreground max-w-md">
                      {result.total_payloads} payloads tested across {result.params_tested.length} parameter{result.params_tested.length !== 1 ? "s" : ""}.
                      No error-based, boolean-blind, time-based, or UNION injection signatures found.
                    </p>
                    <p className="text-[11px] text-muted-foreground mt-1">Try increasing the scan level or add more parameters manually.</p>
                  </div>
                )}
              </>
            )}
          </>
        }
      />
    </div>
  );
}
