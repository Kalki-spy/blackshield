import { useState } from "react";
import {
  FolderSearch, Loader2, Search, XCircle,
  CheckCircle, Lock, Download,
  Copy, ExternalLink, Filter, AlertCircle, Globe,
  FileText, FolderOpen, Settings
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/gobuster";

type ScanMode = "dir" | "file" | "both";
type Flag = "found" | "redirect" | "forbidden" | "auth_required" | "error" | "other";

interface ScanResult {
  url: string;
  path: string;
  status: number;
  flag: Flag;
  size: string;
  type: string;
  redirect: string | null;
  sensitive: boolean;
  scan_type: "dir" | "file";
}

interface ScanResponse {
  target: string;
  hostname: string;
  mode: ScanMode;
  extensions: string[];
  total_probed: number;
  total_found: number;
  flag_counts: Record<string, number>;
  results: ScanResult[];
  timed_out?: boolean;
}

const SCAN_STEPS: [number, string][] = [
  [8,  "Resolving target host..."],
  [18, "Building wordlist..."],
  [30, "Probing directories..."],
  [50, "Scanning for files..."],
  [68, "Checking sensitive paths..."],
  [80, "Analysing responses..."],
  [88, "Finalising results..."],
];

const flagStyle = (flag: Flag) => {
  switch (flag) {
    case "found":        return { badge: "bg-success/10 text-success border-success/30",  dot: "bg-success" };
    case "redirect":     return { badge: "bg-primary/10 text-primary border-primary/30",     dot: "bg-primary"  };
    case "forbidden":    return { badge: "bg-orange-500/10 text-orange-400 border-orange-500/30", dot: "bg-orange-400" };
    case "auth_required":return { badge: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning" };
    case "error":        return { badge: "bg-destructive/10 text-destructive border-destructive/30",        dot: "bg-destructive"   };
    default:             return { badge: "bg-muted text-muted-foreground border-border",         dot: "bg-muted-foreground" };
  }
};

const flagLabel = (flag: Flag) => {
  switch (flag) {
    case "found":         return "FOUND";
    case "redirect":      return "REDIRECT";
    case "forbidden":     return "FORBIDDEN";
    case "auth_required": return "AUTH";
    case "error":         return "ERROR";
    default:              return "OTHER";
  }
};

const statusColor = (code: number) => {
  if (code >= 200 && code < 300) return "text-success";
  if (code >= 300 && code < 400) return "text-primary";
  if (code === 401 || code === 403) return "text-orange-400";
  if (code >= 500) return "text-destructive";
  return "text-muted-foreground";
};

export default function GobusterTool() {
  const [targetUrl, setTargetUrl]     = useState("");
  const [mode, setMode]               = useState<ScanMode>("dir");
  const [extensions, setExtensions]   = useState("php,html,txt,js,json");
  const [threads, setThreads]         = useState(30);
  const [showOptions, setShowOptions] = useState(false);

  const [scanning, setScanning]       = useState(false);
  const [progress, setProgress]       = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error, setError]             = useState("");
  const [result, setResult]           = useState<ScanResponse | null>(null);

  const [filterFlag, setFilterFlag]   = useState<"all" | Flag>("all");
  const [filterSensitive, setFilterSensitive] = useState(false);
  const [copied, setCopied]           = useState(false);

  async function handleScan() {
    const url = targetUrl.trim();
    if (!url) return;

    setError(""); setResult(null); setScanning(true); setProgress(0);
    setFilterFlag("all"); setFilterSensitive(false);

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
      if (currentPct >= 88 && currentPct < 96) {
        currentPct += 1;
        setProgress(p => Math.min(p + 1, 96));
        setProgressMsg("Waiting for scan to complete...");
      }
    }, 4000);

    try {
      const params = new URLSearchParams({
        url,
        mode,
        ext:     extensions,
        threads: String(threads),
      });
      const res  = await fetch(`${BACKEND}/scan?${params}`);
      const data = await res.json();
      clearInterval(tick);
      clearInterval(nudge);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Scan complete.");
      await new Promise(r => setTimeout(r, 300));
      setResult(data as ScanResponse);
    } catch (e: any) {
      clearInterval(tick);
      clearInterval(nudge);
      setError(e.message || "Failed to reach backend. Is gobuster_server.py running?");
    } finally {
      setScanning(false);
    }
  }

  const filtered = result?.results.filter(r => {
    if (filterSensitive && !r.sensitive) return false;
    if (filterFlag !== "all" && r.flag !== filterFlag) return false;
    return true;
  }) ?? [];

  function exportJSON() {
    if (!result) return;
    const blob = new Blob(
      [JSON.stringify({ ...result, timestamp: new Date().toISOString() }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `gobuster-${result.hostname}.json`;
    a.click();
  }

  function exportCSV() {
    if (!result) return;
    const rows = [
      "path,status,flag,size,type,sensitive,redirect",
      ...result.results.map(r =>
        `${r.path},${r.status},${r.flag},${r.size},${r.type},${r.sensitive},${r.redirect ?? ""}`
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `gobuster-${result.hostname}.csv`;
    a.click();
  }

  function copyPaths() {
    if (!result) return;
    navigator.clipboard.writeText(result.results.map(r => r.url).join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const sensitiveCount = result?.results.filter(r => r.sensitive).length ?? 0;

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Reconnaissance" tool="Directory Scanner" />
      <ToolHeader title="Directory Scanner" description="Web content discovery via wordlist brute-force (Gobuster-style)" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Scan configuration"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !targetUrl.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Scan"}
                </RunButton>
              }
            >
              <Field label="Target URL">
                <ToolInput
                  value={targetUrl}
                  onChange={e => setTargetUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="https://example.com"
                  disabled={scanning}
                />
              </Field>

              <button
                onClick={() => setShowOptions(v => !v)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start"
              >
                <Settings className="h-3.5 w-3.5" /> Scan options
              </button>

              {showOptions && (
                <div className="flex flex-col gap-4 pt-1">
                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">Scan mode</label>
                    <div className="flex gap-1">
                      {(["dir", "file", "both"] as ScanMode[]).map(m => (
                        <button
                          key={m}
                          onClick={() => setMode(m)}
                          className={`flex-1 py-1.5 rounded text-[10px] font-mono font-bold transition-colors border ${
                            mode === m
                              ? "bg-primary/15 text-primary border-primary/30"
                              : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {m.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <Field label="Extensions (file mode)">
                    <ToolInput
                      value={extensions}
                      onChange={e => setExtensions(e.target.value)}
                      placeholder="php,html,txt,js"
                      disabled={mode === "dir"}
                    />
                  </Field>

                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">
                      Threads: <span className="text-primary">{threads}</span>
                    </label>
                    <input
                      type="range" min={5} max={50} step={5} value={threads}
                      onChange={e => setThreads(Number(e.target.value))}
                      aria-label="Number of threads"
                      className="w-full accent-primary"
                    />
                    <div className="flex justify-between text-[9px] text-muted-foreground mt-0.5">
                      <span>5</span><span>50</span>
                    </div>
                  </div>
                </div>
              )}

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && (
              <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />
            )}

            {result?.timed_out && (
              <div className="flex items-start gap-2 bg-warning/10 border border-warning/30 rounded-md p-3 text-xs text-warning">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>Scan hit its time budget before finishing every path — showing partial results from what completed. Try fewer threads or a narrower extension list for a full pass.</span>
              </div>
            )}

            {result && (
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Search className="h-4 w-4 text-primary" /><span className="text-lg font-bold text-foreground">{result.total_probed}</span></div>
                  <p className="text-[11px] text-muted-foreground">Probed</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><CheckCircle className="h-4 w-4 text-success" /><span className="text-lg font-bold text-foreground">{result.total_found}</span></div>
                  <p className="text-[11px] text-success">Discovered</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><AlertCircle className="h-4 w-4 text-warning" /><span className="text-lg font-bold text-foreground">{sensitiveCount}</span></div>
                  <p className="text-[11px] text-warning">Sensitive</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Lock className="h-4 w-4 text-orange-400" /><span className="text-lg font-bold text-foreground">{(result.flag_counts["forbidden"] ?? 0) + (result.flag_counts["auth_required"] ?? 0)}</span></div>
                  <p className="text-[11px] text-orange-400">Restricted</p>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="Scan capabilities">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Directory Mode",    "Brute-forces common directory names against the target"],
                    ["File Mode",         "Appends extensions to wordlist to find hidden files"],
                    ["Sensitive Detection","Flags .env, .git, config files, and credentials automatically"],
                    ["Status Analysis",   "Categorises 200/301/401/403/500 responses with context"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <FolderSearch className="h-4 w-4 text-primary mt-0.5 shrink-0" />
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
                <div className="bg-card border border-border rounded-md p-4 flex items-center gap-3 flex-wrap">
                  <Globe className="h-4 w-4 text-primary shrink-0" />
                  <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Target</span>
                  <span className="font-mono text-sm text-foreground">{result.target}</span>
                  <span className="ml-auto text-[10px] text-muted-foreground">
                    Mode: <span className="text-primary">{result.mode.toUpperCase()}</span>
                    {result.mode !== "dir" && <> · Ext: <span className="text-primary">{result.extensions.join(", ")}</span></>}
                  </span>
                </div>

                <div className="flex flex-wrap gap-2">
                  {Object.entries(result.flag_counts).map(([flag, count]) => {
                    const s = flagStyle(flag as Flag);
                    return (
                      <div key={flag} className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-mono ${s.badge}`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
                        {flagLabel(flag as Flag)} <span className="opacity-60">×{count}</span>
                      </div>
                    );
                  })}
                </div>

                <ResultsCard
                  title="Discovered paths"
                  meta={<span>{filtered.length} result{filtered.length !== 1 ? "s" : ""}</span>}
                >
                  <div className="p-4 flex flex-col gap-4">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        onClick={() => setFilterSensitive(v => !v)}
                        className={`flex items-center gap-1 px-2.5 py-1 rounded text-[10px] font-mono font-bold border transition-colors ${
                          filterSensitive
                            ? "bg-warning/20 text-warning border-warning/30"
                            : "bg-muted text-muted-foreground border-border hover:text-foreground"
                        }`}
                      >
                        <AlertCircle className="h-3 w-3" /> SENSITIVE
                      </button>
                      <div className="flex items-center gap-1 p-1 rounded-md bg-muted/40 border border-border">
                        <Filter className="h-3 w-3 text-muted-foreground ml-1" />
                        {(["all", "found", "redirect", "forbidden", "auth_required"] as const).map(f => (
                          <button
                            key={f}
                            onClick={() => setFilterFlag(f)}
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold transition-colors ${
                              filterFlag === f ? "bg-primary/20 text-primary border border-primary/30" : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            {f === "auth_required" ? "AUTH" : f.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      <div className="flex gap-2 ml-auto">
                        <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> JSON</SecondaryButton>
                        <SecondaryButton onClick={exportCSV}><Download className="h-3.5 w-3.5" /> CSV</SecondaryButton>
                        <SecondaryButton onClick={copyPaths}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy URLs"}</SecondaryButton>
                      </div>
                    </div>

                    <div className="grid grid-cols-12 gap-2 px-3 py-1.5">
                      <span className="col-span-5 text-[10px] text-muted-foreground uppercase tracking-widest">Path</span>
                      <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Status</span>
                      <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Flag</span>
                      <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Type</span>
                      <span className="col-span-1 text-[10px] text-muted-foreground uppercase tracking-widest">Size</span>
                    </div>

                    <div className="space-y-1 max-h-[560px] overflow-y-auto pr-1">
                      {filtered.length === 0 ? (
                        <div className="text-center py-10 text-muted-foreground text-sm">No results for this filter.</div>
                      ) : (
                        filtered.map((r, i) => {
                          const style = flagStyle(r.flag);
                          return (
                            <div key={i} className={`grid grid-cols-12 gap-2 items-center px-3 py-2.5 rounded-md border transition-colors group ${
                              r.sensitive ? "bg-warning/5 border-warning/20 hover:border-warning/40" : "bg-muted/20 border-border hover:border-primary/20"
                            }`}>
                              <div className="col-span-5 flex items-center gap-2 min-w-0">
                                {r.scan_type === "dir" ? <FolderOpen className="h-3 w-3 text-muted-foreground shrink-0" /> : <FileText className="h-3 w-3 text-muted-foreground shrink-0" />}
                                <span className="font-mono text-xs text-foreground truncate" title={r.path}>{r.path}</span>
                                {r.sensitive && <div title="Sensitive path"><AlertCircle className="h-3 w-3 text-warning shrink-0" /></div>}
                                <a href={r.url} target="_blank" rel="noopener noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                  <ExternalLink className="h-3 w-3 text-muted-foreground hover:text-primary" />
                                </a>
                              </div>
                              <div className="col-span-2"><span className={`font-mono text-xs font-bold ${statusColor(r.status)}`}>{r.status}</span></div>
                              <div className="col-span-2"><span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${style.badge}`}>{flagLabel(r.flag)}</span></div>
                              <div className="col-span-2 min-w-0">
                                <span className="font-mono text-[10px] text-muted-foreground truncate block" title={r.type}>
                                  {r.type === "—" ? "—" : r.type.split("/").pop()}
                                </span>
                              </div>
                              <div className="col-span-1">
                                <span className="font-mono text-[10px] text-muted-foreground">
                                  {r.size === "—" ? "—" : Number(r.size) > 1024 ? `${(Number(r.size) / 1024).toFixed(1)}k` : `${r.size}b`}
                                </span>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
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
