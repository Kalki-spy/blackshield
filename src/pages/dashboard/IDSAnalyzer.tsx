import { useState, useRef } from "react";
import {
  ShieldCheck, Link2, Upload, Search, AlertTriangle, CheckCircle,
  XCircle, Clock, ChevronDown, ChevronUp, Copy, Download, RefreshCw,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, ToolInput,
  RunButton, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const API = "/api/ids";

interface EngineResult {
  category: "malicious" | "suspicious" | "harmless" | "undetected";
  result: string | null;
  method: string;
  engine_version: string;
}

interface ScanResult {
  source: string; scan_type: string; target: string; meta: Record<string, any>;
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number; total: number };
  verdict: "malicious" | "suspicious" | "clean";
  results: Record<string, EngineResult>;
  scan_date: string;
}

type Tab = "url" | "file";
type FilterCat = "all" | "malicious" | "suspicious" | "harmless";

const verdictConfig = {
  malicious:  { label: "MALICIOUS",  color: "text-destructive", bg: "bg-destructive/10", border: "border-destructive/40", icon: XCircle },
  suspicious: { label: "SUSPICIOUS", color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/40",  icon: AlertTriangle },
  clean:      { label: "CLEAN",      color: "text-success",     bg: "bg-success/10",     border: "border-success/40",     icon: CheckCircle },
};

const catColor: Record<string, string> = {
  malicious:  "bg-destructive/20 text-destructive border-destructive/30",
  suspicious: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  harmless:   "bg-success/20 text-success border-success/30",
  undetected: "bg-muted text-muted-foreground border-border",
};

export default function IDSAnalyzer() {
  const [tab, setTab] = useState<Tab>("url");
  const [urlInput, setUrlInput] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileContent, setFileContent] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<FilterCat>("all");
  const [showAll, setShowAll] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleScan() {
    setError("");
    setResult(null);
    setShowAll(false);

    const target = tab === "url" ? urlInput.trim() : (fileName || "");
    if (!target) { setError("Please enter a URL or select a file."); return; }

    setLoading(true);
    try {
      const res = await fetch(`${API}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, scan_type: tab }),
      });
      if (!res.ok) {
        const err = await res.text();
        throw new Error(err || `Server returned ${res.status}`);
      }
      const data: ScanResult = await res.json();
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Failed to connect to IDS server. Is it running on port 8774?");
    } finally {
      setLoading(false);
    }
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    setFileName(f.name);
    const reader = new FileReader();
    reader.onload = ev => setFileContent(ev.target?.result as string || "");
    reader.readAsText(f);
  }

  function copyReport() {
    if (!result) return;
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
  }

  function downloadReport() {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ids-scan-${Date.now()}.json`;
    a.click();
  }

  const vc = result ? verdictConfig[result.verdict] : null;
  const VIcon = vc?.icon || CheckCircle;

  const filteredEngines = result
    ? Object.entries(result.results).filter(([, v]) => filter === "all" || v.category === filter)
    : [];
  const displayedEngines = showAll ? filteredEngines : filteredEngines.slice(0, 20);

  const detections = result ? Object.entries(result.results).filter(([, v]) => v.category === "malicious" || v.category === "suspicious") : [];

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Defensive Analysis" tool="IDS Analyzer" />
      <ToolHeader title="Intrusion Detection System" description="VirusTotal file/URL scanning · Threat detection across 70+ engines" />

      <TwoColumn
        left={
          <ConfigCard
            title="Scan input"
            footer={
              tab === "url" ? (
                <RunButton onClick={handleScan} disabled={loading}>
                  {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {loading ? "Scanning…" : "Scan"}
                </RunButton>
              ) : fileName ? (
                <RunButton onClick={handleScan} disabled={loading}>
                  {loading ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {loading ? "Scanning…" : "Scan file"}
                </RunButton>
              ) : undefined
            }
          >
            <div className="flex gap-1 p-1 rounded-md bg-muted/30 border border-border">
              <button
                onClick={() => { setTab("url"); setError(""); setResult(null); }}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${tab === "url" ? "bg-primary/20 text-primary border border-primary/40" : "text-muted-foreground hover:text-foreground"}`}
              >
                <Link2 className="h-3.5 w-3.5" /> URL
              </button>
              <button
                onClick={() => { setTab("file"); setError(""); setResult(null); }}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${tab === "file" ? "bg-primary/20 text-primary border border-primary/40" : "text-muted-foreground hover:text-foreground"}`}
              >
                <Upload className="h-3.5 w-3.5" /> File
              </button>
            </div>

            {tab === "url" ? (
              <ToolInput
                id="ids-url-input"
                placeholder="https://www.example.com"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleScan()}
              />
            ) : (
              <div
                onClick={() => fileRef.current?.click()}
                className="flex flex-col items-center justify-center gap-2 p-8 rounded-md border-2 border-dashed border-border hover:border-primary/50 transition-colors cursor-pointer"
              >
                <Upload className="h-7 w-7 text-muted-foreground" />
                <p className="text-sm text-muted-foreground text-center">
                  {fileName ? <span className="text-primary">{fileName}</span> : "Click to select a file"}
                </p>
                <p className="text-xs text-muted-foreground">Any file type · Max 32MB</p>
                <input ref={fileRef} type="file" title="Select file to scan" className="hidden" onChange={handleFile} />
              </div>
            )}

            {error && <ErrorBox message={error} />}
          </ConfigCard>
        }
        right={
          <>
            {!result && !loading && !error && (
              <ResultsCard title="Results">
                <div className="py-14 text-center text-sm text-muted-foreground">Scan a URL or file to see engine results here.</div>
              </ResultsCard>
            )}

            {loading && (
              <div className="bg-card border border-border rounded-md p-5 space-y-3 animate-pulse">
                <div className="h-4 bg-muted/40 rounded w-1/3" />
                <div className="h-4 bg-muted/40 rounded w-2/3" />
                <div className="h-4 bg-muted/40 rounded w-1/2" />
              </div>
            )}

            {result && vc && (
              <>
                <div className={`bg-card border rounded-md p-4 ${vc.border} ${vc.bg}`}>
                  <div className="flex items-center gap-4 flex-wrap">
                    <VIcon className={`h-8 w-8 ${vc.color} shrink-0`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 flex-wrap">
                        <span className={`text-xl font-bold ${vc.color}`}>{vc.label}</span>
                        {result.source === "simulation" && (
                          <span className="px-2 py-0.5 rounded-full text-[9px] font-mono font-bold bg-muted border border-border text-muted-foreground">SIMULATED</span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground font-mono mt-0.5 truncate max-w-lg">{result.target}</p>
                    </div>
                    <div className="flex gap-2">
                      <SecondaryButton onClick={copyReport}><Copy className="h-3.5 w-3.5" /></SecondaryButton>
                      <SecondaryButton onClick={downloadReport}><Download className="h-3.5 w-3.5" /></SecondaryButton>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-4">
                    {[
                      { label: "Malicious",     value: result.stats.malicious,  color: "text-destructive" },
                      { label: "Suspicious",    value: result.stats.suspicious, color: "text-orange-400" },
                      { label: "Harmless",      value: result.stats.harmless,   color: "text-success" },
                      { label: "Total Engines", value: result.stats.total,      color: "text-foreground" },
                    ].map(s => (
                      <div key={s.label} className="bg-background/40 rounded-md p-3 text-center border border-border">
                        <p className={`text-lg font-bold ${s.color}`}>{s.value}</p>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{s.label}</p>
                      </div>
                    ))}
                  </div>

                  <div className="mt-4">
                    <div className="flex justify-between text-[10px] text-muted-foreground mb-1">
                      <span>Detection rate</span>
                      <span>{result.stats.malicious}/{result.stats.total} engines</span>
                    </div>
                    <div className="h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${result.verdict === "malicious" ? "bg-destructive" : result.verdict === "suspicious" ? "bg-orange-500" : "bg-success"}`}
                        style={{ width: `${Math.round((result.stats.malicious / result.stats.total) * 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 mt-3 text-[10px] text-muted-foreground">
                    <Clock className="h-3 w-3" /> Scanned {new Date(result.scan_date).toLocaleString()}
                  </div>
                </div>

                {detections.length > 0 && (
                  <ResultsCard title={`Detections (${detections.length})`}>
                    <div className="p-4 space-y-2">
                      {detections.map(([eng, v]) => (
                        <div key={eng} className="flex items-center gap-3 p-2.5 rounded-md bg-muted/20 border border-border">
                          <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${catColor[v.category]}`}>{v.category.toUpperCase()}</span>
                          <span className="font-mono text-sm font-semibold text-foreground w-40 shrink-0">{eng}</span>
                          <span className="font-mono text-xs text-muted-foreground truncate">{v.result || "—"}</span>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard
                  title="Engine results"
                  meta={
                    <div className="flex gap-1.5 flex-wrap">
                      {(["all", "malicious", "suspicious", "harmless"] as FilterCat[]).map(f => (
                        <button
                          key={f}
                          onClick={() => setFilter(f)}
                          className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border transition-colors ${filter === f ? "bg-primary/20 text-primary border-primary/40" : "bg-muted text-muted-foreground border-border hover:text-foreground"}`}
                        >
                          {f.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  }
                >
                  <div className="p-4 space-y-1.5">
                    {displayedEngines.map(([eng, v]) => (
                      <div key={eng} className="flex items-center gap-3 p-2 rounded-md bg-muted/10 border border-border/50">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border w-24 text-center shrink-0 ${catColor[v.category]}`}>{v.category.toUpperCase()}</span>
                        <span className="font-mono text-xs text-foreground w-36 shrink-0">{eng}</span>
                        <span className="font-mono text-xs text-muted-foreground truncate flex-1">{v.result || "—"}</span>
                        <span className="font-mono text-[10px] text-muted-foreground/50 shrink-0">{v.engine_version}</span>
                      </div>
                    ))}
                  </div>

                  {filteredEngines.length > 20 && (
                    <button
                      onClick={() => setShowAll(!showAll)}
                      className="flex items-center gap-1.5 mb-4 mx-auto text-xs text-muted-foreground hover:text-foreground transition-colors"
                    >
                      {showAll ? <><ChevronUp className="h-4 w-4" /> Show less</> : <><ChevronDown className="h-4 w-4" /> Show all {filteredEngines.length} engines</>}
                    </button>
                  )}

                  {filteredEngines.length === 0 && (
                    <p className="text-center text-sm text-muted-foreground py-4">No engines in this category.</p>
                  )}
                </ResultsCard>
              </>
            )}
          </>
        }
      />
    </div>
  );
}
