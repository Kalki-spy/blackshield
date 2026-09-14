import { useState } from "react";
import { Bug, Search, Loader2, Plus, X, Download } from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, ErrorBox, ResultsCard, SecondaryButton, Tag,
} from "@/components/tool/ToolUI";

const BACKEND = "/api";

interface CVEEntry {
  cve: string; software: string; cvss: number; severity: string;
  desc: string; vector: string; patch: string; affects_version?: boolean; note?: string;
}
interface ScanResult {
  software: string; version: string | null;
  cves: CVEEntry[]; risk: string;
  summary: { total: number; critical: number; high: number; medium: number; max_cvss: number };
  scanned_at: string;
}
type Tab = "single" | "bulk";

const riskCls = (r: string) => {
  if (r === "critical") return "text-destructive border-destructive/40 bg-destructive/10";
  if (r === "high")     return "text-orange-400 border-orange-500/40 bg-orange-500/10";
  if (r === "medium")   return "text-warning border-warning/40 bg-warning/10";
  if (r === "low")      return "text-success border-success/40 bg-success/10";
  return "text-muted-foreground border-border bg-muted/20";
};
const sevBadge = (s: string) => {
  if (s === "critical") return "bg-destructive/10 text-destructive border border-destructive/30";
  if (s === "high")     return "bg-orange-500/10 text-orange-400 border border-orange-500/30";
  if (s === "medium")   return "bg-warning/10 text-warning border border-warning/30";
  return "bg-primary/10 text-primary border border-primary/30";
};
const cvssCls = (c: number) => {
  if (c >= 9) return "text-destructive";
  if (c >= 7) return "text-orange-400";
  if (c >= 4) return "text-warning";
  return "text-success";
};

export default function CVEScanner() {
  const [tab, setTab]         = useState<Tab>("single");
  const [sw, setSw]           = useState("");
  const [ver, setVer]         = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<ScanResult | null>(null);
  const [error, setError]     = useState("");
  const [targets, setTargets] = useState([{ software: "", version: "" }]);
  const [bulkRes, setBulkRes] = useState<ScanResult[] | null>(null);

  async function scan() {
    if (!sw.trim()) return;
    setError(""); setResult(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/cve/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ software: sw.trim(), version: ver.trim() || undefined }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setResult(d);
    } catch (e: any) { setError(e.message || "Failed to reach cve_scanner_server.py (port 8779)"); }
    finally { setLoading(false); }
  }

  async function scanBulk() {
    const valid = targets.filter(t => t.software.trim());
    if (!valid.length) return;
    setError(""); setBulkRes(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/cve/bulk`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ targets: valid }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setBulkRes(d.results);
    } catch (e: any) { setError(e.message || "Failed to reach cve_scanner_server.py (port 8779)"); }
    finally { setLoading(false); }
  }

  function exportResult() {
    const data = tab === "single" ? result : bulkRes;
    if (!data) return;
    const b = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(b);
    a.download = `cve-scan-${Date.now()}.json`; a.click();
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Defensive Analysis" tool="CVE Scanner" />
      <ToolHeader title="CVE Vulnerability Scanner" description="Known CVE lookup · CVSS scoring · Patch guidance · Bulk software audit" />

      <div className="flex gap-1 p-1 rounded-md bg-muted/30 border border-border w-fit">
        {(["single", "bulk"] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => { setTab(t); setError(""); setResult(null); setBulkRes(null); }}
            className={`flex items-center gap-1.5 px-4 py-2 rounded text-xs font-medium transition-colors ${tab === t ? "bg-primary/20 border border-primary/40 text-primary" : "text-muted-foreground hover:text-foreground"}`}
          >
            {t === "single" ? <><Search className="h-3.5 w-3.5" /> Single Scan</> : <><Bug className="h-3.5 w-3.5" /> Bulk Scan</>}
          </button>
        ))}
      </div>

      <TwoColumn
        left={
          tab === "single" ? (
            <ConfigCard
              title="Software target"
              footer={
                <RunButton onClick={scan} disabled={loading || !sw.trim()}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {loading ? "Scanning..." : "Scan"}
                </RunButton>
              }
            >
              <Field label="Software name">
                <ToolInput value={sw} onChange={e => setSw(e.target.value)} onKeyDown={e => e.key === "Enter" && !loading && scan()} placeholder="apache, log4j, openssl" disabled={loading} />
              </Field>
              <Field label="Version" hint="Optional">
                <ToolInput value={ver} onChange={e => setVer(e.target.value)} placeholder="e.g. 2.4.49" disabled={loading} />
              </Field>
              <div className="flex flex-wrap gap-1.5">
                {["apache", "log4j", "openssl", "nginx", "wordpress", "mysql", "vsftpd", "redis"].map(s => (
                  <button key={s} onClick={() => setSw(s)} className="px-2 py-0.5 rounded font-mono text-[10px] bg-muted/30 border border-border text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors">{s}</button>
                ))}
              </div>
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          ) : (
            <ConfigCard
              title="Bulk software audit"
              footer={
                <div className="flex gap-2 flex-wrap">
                  <SecondaryButton onClick={() => setTargets([...targets, { software: "", version: "" }])} className="flex-1 justify-center py-2.5" >
                    <Plus className="h-3.5 w-3.5" /> Add target
                  </SecondaryButton>
                  <RunButton onClick={scanBulk} disabled={loading || !targets.some(t => t.software.trim())} className="flex-1">
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Bug className="h-4 w-4" />}
                    {loading ? "Scanning..." : "Scan all"}
                  </RunButton>
                </div>
              }
            >
              <div className="space-y-2">
                {targets.map((t, i) => (
                  <div key={i} className="flex gap-2">
                    <ToolInput
                      value={t.software}
                      onChange={e => { const n = [...targets]; n[i] = { ...n[i], software: e.target.value }; setTargets(n); }}
                      placeholder="Software name" disabled={loading}
                    />
                    <ToolInput
                      value={t.version}
                      onChange={e => { const n = [...targets]; n[i] = { ...n[i], version: e.target.value }; setTargets(n); }}
                      placeholder="Version" disabled={loading}
                      className="w-24 shrink-0"
                    />
                    {targets.length > 1 && (
                      <button onClick={() => setTargets(targets.filter((_, j) => j !== i))} title="Remove target" aria-label="Remove target" className="p-2 rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors shrink-0">
                        <X className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          )
        }
        right={
          <>
            {tab === "single" && result && (
              <>
                <div className={`bg-card border-2 rounded-md p-4 ${riskCls(result.risk)}`}>
                  <div className="flex items-center justify-between flex-wrap gap-3">
                    <div>
                      <div className="flex items-center gap-3">
                        <span className="text-xl font-black uppercase">{result.risk} Risk</span>
                        <span className="text-sm text-muted-foreground">{result.software} {result.version || ""}</span>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{result.summary.total} CVEs · Max CVSS {result.summary.max_cvss} · {result.summary.critical} critical · {result.summary.high} high</p>
                    </div>
                    <SecondaryButton onClick={exportResult}><Download className="h-3.5 w-3.5" /> Export</SecondaryButton>
                  </div>
                </div>

                {result.cves.length > 0 ? (
                  <ResultsCard title="CVE findings">
                    <div className="p-4 space-y-3">
                      {result.cves.map((c, i) => (
                        <div key={i} className={`p-4 rounded-md border ${c.affects_version === false ? "opacity-50 border-border bg-muted/10" : c.severity === "critical" ? "bg-destructive/5 border-destructive/20" : c.severity === "high" ? "bg-orange-500/5 border-orange-500/15" : "bg-muted/20 border-border"}`}>
                          <div className="flex items-start justify-between gap-3 mb-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-sm font-black text-foreground">{c.cve}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${sevBadge(c.severity)}`}>{c.severity.toUpperCase()}</span>
                              {c.affects_version === false && <Tag>VER N/A</Tag>}
                            </div>
                            <span className={`text-lg font-black shrink-0 ${cvssCls(c.cvss)}`}>{c.cvss}</span>
                          </div>
                          <p className="text-xs text-foreground mb-2">{c.desc}</p>
                          <p className="font-mono text-[10px] text-muted-foreground mb-1">Vector: {c.vector}</p>
                          <p className="text-[10px] text-primary">↳ Patch: {c.patch}</p>
                          {c.note && <p className="text-[10px] text-muted-foreground/60 mt-1 italic">{c.note}</p>}
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                ) : (
                  <div className="bg-card border border-border rounded-md p-4 flex items-center gap-3">
                    <Bug className="h-5 w-5 text-success" />
                    <p className="text-sm text-success">No CVEs found in database for "{result.software}"</p>
                  </div>
                )}
              </>
            )}

            {tab === "bulk" && bulkRes && (
              <div className="space-y-3">
                {bulkRes.length > 0 && (
                  <div className="flex justify-end">
                    <SecondaryButton onClick={exportResult}><Download className="h-3.5 w-3.5" /> Export all</SecondaryButton>
                  </div>
                )}
                {bulkRes.map((r, i) => (
                  <div key={i} className={`bg-card border rounded-md p-4 ${r.risk === "critical" ? "border-destructive/30" : r.risk === "high" ? "border-orange-500/30" : r.risk === "low" || r.risk === "unknown" ? "border-success/20" : "border-warning/20"}`}>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-mono text-sm font-bold text-foreground">{r.software} {r.version || ""}</span>
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${riskCls(r.risk)}`}>{r.risk.toUpperCase()}</span>
                      <span className="text-xs text-muted-foreground ml-auto">{r.summary.total} CVEs · Max {r.summary.max_cvss} CVSS</span>
                    </div>
                    {r.cves.slice(0, 2).map((c, j) => (
                      <div key={j} className="mt-2 flex items-center gap-2">
                        <span className="font-mono text-[10px] text-muted-foreground">{c.cve}</span>
                        <span className={`px-1 py-0.5 rounded text-[9px] font-mono font-bold ${sevBadge(c.severity)}`}>{c.severity.toUpperCase()}</span>
                        <span className="text-[10px] text-muted-foreground truncate">{c.desc}</span>
                      </div>
                    ))}
                    {r.cves.length > 2 && <p className="text-[10px] text-muted-foreground/60 mt-1">+{r.cves.length - 2} more CVEs</p>}
                  </div>
                ))}
              </div>
            )}

            {!loading && !result && !bulkRes && !error && (
              <ResultsCard title="Supported software">
                <div className="flex flex-wrap gap-2 p-4">
                  {["Apache", "OpenSSL", "Nginx", "WordPress", "MySQL", "PHP", "OpenSSH", "Log4j", "Samba", "vsftpd", "Tomcat", "Elasticsearch", "Redis"].map(s => (
                    <span key={s} className="px-2.5 py-1 rounded-md text-xs bg-primary/10 text-primary border border-primary/20">{s}</span>
                  ))}
                </div>
              </ResultsCard>
            )}
          </>
        }
      />
    </div>
  );
}
