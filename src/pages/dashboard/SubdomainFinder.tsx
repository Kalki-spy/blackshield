import { useState } from "react";
import {
  Globe, Search, CheckCircle, XCircle,
  Loader2, Copy, Download, Network, Database, Shield,
  ExternalLink, Filter
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/subdomain";

type Source = "crt.sh" | "wordlist" | "both";

interface Subdomain {
  subdomain: string;
  ip: string | null;
  reverse: string | null;
  source: Source;
}

interface FindResult {
  domain: string;
  input_domain?: string;
  base_ip: string;
  total: number;
  resolved: number;
  subdomains: Subdomain[];
  sources: Record<string, number>;
}

const SCAN_STEPS: [number, string][] = [
  [10, "Resolving base domain..."],
  [25, "Querying certificate transparency logs..."],
  [55, "Running DNS wordlist enumeration..."],
  [80, "Resolving discovered subdomains..."],
  [92, "Aggregating & deduplicating results..."],
];

const sourceBadge = (source: Source) => {
  if (source === "crt.sh")   return "bg-primary/10 text-primary border-primary/30";
  if (source === "wordlist") return "bg-orange-500/10 text-orange-400 border-orange-500/30";
  if (source === "both")     return "bg-success/10 text-success border-success/30";
  return "";
};

const sourceLabel = (source: Source) => {
  if (source === "crt.sh")   return "cert";
  if (source === "wordlist") return "brute";
  if (source === "both")     return "both";
  return source;
};

export default function SubdomainFinder() {
  const [inputDomain, setInputDomain] = useState("");
  const [scanning, setScanning]       = useState(false);
  const [progress, setProgress]       = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error, setError]             = useState("");
  const [result, setResult]           = useState<FindResult | null>(null);
  const [filter, setFilter]           = useState<"all" | "resolved" | "crt.sh" | "wordlist" | "both">("all");
  const [copied, setCopied]           = useState(false);

  async function handleScan() {
    const domain = inputDomain.trim();
    if (!domain) return;

    setError(""); setResult(null); setScanning(true); setProgress(0);

    let si = 0;
    const tick = setInterval(() => {
      if (si < SCAN_STEPS.length) {
        setProgress(SCAN_STEPS[si][0]);
        setProgressMsg(SCAN_STEPS[si][1]);
        si++;
      }
    }, 1800);

    try {
      const res  = await fetch(`${BACKEND}/find?domain=${encodeURIComponent(domain)}`);
      const data = await res.json();
      clearInterval(tick);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Complete.");
      await new Promise(r => setTimeout(r, 300));
      setResult(data as FindResult);
    } catch (e: any) {
      clearInterval(tick);
      setError(e.message || "Failed to reach backend. Is the Python server running?");
    } finally {
      setScanning(false);
    }
  }

  const filtered = result?.subdomains.filter(s => {
    if (filter === "resolved") return !!s.ip;
    if (filter === "crt.sh")   return s.source === "crt.sh"   || s.source === "both";
    if (filter === "wordlist") return s.source === "wordlist" || s.source === "both";
    if (filter === "both")     return s.source === "both";
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
    a.download = `subdomains-${result.domain}.json`;
    a.click();
  }

  function exportCSV() {
    if (!result) return;
    const rows = [
      "subdomain,ip,reverse,source",
      ...result.subdomains.map(s =>
        `${s.subdomain},${s.ip ?? ""},${s.reverse ?? ""},${s.source}`
      ),
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `subdomains-${result.domain}.csv`;
    a.click();
  }

  function copyList() {
    if (!result) return;
    navigator.clipboard.writeText(result.subdomains.map(s => s.subdomain).join("\n")).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const crtCount = result ? (result.sources["crt.sh"] ?? 0) + (result.sources["both"] ?? 0) : 0;
  const wlCount  = result ? (result.sources["wordlist"] ?? 0) + (result.sources["both"] ?? 0) : 0;

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Reconnaissance" tool="Subdomain Finder" />
      <ToolHeader title="Subdomain Finder" description="DNS enumeration via certificate transparency logs & wordlist brute-force" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Domain"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !inputDomain.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Find subdomains"}
                </RunButton>
              }
            >
              <Field label="Domain">
                <ToolInput
                  value={inputDomain}
                  onChange={e => setInputDomain(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="example.com or www.example.com"
                  disabled={scanning}
                />
              </Field>
              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />}

            {result && (
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Network className="h-4 w-4 text-primary" /><span className="text-lg font-bold text-foreground">{result.total}</span></div>
                  <p className="text-[11px] text-muted-foreground">Total found</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><CheckCircle className="h-4 w-4 text-success" /><span className="text-lg font-bold text-foreground">{result.resolved}</span></div>
                  <p className="text-[11px] text-success">Resolved</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Shield className="h-4 w-4 text-primary" /><span className="text-lg font-bold text-foreground">{crtCount}</span></div>
                  <p className="text-[11px] text-primary">From crt.sh</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3">
                  <div className="flex items-center gap-2 mb-1"><Database className="h-4 w-4 text-orange-400" /><span className="text-lg font-bold text-foreground">{wlCount}</span></div>
                  <p className="text-[11px] text-orange-400">From wordlist</p>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="Discovery methods">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Certificate Transparency", "Queries crt.sh for all SSL certs ever issued for the domain"],
                    ["DNS Wordlist",             "Brute-forces 100+ common subdomain prefixes via live DNS"],
                    ["IP Resolution",           "Resolves each discovered subdomain to its IPv4 address"],
                    ["Reverse DNS",             "Attempts PTR record lookup for each resolved IP"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Globe className="h-4 w-4 text-primary mt-0.5 shrink-0" />
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
                  <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Root domain</span>
                  <span className="font-mono text-sm text-foreground">{result.domain}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono text-sm text-primary">{result.base_ip}</span>
                  {result.input_domain && result.input_domain !== result.domain && (
                    <span className="text-[10px] text-muted-foreground">(extracted from <span className="text-foreground">{result.input_domain}</span>)</span>
                  )}
                </div>

                <ResultsCard
                  title="Discovered subdomains"
                  meta={<span>{filtered.length} result{filtered.length !== 1 ? "s" : ""}</span>}
                >
                  <div className="p-4 flex flex-col gap-4">
                    <div className="flex items-center justify-between flex-wrap gap-3">
                      <div className="flex items-center gap-1 p-1 rounded-md bg-muted/40 border border-border flex-wrap">
                        <Filter className="h-3 w-3 text-muted-foreground ml-1.5 mr-0.5" />
                        {(["all", "resolved", "crt.sh", "wordlist", "both"] as const).map(f => (
                          <button
                            key={f}
                            onClick={() => setFilter(f)}
                            className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold transition-colors ${
                              filter === f ? "bg-primary/20 text-primary border border-primary/30" : "text-muted-foreground hover:text-foreground"
                            }`}
                          >
                            {f.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      <div className="flex gap-2">
                        <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> JSON</SecondaryButton>
                        <SecondaryButton onClick={exportCSV}><Download className="h-3.5 w-3.5" /> CSV</SecondaryButton>
                        <SecondaryButton onClick={copyList}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy list"}</SecondaryButton>
                      </div>
                    </div>

                    <div className="grid grid-cols-12 gap-2 px-3 py-1.5">
                      <span className="col-span-5 text-[10px] text-muted-foreground uppercase tracking-widest">Subdomain</span>
                      <span className="col-span-3 text-[10px] text-muted-foreground uppercase tracking-widest">IP Address</span>
                      <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Reverse DNS</span>
                      <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Source</span>
                    </div>

                    <div className="space-y-1 max-h-[520px] overflow-y-auto pr-1">
                      {filtered.length === 0 ? (
                        <div className="text-center py-10 text-muted-foreground text-sm">No results for this filter.</div>
                      ) : (
                        filtered.map((s, i) => (
                          <div key={i} className="grid grid-cols-12 gap-2 items-center px-3 py-2.5 rounded-md bg-muted/20 border border-border hover:border-primary/20 transition-colors group">
                            <div className="col-span-5 flex items-center gap-2 min-w-0">
                              {s.ip ? <CheckCircle className="h-3 w-3 text-success shrink-0" /> : <XCircle className="h-3 w-3 text-muted-foreground shrink-0" />}
                              <span className="font-mono text-xs text-foreground truncate" title={s.subdomain}>{s.subdomain}</span>
                              <a href={`https://${s.subdomain}`} target="_blank" rel="noopener noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                                <ExternalLink className="h-3 w-3 text-muted-foreground hover:text-primary" />
                              </a>
                            </div>
                            <div className="col-span-3 min-w-0">
                              {s.ip ? <span className="font-mono text-xs text-primary truncate block" title={s.ip}>{s.ip}</span> : <span className="font-mono text-xs text-muted-foreground">—</span>}
                            </div>
                            <div className="col-span-2 min-w-0">
                              {s.reverse ? <span className="font-mono text-xs text-muted-foreground truncate block" title={s.reverse}>{s.reverse}</span> : <span className="font-mono text-xs text-muted-foreground/40">—</span>}
                            </div>
                            <div className="col-span-2">
                              <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${sourceBadge(s.source)}`}>{sourceLabel(s.source)}</span>
                            </div>
                          </div>
                        ))
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
