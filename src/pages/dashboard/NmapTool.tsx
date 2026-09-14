import { useState } from "react";
import {
  Terminal, Loader2, Search, XCircle,
  CheckCircle, Shield, Copy, Download,
  Globe, Wifi, Settings,
  Cpu, Clock, Network, Eye
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/nmap";

type ScanType = "syn" | "version" | "os" | "aggressive";

interface PortInfo {
  port:      number;
  proto:     string;
  state:     string;
  reason:    string;
  service:   string;
  desc:      string;
  version:   string;
  banner:    string;
  latency:   number;
  http_info?: Record<string, string | number>;
}

interface OsInfo {
  os:         string;
  confidence: number;
  candidates: Record<string, number>;
  method:     string;
}

interface ScanResult {
  target:         string;
  ip:             string;
  rdns:           string;
  scan_type:      string;
  ports_scanned:  number;
  open_ports:     number;
  closed_ports:   number;
  filtered_ports: number;
  scan_time:      number;
  avg_latency:    number;
  ports:          PortInfo[];
  os_info:        OsInfo;
  http_info:      Record<string, string | number>;
  host_up:        boolean;
}

const SCAN_TYPES: { value: ScanType; label: string; flag: string; desc: string }[] = [
  { value: "syn",        label: "SYN Scan",        flag: "-sS", desc: "Fast stealth scan (TCP half-open)" },
  { value: "version",    label: "Version Detection",flag: "-sV", desc: "Probe open ports to determine service versions" },
  { value: "os",         label: "OS Detection",     flag: "-O",  desc: "Enable OS fingerprinting" },
  { value: "aggressive", label: "Aggressive",       flag: "-A",  desc: "OS detection + version + scripts + traceroute" },
];

const SCAN_STEPS: [number, string][] = [
  [5,  "Initiating ARP Ping Scan..."],
  [15, "Scanning target host..."],
  [30, "Discovering open ports..."],
  [50, "Probing service versions..."],
  [65, "Running OS detection..."],
  [80, "Performing script scanning..."],
  [92, "Post-scan analysis..."],
];

const stateColor = (state: string) => {
  switch (state) {
    case "open":           return "text-success";
    case "closed":         return "text-destructive";
    case "filtered":       return "text-warning";
    case "open|filtered":  return "text-orange-400";
    default:               return "text-muted-foreground";
  }
};

const osConfColor = (conf: number) => {
  if (conf >= 80) return "text-success";
  if (conf >= 50) return "text-warning";
  return "text-orange-400";
};

export default function NmapTool() {
  const [target, setTarget]           = useState("");
  const [scanType, setScanType]       = useState<ScanType>("syn");
  const [customPorts, setCustomPorts] = useState("");
  const [showOptions, setShowOptions] = useState(false);
  const [showBanners, setShowBanners] = useState(false);

  const [scanning, setScanning]         = useState(false);
  const [progress, setProgress]         = useState(0);
  const [progressMsg, setProgressMsg]   = useState("");
  const [error, setError]               = useState("");
  const [result, setResult]             = useState<ScanResult | null>(null);
  const [copied, setCopied]             = useState(false);

  async function handleScan() {
    const t = target.trim();
    if (!t) return;
    setError(""); setResult(null); setScanning(true); setProgress(0);

    let si = 0;
    const intervalMs = scanType === "aggressive" ? 2800 : scanType === "version" ? 2200 : 1600;
    const tick = setInterval(() => {
      if (si < SCAN_STEPS.length) {
        setProgress(SCAN_STEPS[si][0]);
        setProgressMsg(SCAN_STEPS[si][1]);
        si++;
      }
    }, intervalMs);

    try {
      const ports = customPorts.trim()
        ? customPorts.split(",").map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n))
        : undefined;

      const res = await fetch(`${BACKEND}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t, scan_type: scanType, ...(ports ? { ports } : {}) }),
      });
      const data = await res.json();
      clearInterval(tick);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Nmap done.");
      await new Promise(r => setTimeout(r, 200));
      setResult(data as ScanResult);
    } catch (e: any) {
      clearInterval(tick);
      setError(e.message || "Failed to reach backend. Is nmap_server.py running?");
    } finally {
      setScanning(false);
    }
  }

  function exportGrepable() {
    if (!result) return;
    const lines = [
      `# Nmap scan — ${new Date().toISOString()}`,
      `# Scan type: ${result.scan_type} | Target: ${result.target} (${result.ip})`,
      `Host: ${result.ip} (${result.rdns || result.target})\tStatus: ${result.host_up ? "Up" : "Down"}`,
      `Host: ${result.ip} (${result.rdns || result.target})\tPorts: ` +
        result.ports.map(p =>
          `${p.port}/${p.state}/${p.proto}//${p.service}//${p.version || ""}/`
        ).join(", "),
      `# OS guess: ${result.os_info?.os} (${result.os_info?.confidence}% confidence)`,
      `# ${result.ports_scanned} ports scanned in ${result.scan_time}s`,
    ].join("\n");

    const blob = new Blob([lines], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `nmap-scan-${result.target}.gnmap`;
    a.click();
  }

  function copyReport() {
    if (!result) return;
    const lines = [
      `Starting Nmap scan — ${new Date().toUTCString()}`,
      `Host: ${result.ip} (${result.rdns || result.target}) is up (${result.avg_latency}ms latency).`,
      `Not shown: ${result.closed_ports} closed ports`,
      `PORT     STATE  SERVICE  VERSION`,
      ...result.ports.map(p =>
        `${String(p.port).padEnd(8)} ${p.state.padEnd(6)} ${p.service.padEnd(8)} ${p.version || ""}`
      ),
      "",
      `OS: ${result.os_info?.os} (${result.os_info?.confidence}% confidence)`,
      `Nmap done: 1 IP address scanned in ${result.scan_time} seconds`,
    ].join("\n");
    navigator.clipboard.writeText(lines).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const activeScanDef = SCAN_TYPES.find(s => s.value === scanType)!;

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Reconnaissance" tool="Nmap Scanner" />
      <ToolHeader title="Nmap Scanner" description="Network exploration tool and port scanner" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Scan configuration"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !target.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Run scan"}
                </RunButton>
              }
            >
              <Field label="Target">
                <ToolInput
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="192.168.1.1, 10.0.0.0/24, scanme.nmap.org"
                />
              </Field>

              <div className="flex flex-col gap-2">
                <label className="text-xs font-medium text-muted-foreground">Scan type</label>
                <div className="flex flex-wrap gap-2">
                  {SCAN_TYPES.map(st => (
                    <button
                      key={st.value}
                      onClick={() => setScanType(st.value)}
                      title={st.desc}
                      className={`px-2.5 py-1.5 rounded-md text-[11px] font-mono font-bold border transition-all ${
                        scanType === st.value
                          ? "bg-primary/15 border-primary/40 text-primary"
                          : "bg-muted/30 border-border text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <span className="opacity-60">{st.flag}</span>
                      <span className="ml-1.5">{st.label}</span>
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={() => setShowOptions(v => !v)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start"
              >
                <Settings className="h-3.5 w-3.5" /> Advanced options
              </button>

              {showOptions && (
                <Field label="Custom port list" hint={`Defaults: ${scanType === "syn" ? "21 common ports" : "35 common ports"} · comma-separated`}>
                  <ToolInput
                    value={customPorts}
                    onChange={e => setCustomPorts(e.target.value)}
                    placeholder="22,80,443,8080"
                  />
                </Field>
              )}

              <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-muted/40 border border-border">
                <Terminal className="h-3.5 w-3.5 text-primary shrink-0" />
                <span className="font-mono text-[11px] text-primary truncate">nmap {activeScanDef.flag} {target || "<target>"}</span>
              </div>

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && (
              <StatusCard status="Running" message={progressMsg} progress={progress} elapsed={`nmap ${activeScanDef.flag} ${target}`} />
            )}

            {result && (
              <div className="flex flex-wrap gap-2">
                <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-card border border-border">
                  {result.host_up
                    ? <CheckCircle className="h-3.5 w-3.5 text-success" />
                    : <XCircle className="h-3.5 w-3.5 text-destructive" />}
                  <span className={`font-mono text-xs font-bold ${result.host_up ? "text-success" : "text-destructive"}`}>
                    Host {result.host_up ? "Up" : "Down"}
                  </span>
                </div>
                <SecondaryButton onClick={() => setShowBanners(v => !v)} className={showBanners ? "text-primary border-primary/30 bg-primary/10" : ""}>
                  <Eye className="h-3.5 w-3.5" /> Banners
                </SecondaryButton>
                <SecondaryButton onClick={copyReport}>
                  {copied ? <CheckCircle className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied ? "Copied!" : "Copy"}
                </SecondaryButton>
                <SecondaryButton onClick={exportGrepable}>
                  <Download className="h-3.5 w-3.5" /> .gnmap
                </SecondaryButton>
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
                    ["Port Discovery",     "TCP connect scan across 21–35 common service ports"],
                    ["Version Detection",  "Banner grabbing to identify service name and version"],
                    ["OS Fingerprinting",  "Heuristic OS guess from open ports and service banners"],
                    ["HTTP Analysis",      "Security header audit: HSTS, CSP, X-Frame-Options and more"],
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
                    <div className="flex items-center gap-2 mb-1"><Wifi className="h-4 w-4 text-success" /><span className="text-xl font-bold text-foreground">{result.open_ports}</span></div>
                    <p className="text-[11px] text-success">Open ports</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><XCircle className="h-4 w-4 text-muted-foreground" /><span className="text-xl font-bold text-foreground">{result.closed_ports}</span></div>
                    <p className="text-[11px] text-muted-foreground">Closed ports</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><Clock className="h-4 w-4 text-primary" /><span className="text-xl font-bold text-foreground">{result.avg_latency}</span></div>
                    <p className="text-[11px] text-primary">Avg latency (ms)</p>
                  </div>
                  <div className="bg-card border border-border rounded-md p-3">
                    <div className="flex items-center gap-2 mb-1"><Shield className="h-4 w-4 text-foreground/70" /><span className="text-xl font-bold text-foreground">{result.ports_scanned}</span></div>
                    <p className="text-[11px] text-muted-foreground">Ports scanned</p>
                  </div>
                </div>

                <div className="bg-card border border-border rounded-md p-4 flex flex-wrap items-center gap-x-4 gap-y-2">
                  <Globe className="h-4 w-4 text-success shrink-0" />
                  <span className="text-[10px] text-muted-foreground uppercase tracking-widest">Host</span>
                  <span className="font-mono text-sm text-foreground">{result.target}</span>
                  <span className="text-muted-foreground">→</span>
                  <span className="font-mono text-sm text-success">{result.ip}</span>
                  {result.rdns && (
                    <>
                      <span className="text-muted-foreground">·</span>
                      <span className="font-mono text-sm text-primary">{result.rdns}</span>
                    </>
                  )}
                  <span className="ml-auto text-[10px] text-muted-foreground">{result.scan_type} scan · {result.scan_time}s</span>
                </div>

                {result.os_info && (
                  <ResultsCard title="OS detection">
                    <div className="p-4">
                      <div className="flex items-start gap-4 flex-wrap">
                        <div className="flex items-center gap-2">
                          <Cpu className="h-4 w-4 text-success" />
                          <span className="font-mono text-sm font-bold text-foreground">{result.os_info.os}</span>
                          <span className={`font-mono text-xs ${osConfColor(result.os_info.confidence)}`}>({result.os_info.confidence}% confidence)</span>
                        </div>
                        {result.os_info.candidates && Object.keys(result.os_info.candidates).length > 1 && (
                          <div className="flex flex-wrap gap-2 ml-auto">
                            {Object.entries(result.os_info.candidates).map(([os, score]) => (
                              <span key={os} className="px-2 py-0.5 rounded text-[10px] font-mono bg-muted/30 border border-border text-muted-foreground">{os} ({score}pts)</span>
                            ))}
                          </div>
                        )}
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-2">{result.os_info.method}</p>
                    </div>
                  </ResultsCard>
                )}

                {result.http_info && Object.keys(result.http_info).length > 0 && (
                  <ResultsCard title="HTTP fingerprint">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 p-4">
                      {Object.entries(result.http_info).map(([k, v]) => (
                        <div key={k} className="p-2 rounded-md bg-muted/20 border border-border">
                          <p className="text-[9px] text-muted-foreground uppercase tracking-wider">{k.replace(/_/g, " ")}</p>
                          <p className={`font-mono text-xs mt-0.5 ${
                            String(v).toUpperCase() === "MISSING" ? "text-orange-400" :
                            v === "present"                       ? "text-success"  : "text-foreground"
                          }`}>{String(v) || "—"}</p>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard title="Port scan results">
                  {result.ports.length === 0 ? (
                    <p className="text-sm text-muted-foreground p-4">All scanned ports are closed or filtered.</p>
                  ) : (
                    <div className="p-4 space-y-0.5">
                      <div className="grid grid-cols-12 gap-2 px-3 py-1.5">
                        <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Port/Proto</span>
                        <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">State</span>
                        <span className="col-span-2 text-[10px] text-muted-foreground uppercase tracking-widest">Service</span>
                        <span className="col-span-3 text-[10px] text-muted-foreground uppercase tracking-widest">Version</span>
                        <span className="col-span-3 text-[10px] text-muted-foreground uppercase tracking-widest">Latency</span>
                      </div>
                      {result.ports.map((p, i) => (
                        <div key={i} className="space-y-0">
                          <div className="grid grid-cols-12 gap-2 items-center px-3 py-2 rounded-md bg-muted/20 border border-border hover:border-success/20 transition-colors">
                            <div className="col-span-2">
                              <span className="font-mono text-sm font-bold text-success">{p.port}</span>
                              <span className="font-mono text-[10px] text-muted-foreground">/{p.proto}</span>
                            </div>
                            <div className="col-span-2">
                              <span className={`font-mono text-xs font-bold ${stateColor(p.state)}`}>{p.state}</span>
                              <span className="block font-mono text-[9px] text-muted-foreground">{p.reason}</span>
                            </div>
                            <div className="col-span-2"><span className="font-mono text-xs text-foreground">{p.service}</span></div>
                            <div className="col-span-3 min-w-0">
                              <span className="font-mono text-xs text-primary truncate block" title={p.version}>
                                {p.version || <span className="text-muted-foreground">—</span>}
                              </span>
                            </div>
                            <div className="col-span-3"><span className="font-mono text-xs text-muted-foreground">{p.latency}ms</span></div>
                          </div>

                          {showBanners && p.banner && (
                            <div className="mx-3 px-3 py-1.5 rounded-b-md bg-black/40 border-x border-b border-success/10">
                              <span className="font-mono text-[10px] text-success/70 break-all">{p.banner}</span>
                            </div>
                          )}

                          {p.http_info && Object.keys(p.http_info).length > 0 && (
                            <div className="mx-3 px-3 py-2 rounded-b-md bg-muted/10 border-x border-b border-border grid grid-cols-3 md:grid-cols-6 gap-1.5">
                              {Object.entries(p.http_info).slice(0, 6).map(([k, v]) => (
                                <div key={k}>
                                  <p className="text-[8px] text-muted-foreground uppercase">{k.replace(/_/g," ")}</p>
                                  <p className={`font-mono text-[10px] ${
                                    String(v).toUpperCase() === "MISSING" ? "text-orange-400" :
                                    v === "present"                       ? "text-success"  : "text-foreground"
                                  }`}>{String(v) || "—"}</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </ResultsCard>

                <div className="bg-card border border-success/10 rounded-md p-3">
                  <p className="font-mono text-xs text-success/80">Nmap done: 1 IP address (1 host up) scanned in {result.scan_time} seconds</p>
                  <p className="font-mono text-[10px] text-muted-foreground mt-0.5">Not shown: {result.closed_ports} closed tcp ports (reset)</p>
                </div>
              </>
            )}
          </>
        }
      />
    </div>
  );
}
