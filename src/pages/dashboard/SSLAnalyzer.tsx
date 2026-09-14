import { useState } from "react";
import {
  Lock, Shield, CheckCircle, AlertTriangle, XCircle,
  Loader2, AlertCircle, FileText, Copy, Download,
  ShieldCheck
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/sslanalyzer";

interface CertInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  signatureAlgorithm: string;
  keyType: string;
  keyBits: number;
  sans: string[];
  fingerprint: string;
  activeProtocol: string;
  activeCipher: string;
}

interface SSLResult {
  category: string;
  item: string;
  status: "secure" | "warning" | "vulnerable";
  description: string;
  severity: "low" | "medium" | "high" | "critical";
}

const CATEGORIES = ["Certificate", "Protocol Support", "Cipher Suites", "Vulnerabilities", "Features"];

const StatusIcon = ({ status }: { status: string }) => {
  if (status === "secure")     return <CheckCircle className="h-4 w-4 text-success" />;
  if (status === "warning")    return <AlertTriangle className="h-4 w-4 text-warning" />;
  if (status === "vulnerable") return <XCircle className="h-4 w-4 text-destructive" />;
  return <Shield className="h-4 w-4 text-muted-foreground" />;
};

const statusBadge = (status: string) => {
  if (status === "secure")     return "bg-success/10 text-success border border-success/30";
  if (status === "warning")    return "bg-warning/10 text-warning border border-warning/30";
  if (status === "vulnerable") return "bg-destructive/10 text-destructive border border-destructive/30";
  return "bg-muted text-muted-foreground";
};

const severityBadge = (sev: string) => {
  if (sev === "low")      return "bg-primary/10 text-primary border border-primary/30";
  if (sev === "medium")   return "bg-warning/10 text-warning border border-warning/30";
  if (sev === "high")     return "bg-orange-500/10 text-orange-400 border border-orange-500/30";
  if (sev === "critical") return "bg-destructive/10 text-destructive border border-destructive/30";
  return "";
};

export default function SSLAnalyzer() {
  const [inputUrl, setInputUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error, setError] = useState("");
  const [cert, setCert] = useState<CertInfo | null>(null);
  const [results, setResults] = useState<SSLResult[]>([]);
  const [scannedUrl, setScannedUrl] = useState("");
  const [showReport, setShowReport] = useState(false);
  const [copied, setCopied] = useState(false);

  const steps: [number, string][] = [
    [10, "Resolving hostname..."],
    [25, "Establishing TLS connection..."],
    [45, "Parsing certificate..."],
    [60, "Testing protocol versions (parallel)..."],
    [75, "Checking cipher suites..."],
    [88, "Analyzing vulnerabilities & features..."],
  ];

  async function handleScan() {
    let url = inputUrl.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;

    setError(""); setCert(null); setResults([]);
    setShowReport(false); setScanning(true); setProgress(0);

    let si = 0;
    const tick = setInterval(() => {
      if (si < steps.length) {
        setProgress(steps[si][0]);
        setProgressMsg(steps[si][1]);
        si++;
      }
    }, 2000);

    try {
      const res  = await fetch(`${BACKEND}/analyze?url=${encodeURIComponent(url)}`);
      const data = await res.json();
      clearInterval(tick);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Complete.");
      await new Promise(r => setTimeout(r, 400));
      setCert(data.certificate);
      setResults(data.results);
      setScannedUrl(url);
    } catch (e: any) {
      clearInterval(tick);
      setError(e.message || "Failed to reach backend. Is the Python server running?");
    } finally {
      setScanning(false);
    }
  }

  const summary = results.reduce(
    (a, r) => { a[r.status] = (a[r.status] || 0) + 1; return a; },
    { secure: 0, warning: 0, vulnerable: 0 } as Record<string, number>
  );
  const vulns = results.filter(r => r.status === "vulnerable");
  const warns  = results.filter(r => r.status === "warning");

  function exportJSON() {
    const blob = new Blob(
      [JSON.stringify({ url: scannedUrl, certificate: cert, results, timestamp: new Date().toISOString() }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "ssl-report.json";
    a.click();
  }

  function copyReport() {
    const text = results.map(r => `[${r.status.toUpperCase()}] ${r.item} — ${r.description}`).join("\n");
    navigator.clipboard.writeText(`SSL/TLS Report: ${scannedUrl}\n\n${text}`).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Web Security" tool="SSL Analyzer" />
      <ToolHeader title="TLS/SSL Analyzer" description="Deep inspection of certificates, protocols, ciphers & vulnerabilities" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Target"
              footer={
                <RunButton onClick={handleScan} disabled={scanning || !inputUrl.trim()}>
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
                  {scanning ? "Scanning..." : "Analyze"}
                </RunButton>
              }
            >
              <Field label="URL">
                <ToolInput
                  value={inputUrl}
                  onChange={e => setInputUrl(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="example.com"
                  disabled={scanning}
                />
              </Field>
              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />}

            {results.length > 0 && (
              <div className="grid grid-cols-3 gap-2">
                <div className="bg-card border border-border rounded-md p-3 text-center">
                  <div className="flex items-center justify-center gap-1.5"><CheckCircle className="h-4 w-4 text-success" /><span className="text-lg font-bold text-foreground">{summary.secure}</span></div>
                  <p className="text-[11px] text-success">Secure</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3 text-center">
                  <div className="flex items-center justify-center gap-1.5"><AlertTriangle className="h-4 w-4 text-warning" /><span className="text-lg font-bold text-foreground">{summary.warning}</span></div>
                  <p className="text-[11px] text-warning">Warnings</p>
                </div>
                <div className="bg-card border border-border rounded-md p-3 text-center">
                  <div className="flex items-center justify-center gap-1.5"><XCircle className="h-4 w-4 text-destructive" /><span className="text-lg font-bold text-foreground">{summary.vulnerable}</span></div>
                  <p className="text-[11px] text-destructive">Vulnerable</p>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && results.length === 0 && !error && (
              <ResultsCard title="What we check">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Certificate",     "Chain validity, expiry, key length, SANs"],
                    ["Protocols",       "Live TLS 1.0 / 1.1 / 1.2 / 1.3 testing"],
                    ["Cipher Suites",   "AEAD, forward secrecy, weak ciphers"],
                    ["Vulnerabilities", "BEAST, POODLE, SWEET32, CRIME"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Lock className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-foreground">{title}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </ResultsCard>
            )}

            {cert && (
              <ResultsCard title="Certificate">
                <div className="p-4 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {([
                    ["Issued To",       cert.subject,                                     undefined],
                    ["Issued By",       cert.issuer,                                      undefined],
                    ["Valid From",      cert.validFrom,                                   undefined],
                    ["Valid Until",     cert.validTo,                                     cert.daysRemaining],
                    ["Key",             `${cert.keyBits}-bit ${cert.keyType}`,            undefined],
                    ["Protocol/Cipher", `${cert.activeProtocol} · ${cert.activeCipher}`, undefined],
                    ["Signature Alg",   cert.signatureAlgorithm,                          undefined],
                    ["Serial",          cert.serialNumber,                                undefined],
                    ["Fingerprint",     cert.fingerprint,                                 undefined],
                  ] as [string, string, number | undefined][]).map(([label, value, extra]) => (
                    <div key={label} className="bg-muted/30 rounded-md p-3 border border-border">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">{label}</p>
                      <p className="text-xs font-mono text-foreground truncate" title={value}>{value}</p>
                      {extra !== undefined && (
                        <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                          extra > 30 ? "bg-success/15 text-success" : "bg-destructive/15 text-destructive"
                        }`}>
                          {extra > 0 ? `${extra}d left` : "EXPIRED"}
                        </span>
                      )}
                    </div>
                  ))}
                  {cert.sans?.length > 0 && (
                    <div className="bg-muted/30 rounded-md p-3 border border-border col-span-2 md:col-span-3">
                      <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Subject Alt Names</p>
                      <p className="text-xs font-mono text-foreground break-all">{cert.sans.join(", ")}</p>
                    </div>
                  )}
                </div>
              </ResultsCard>
            )}

            {results.length > 0 && (
              <ResultsCard
                title="Security analysis"
                meta={
                  <SecondaryButton
                    onClick={() => {
                      setShowReport(true);
                      setTimeout(() => document.getElementById("report")?.scrollIntoView({ behavior: "smooth" }), 100);
                    }}
                  >
                    <FileText className="h-3.5 w-3.5" /> Generate report
                  </SecondaryButton>
                }
              >
                <div className="px-4 pt-4">
                  <div className="px-3 py-2 rounded-md bg-muted/30 border border-border inline-block">
                    <span className="text-[10px] text-muted-foreground">TARGET </span>
                    <span className="text-xs font-mono text-primary">{scannedUrl}</span>
                  </div>
                </div>
                <div className="p-4 space-y-6">
                  {CATEGORIES.map(cat => {
                    const items = results.filter(r => r.category === cat);
                    if (!items.length) return null;
                    return (
                      <div key={cat}>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-[0.15em] mb-2 pb-2 border-b border-border">{cat}</p>
                        <div className="space-y-2">
                          {items.map((r, i) => (
                            <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/10 border border-border hover:border-primary/20 transition-colors">
                              <div className="mt-0.5"><StatusIcon status={r.status} /></div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap mb-1">
                                  <span className="font-mono text-sm font-semibold text-foreground">{r.item}</span>
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${statusBadge(r.status)}`}>{r.status.toUpperCase()}</span>
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${severityBadge(r.severity)}`}>{r.severity.toUpperCase()}</span>
                                </div>
                                <p className="text-xs text-muted-foreground">{r.description}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </ResultsCard>
            )}

            {showReport && results.length > 0 && (
              <ResultsCard title="SSL/TLS security report">
                <div id="report" className="p-4 space-y-5">
                  <p className="text-xs text-muted-foreground">
                    Generated {new Date().toLocaleString()} · <span className="font-mono text-primary">{scannedUrl}</span>
                  </p>
                  <div className="grid grid-cols-4 gap-3">
                    {([
                      ["Tests",      results.length,     "text-foreground"],
                      ["Secure",     summary.secure,     "text-success"],
                      ["Warnings",   summary.warning,    "text-warning"],
                      ["Vulnerable", summary.vulnerable, "text-destructive"],
                    ] as [string, number, string][]).map(([label, val, cls]) => (
                      <div key={label} className="bg-muted/30 rounded-md p-3 border border-border text-center">
                        <div className={`font-mono text-xl font-bold ${cls}`}>{val}</div>
                        <div className="text-[10px] text-muted-foreground mt-1">{label}</div>
                      </div>
                    ))}
                  </div>

                  {vulns.length > 0 && (
                    <div>
                      <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Critical issues</p>
                      {vulns.map((r, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-destructive/5 border border-destructive/20 mb-2">
                          <XCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                          <div>
                            <span className="font-mono text-sm font-semibold text-foreground">{r.item} </span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${severityBadge(r.severity)}`}>{r.severity.toUpperCase()}</span>
                            <p className="text-xs text-muted-foreground mt-0.5">{r.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {warns.length > 0 && (
                    <div>
                      <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Warnings</p>
                      {warns.map((r, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-warning/5 border border-warning/20 mb-2">
                          <AlertTriangle className="h-4 w-4 text-warning mt-0.5 shrink-0" />
                          <div>
                            <p className="font-mono text-sm font-semibold text-foreground">{r.item}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{r.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  <div>
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wide mb-2">Recommendations</p>
                    {vulns.length > 0 && (
                      <div className="flex gap-3 p-3 rounded-md bg-destructive/5 border border-destructive/20 mb-2">
                        <AlertCircle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                        <div>
                          <p className="text-xs font-semibold text-destructive mb-0.5">Critical priority</p>
                          <p className="text-xs text-muted-foreground">Disable vulnerable protocols and weak ciphers immediately to prevent exploitation.</p>
                        </div>
                      </div>
                    )}
                    <div className="flex gap-3 p-3 rounded-md bg-warning/5 border border-warning/20 mb-2">
                      <Shield className="h-4 w-4 text-warning mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-warning mb-0.5">High priority</p>
                        <p className="text-xs text-muted-foreground">Enforce TLS 1.2+ minimum. Prefer TLS 1.3 with AEAD cipher suites and perfect forward secrecy.</p>
                      </div>
                    </div>
                    <div className="flex gap-3 p-3 rounded-md bg-primary/5 border border-primary/20">
                      <CheckCircle className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                      <div>
                        <p className="text-xs font-semibold text-primary mb-0.5">Best practices</p>
                        <p className="text-xs text-muted-foreground">Enable HSTS, configure OCSP stapling, automate certificate renewal, and schedule quarterly TLS audits.</p>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2 flex-wrap pt-1">
                    <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> Export JSON</SecondaryButton>
                    <SecondaryButton onClick={copyReport}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy report"}</SecondaryButton>
                  </div>
                </div>
              </ResultsCard>
            )}
          </>
        }
      />
    </div>
  );
}
