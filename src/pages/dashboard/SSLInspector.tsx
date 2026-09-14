import { useState } from "react";
import { Link } from "react-router-dom";
import { Lock, Globe, AlertTriangle, CheckCircle, XCircle, Shield, Loader2, Download, Copy } from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, ErrorBox, ResultsCard, SecondaryButton, Tag,
} from "@/components/tool/ToolUI";


const BACKEND = "/api";

interface Finding { item:string; status:string; severity:string; desc:string }
interface CertInfo {
  subject_cn:string; issuer_cn:string; issuer_org:string;
  not_before:string; not_after:string; days_remaining:number|null;
  serial:string; sans:string[]; san_count:number;
}
interface SSLResult {
  host:string; port:number; reachable:boolean; has_ssl:boolean;
  protocol:string|null; cipher:string|null; cipher_bits:number|null;
  cert:CertInfo; findings:Finding[]; grade:string; error?:string;
}

const StatusIcon = ({s}:{s:string}) => {
  if (s==="secure")     return <CheckCircle   className="h-4 w-4 text-green-400"/>;
  if (s==="warning")    return <AlertTriangle className="h-4 w-4 text-yellow-400"/>;
  if (s==="vulnerable") return <XCircle       className="h-4 w-4 text-red-400"/>;
  return <Shield className="h-4 w-4 text-muted-foreground"/>;
};

const gradeCls = (g:string) => {
  if (g==="A+") return "text-green-400 border-green-500/40 bg-green-500/10";
  if (g==="A")  return "text-green-400 border-green-500/30 bg-green-500/10";
  if (g==="B")  return "text-yellow-400 border-yellow-500/30 bg-yellow-500/10";
  if (g==="C")  return "text-orange-400 border-orange-500/30 bg-orange-500/10";
  return "text-red-400 border-red-500/30 bg-red-500/10";
};

const sevCls = (s:string) => {
  if (s==="critical") return "bg-red-500/10 text-red-400 border border-red-500/30";
  if (s==="high")     return "bg-orange-500/10 text-orange-400 border border-orange-500/30";
  if (s==="medium")   return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/30";
  return "bg-blue-500/10 text-blue-400 border border-blue-500/30";
};

export default function SSLInspector() {
  const [host,    setHost]    = useState("");
  const [port,    setPort]    = useState("443");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState<SSLResult|null>(null);
  const [error,   setError]   = useState("");
  const [copied,  setCopied]  = useState(false);

  async function inspect() {
    const h = host.trim(); if (!h) return;
    setError(""); setResult(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/ssl/inspect`,{
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({host:h, port:parseInt(port)||443})
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d:SSLResult = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setResult(d);
    } catch(e:any) { setError(e.message||"Failed to reach ssl_inspector_server.py (port 8776)"); }
    finally { setLoading(false); }
  }

  function copyResult() {
    if (!result) return;
    const txt = [
      `SSL Report: ${result.host}:${result.port}`,
      `Grade: ${result.grade}  Protocol: ${result.protocol}  Cipher: ${result.cipher}`,
      `Cert CN: ${result.cert?.subject_cn}  Expires: ${result.cert?.not_after}  Days: ${result.cert?.days_remaining}`,
      "",
      ...result.findings.map(f=>`[${f.status.toUpperCase()}] ${f.item}: ${f.desc}`)
    ].join("\n");
    navigator.clipboard.writeText(txt).then(()=>{ setCopied(true); setTimeout(()=>setCopied(false),2000); });
  }

  function exportJSON() {
    if (!result) return;
    const b = new Blob([JSON.stringify(result,null,2)],{type:"application/json"});
    const a = document.createElement("a"); a.href=URL.createObjectURL(b);
    a.download=`ssl-report-${result.host}.json`; a.click();
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Web Security" tool="SSL Inspector" />
      <ToolHeader title="SSL/TLS Inspector" description="Certificate analysis · Protocol audit · Cipher strength · Expiry check" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Target"
              footer={
                <RunButton onClick={inspect} disabled={loading||!host.trim()}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin"/> : <Lock className="h-4 w-4"/>}
                  {loading ? "Inspecting..." : "Inspect"}
                </RunButton>
              }
            >
              <Field label="Hostname">
                <ToolInput
                  value={host} onChange={e=>setHost(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&!loading&&inspect()}
                  placeholder="example.com" disabled={loading}
                />
              </Field>
              <Field label="Port">
                <ToolInput value={port} onChange={e=>setPort(e.target.value)} placeholder="443" disabled={loading} className="text-center" />
              </Field>
              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {result && (
              <div className="bg-card border border-border rounded-md p-4 flex items-center gap-4">
                <div className={`h-14 w-14 rounded-md border-2 flex items-center justify-center font-mono text-xl font-black shrink-0 ${gradeCls(result.grade)}`}>
                  {result.grade}
                </div>
                <div className="min-w-0">
                  <p className="font-mono text-sm font-bold text-foreground truncate">{result.host}:{result.port}</p>
                  <div className="flex items-center gap-2 mt-1 flex-wrap">
                    {result.protocol && <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-primary/10 text-primary border border-primary/30">{result.protocol}</span>}
                    {result.cipher   && <span className="px-2 py-0.5 rounded font-mono text-[10px] text-muted-foreground border border-border">{result.cipher} ({result.cipher_bits}b)</span>}
                  </div>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!loading && !result && !error && (
              <ResultsCard title="What we check">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Protocol Version","TLS 1.0/1.1/1.2/1.3 detection and deprecation flags"],
                    ["Cipher Strength", "Algorithm and key-length analysis (RC4, 3DES, NULL...)"],
                    ["Certificate Expiry","Days remaining with urgent renewal warnings"],
                    ["CA Trust & SANs",  "Issuer trust chain and hostname validation"],
                  ] as [string,string][]).map(([t,d])=>(
                    <div key={t} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Lock className="h-4 w-4 text-primary mt-0.5 shrink-0"/>
                      <div>
                        <p className="text-xs font-semibold text-foreground">{t}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{d}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </ResultsCard>
            )}

            {result && (
              <>
                {result.cert?.subject_cn && (
                  <ResultsCard
                    title="Certificate"
                    meta={
                      <div className="flex gap-2">
                        <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> Export</SecondaryButton>
                        <SecondaryButton onClick={copyResult}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}</SecondaryButton>
                      </div>
                    }
                  >
                    <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {([
                        ["Subject CN", result.cert.subject_cn],
                        ["Issuer",     result.cert.issuer_cn],
                        ["Valid From", result.cert.not_before],
                        ["Expires",    result.cert.not_after],
                        ["Days Left",  result.cert.days_remaining != null ? `${result.cert.days_remaining} days` : "Unknown"],
                        ["SANs",       `${result.cert.san_count} entries`],
                      ] as [string,string][]).map(([k,v])=>(
                        <div key={k} className="p-3 rounded-md bg-muted/20 border border-border">
                          <p className="text-[10px] text-muted-foreground uppercase mb-1">{k}</p>
                          <p className="font-mono text-xs text-foreground truncate">{v}</p>
                        </div>
                      ))}
                    </div>
                    {result.cert.sans.length > 0 && (
                      <div className="mx-4 mb-4 p-3 rounded-md bg-muted/20 border border-border">
                        <p className="text-[10px] text-muted-foreground uppercase mb-2">Subject Alt Names</p>
                        <div className="flex flex-wrap gap-1.5">
                          {result.cert.sans.map(s=> <Tag key={s}>{s}</Tag>)}
                        </div>
                      </div>
                    )}
                  </ResultsCard>
                )}

                <ResultsCard title="Security findings">
                  <div className="space-y-2 p-4">
                    {result.findings.map((f,i)=>(
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/10 border border-border hover:border-primary/20 transition-colors">
                        <div className="mt-0.5"><StatusIcon s={f.status}/></div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className="font-mono text-sm font-semibold text-foreground">{f.item}</span>
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${sevCls(f.severity)}`}>{f.severity.toUpperCase()}</span>
                          </div>
                          <p className="text-xs text-muted-foreground">{f.desc}</p>
                        </div>
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
