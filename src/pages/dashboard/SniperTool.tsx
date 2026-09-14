import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Crosshair, ChevronLeft, Loader2, XCircle, CheckCircle,
  AlertTriangle, AlertCircle, Globe, Settings, Zap,
  Download, Copy, Server, Shield, Lock,
  ChevronDown, ChevronRight, ExternalLink,
  Network, Target, Activity, Eye, Cpu,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/sniper";

// ── Types ─────────────────────────────────────────────────────────────────────
type Sev      = "critical"|"high"|"medium"|"low";
type StepSt   = "complete"|"exploitable"|"potential"|"client_side"|"blocked";

interface OpenPort  { port:number; service:string; risk:string; desc:string; banner:string; }
interface CVE       { cve:string; name:string; cvss:number; severity:Sev; year:number; exploit_type:string;
                      description:string; impact:string; remediation:string; poc:string; cwe:string;
                      mitre:string; patch_url:string; in_wild:boolean; ransomware_linked:boolean;
                      evidence:string[]; confidence:"high"|"medium"|"low"; }
interface HdrAudit  { key:string; name:string; desc:string; importance:string; present:boolean; value:string; status:"pass"|"fail"; }
interface TopoNode  { id:string; label:string; type:string; }
interface TopoEdge  { from:string; to:string; label:string; type:string; }
interface KillStep  { phase:string; tactic:string; action:string; status:StepSt; cve:string|null; }
interface TLSInfo   { version?:string; cipher?:string; subject?:Record<string,string>; issuer?:Record<string,string>;
                      not_before?:string; not_after?:string; sans?:string[]; weak_tls?:boolean; error?:string; }

interface ScanResult {
  target:string; hostname:string; ip:string; mode:string; intensity:number;
  http_status:number; timestamp:string; tech_stack:string[]; tls:TLSInfo;
  headers:Record<string,string>; header_audit:HdrAudit[];
  open_ports:OpenPort[]; cves:CVE[];
  total_cves:number; critical_count:number; high_count:number; medium_count:number; low_count:number;
  vulnerable:boolean; topology:{nodes:TopoNode[];edges:TopoEdge[]};
  kill_chain:KillStep[]; risk_score:number; risk_grade:string;
  header_pass:number; header_fail:number;
}

// ── Styling ───────────────────────────────────────────────────────────────────
const SEV_STYLE: Record<Sev,{bg:string;text:string;border:string;dot:string;bar:string}> = {
  critical: {bg:"bg-red-500/10",    text:"text-red-400",    border:"border-red-500/30",    dot:"bg-red-400",    bar:"bg-red-500"},
  high:     {bg:"bg-orange-500/10", text:"text-orange-400", border:"border-orange-500/30", dot:"bg-orange-400", bar:"bg-orange-500"},
  medium:   {bg:"bg-yellow-500/10", text:"text-yellow-400", border:"border-yellow-500/30", dot:"bg-yellow-400", bar:"bg-yellow-500"},
  low:      {bg:"bg-blue-500/10",   text:"text-blue-400",   border:"border-blue-500/30",   dot:"bg-blue-400",   bar:"bg-blue-500"},
};

const EXPLOIT_EMOJI: Record<string,string> = {
  remote_code_execution:"💀", authentication_bypass:"🔓", sql_injection:"🗄️",
  cross_site_scripting:"📜",  clickjacking:"🖱️",          csrf:"🔄",
  information_disclosure:"👁️",denial_of_service:"💥",      credential_theft:"🔑",
  privilege_escalation:"⬆️",  downgrade_attack:"📡",
};

const STEP_STYLE: Record<StepSt,string> = {
  complete:    "border-green-500/30 bg-green-500/5 text-green-400",
  exploitable: "border-red-500/30 bg-red-500/5 text-red-400",
  potential:   "border-orange-500/30 bg-orange-500/5 text-orange-400",
  client_side: "border-purple-500/30 bg-purple-500/5 text-purple-400",
  blocked:     "border-border bg-muted/20 text-muted-foreground",
};

const SCAN_STEPS: [number,string][] = [
  [7,  "Resolving DNS..."],
  [16, "Fetching HTTP response..."],
  [26, "Analysing response headers..."],
  [38, "Detecting technology stack..."],
  [50, "Scanning open ports..."],
  [63, "Matching CVE database..."],
  [74, "Building exploit paths..."],
  [83, "Generating network topology..."],
  [90, "Computing risk score..."],
];

type Tab = "overview"|"cves"|"ports"|"tls"|"headers"|"topology"|"killchain";

// ── Component ─────────────────────────────────────────────────────────────────
export default function SniperTool() {
  const navigate = useNavigate();
  const [target,      setTarget]      = useState("");
  const [mode,        setMode]        = useState<"remote"|"client"|"both">("both");
  const [intensity,   setIntensity]   = useState(2);
  const [showOpts,    setShowOpts]    = useState(false);
  const [scanning,    setScanning]    = useState(false);
  const [progress,    setProgress]    = useState(0);
  const [progMsg,     setProgMsg]     = useState("");
  const [error,       setError]       = useState("");
  const [result,      setResult]      = useState<ScanResult|null>(null);
  const [activeTab,   setActiveTab]   = useState<Tab>("overview");
  const [expanded,    setExpanded]    = useState<string|null>(null);
  const [copied,      setCopied]      = useState(false);
  const curRef = useRef(0);

  async function handleScan() {
    const t = target.trim();
    if (!t) return;
    setError(""); setResult(null); setScanning(true); setProgress(0);
    setExpanded(null); setActiveTab("overview"); curRef.current = 0;

    let si = 0;
    const tick = setInterval(() => {
      if (si < SCAN_STEPS.length) {
        curRef.current = SCAN_STEPS[si][0];
        setProgress(SCAN_STEPS[si][0]);
        setProgMsg(SCAN_STEPS[si][1]);
        si++;
      }
    }, 2500);
    const nudge = setInterval(() => {
      if (curRef.current >= 90 && curRef.current < 99) {
        curRef.current++;
        setProgress(p => Math.min(p+1, 99));
        setProgMsg("Finalising exploitation analysis...");
      }
    }, 4000);

    try {
      const res  = await fetch(`${BACKEND}/scan?${new URLSearchParams({target:t, mode, intensity:String(intensity)})}`);
      const data = await res.json();
      clearInterval(tick); clearInterval(nudge);
      if (data.error) throw new Error(data.error);
      setProgress(100); setProgMsg("Scan complete.");
      await new Promise(r => setTimeout(r, 350));
      setResult(data as ScanResult);
    } catch(e:unknown) {
      clearInterval(tick); clearInterval(nudge);
      setError(e instanceof Error ? e.message : "Backend unreachable — is sniper_server.py running?");
    } finally { setScanning(false); }
  }

  function exportJSON() {
    if (!result) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:"application/json"}));
    a.download = `sniper-${result.hostname}.json`; a.click();
  }
  function copyReport() {
    if (!result) return;
    const txt = [`Sniper Report — ${result.target}`,`Risk: ${result.risk_grade} (${result.risk_score}/100)`,
      `CVEs: ${result.total_cves} | Critical: ${result.critical_count} | High: ${result.high_count}`,``,
      ...result.cves.map(c=>`[${c.severity.toUpperCase()}] ${c.cve} — ${c.name}\n  ${c.description}`)].join("\n");
    navigator.clipboard.writeText(txt).then(()=>{setCopied(true);setTimeout(()=>setCopied(false),2000);});
  }

  const riskTextColor = (g:string) =>
    g==="CRITICAL"?"text-red-400":g==="HIGH"?"text-orange-400":g==="MEDIUM"?"text-yellow-400":"text-green-400";
  const riskBorderL = (g:string) =>
    g==="CRITICAL"?"border-l-red-500":g==="HIGH"?"border-l-orange-500":g==="MEDIUM"?"border-l-yellow-500":"border-l-green-500";

  // ── Topology SVG ─────────────────────────────────────────────────────────────
  function TopologySVG({topo}:{topo:ScanResult["topology"]}) {
    const W=540, H=220;
    const pos: Record<string,{x:number,y:number}> = {};
    const n = topo.nodes.length;
    topo.nodes.forEach((node, i) => {
      if (node.type === "attacker")      pos[node.id] = { x: 60,  y: H/2 };
      else if (node.type === "cdn")      pos[node.id] = { x: 200, y: H/2 };
      else if (node.type === "target")   pos[node.id] = { x: n>3?300:360, y: H/2 };
      else {
        const svcNodes = topo.nodes.filter(nd => nd.type.startsWith("service_"));
        const si = svcNodes.findIndex(nd => nd.id === node.id);
        const count = svcNodes.length;
        pos[node.id] = { x: 420 + (si % 3)*80, y: 60 + Math.floor(si/3)*80 };
      }
    });
    const nodeColor = (type:string) =>
      type==="attacker"?"#ef4444":type==="cdn"?"#3b82f6":type==="target"?"#f97316":
      type==="service_critical"?"#ef4444":type==="service_high"?"#f97316":"#eab308";

    return (
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full rounded-md bg-black/20 border border-border">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#374151"/>
          </marker>
        </defs>
        {topo.edges.map((e,i)=>{
          const s=pos[e.from], t=pos[e.to];
          if(!s||!t) return null;
          const mx=(s.x+t.x)/2, my=(s.y+t.y)/2;
          return (
            <g key={i}>
              <line x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                stroke={e.type==="risky"?"#ef444466":"#37415180"}
                strokeWidth={e.type==="risky"?"1.5":"1.5"}
                strokeDasharray={e.type==="risky"?"5 3":"4 2"}
                markerEnd="url(#arrow)"
              />
              <text x={mx} y={my-5} textAnchor="middle" fill="#6b7280" fontSize="8" fontFamily="monospace">{e.label}</text>
            </g>
          );
        })}
        {topo.nodes.map(node=>{
          const p=pos[node.id]; if(!p) return null;
          const col=nodeColor(node.type);
          const lines=node.label.split("\n");
          return (
            <g key={node.id}>
              <circle cx={p.x} cy={p.y} r="24" fill={col+"18"} stroke={col} strokeWidth="1.5"/>
              <circle cx={p.x} cy={p.y} r="3" fill={col} opacity="0.8"/>
              {lines.map((l,i)=>(
                <text key={i} x={p.x} y={p.y+34+(i*11)} textAnchor="middle"
                  fill="#9ca3af" fontSize="8" fontFamily="monospace">{l}</text>
              ))}
              <text x={p.x} y={p.y+4} textAnchor="middle" fill={col}
                fontSize="12" fontFamily="monospace" fontWeight="bold">
                {node.type==="attacker"?"✦":node.type==="cdn"?"☁":node.type==="target"?"◎":"⚠"}
              </text>
            </g>
          );
        })}
      </svg>
    );
  }

  // ── Overview tab ─────────────────────────────────────────────────────────────
  function OverviewTab({r}:{r:ScanResult}) {
    const sevCounts = [
      {label:"Critical", count:r.critical_count, sev:"critical" as Sev},
      {label:"High",     count:r.high_count,     sev:"high"     as Sev},
      {label:"Medium",   count:r.medium_count,   sev:"medium"   as Sev},
      {label:"Low",      count:r.low_count,       sev:"low"      as Sev},
    ];
    return (
      <div className="space-y-4">
        {/* Tech stack */}
        {r.tech_stack.length > 0 && (
          <div>
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2">Detected Stack</p>
            <div className="flex flex-wrap gap-1.5">
              {r.tech_stack.map(t=>(
                <span key={t} className="px-2 py-1 rounded-md bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono text-[10px] font-bold">{t}</span>
              ))}
            </div>
          </div>
        )}
        {/* CVE severity breakdown */}
        <div>
          <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2">CVE Severity Breakdown</p>
          <div className="space-y-2">
            {sevCounts.map(({label,count,sev})=>{
              const s=SEV_STYLE[sev];
              const pct = r.total_cves > 0 ? Math.round((count/r.total_cves)*100) : 0;
              return (
                <div key={label} className="flex items-center gap-3">
                  <span className={`font-mono text-[10px] w-14 flex-shrink-0 ${s.text}`}>{label}</span>
                  <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                    <div className={`h-full rounded-full ${s.bar} transition-all duration-700`} style={{width:`${pct}%`}}/>
                  </div>
                  <span className={`font-mono text-xs font-bold w-4 text-right ${s.text}`}>{count}</span>
                </div>
              );
            })}
          </div>
        </div>
        {/* Target info grid */}
        <div className="grid grid-cols-2 gap-2">
          {[
            ["IP Address",   r.ip],
            ["HTTP Status",  String(r.http_status)],
            ["Open Ports",   String(r.open_ports.length)],
            ["TLS Version",  r.tls?.version || (r.tls?.error ? "Error" : "N/A")],
            ["Sec Headers",  `${r.header_pass}/${r.header_audit.length} pass`],
            ["Scan Mode",    r.mode.toUpperCase()],
          ].map(([k,v])=>(
            <div key={k} className="flex justify-between px-3 py-2 rounded bg-muted/20 border border-border">
              <span className="text-[10px] font-mono text-muted-foreground">{k}</span>
              <span className={`text-[10px] font-mono font-bold ${
                k==="TLS Version" && r.tls?.weak_tls ? "text-red-400" :
                k==="HTTP Status" && r.http_status >= 400 ? "text-orange-400" : "text-foreground"
              }`}>{v}</span>
            </div>
          ))}
        </div>
        {/* Top exploitable CVE */}
        {r.cves.filter(c=>c.severity==="critical").slice(0,1).map(c=>(
          <div key={c.cve} className="p-3 rounded-md bg-red-500/10 border border-red-500/30">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-base">{EXPLOIT_EMOJI[c.exploit_type]||"⚡"}</span>
              <span className="font-mono text-xs font-bold text-red-400">TOP EXPLOIT: {c.cve}</span>
              <span className="font-mono text-xs text-muted-foreground ml-auto">CVSS {c.cvss.toFixed(1)}</span>
            </div>
            <p className="text-xs text-foreground font-semibold">{c.name}</p>
            <p className="text-xs text-muted-foreground mt-0.5">{c.description.slice(0,140)}…</p>
          </div>
        ))}
      </div>
    );
  }

  // ── CVEs tab ──────────────────────────────────────────────────────────────────
  function CVEsTab({cves}:{cves:CVE[]}) {
    if (!cves.length)
      return <div className="py-12 flex flex-col items-center gap-3 text-center">
        <CheckCircle className="h-10 w-10 text-green-400"/>
        <p className="font-mono text-sm font-bold text-foreground">No CVEs Matched</p>
        <p className="text-xs text-muted-foreground">No known vulnerabilities detected for this target fingerprint</p>
      </div>;

    return (
      <div className="space-y-2">
        {cves.map(cve=>{
          const s   = SEV_STYLE[cve.severity]??SEV_STYLE.low;
          const exp = expanded===cve.cve;
          return (
            <div key={cve.cve} className={`rounded-md border overflow-hidden ${s.border}`}>
              <button onClick={()=>setExpanded(exp?null:cve.cve)}
                className="w-full flex items-center gap-2.5 px-4 py-3 text-left hover:opacity-90 transition-opacity">
                <span className="text-xl flex-shrink-0">{EXPLOIT_EMOJI[cve.exploit_type]||"⚡"}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-black border ${s.bg} ${s.text} ${s.border}`}>
                      {cve.severity.toUpperCase()}
                    </span>
                    <span className="font-mono text-xs font-bold text-muted-foreground">{cve.cve}</span>
                    <span className="font-mono text-sm font-bold text-foreground truncate">{cve.name}</span>
                  </div>
                  <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                    <span className="text-[10px] font-mono text-muted-foreground">CVSS {cve.cvss.toFixed(1)}</span>
                    <span className="text-[10px] font-mono text-muted-foreground">{cve.year}</span>
                    {cve.in_wild      && <span className="text-[9px] font-mono font-bold px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">IN THE WILD</span>}
                    {cve.ransomware_linked && <span className="text-[9px] font-mono font-bold px-1 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">RANSOMWARE</span>}
                    <span className={`text-[9px] font-mono font-bold px-1 py-0.5 rounded border ${
                      cve.confidence==="high" ? "bg-green-500/10 text-green-400 border-green-500/20"
                      : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                    }`}>{cve.confidence.toUpperCase()} CONF</span>
                  </div>
                </div>
                {exp ? <ChevronDown className="h-4 w-4 text-muted-foreground flex-shrink-0"/>
                     : <ChevronRight className="h-4 w-4 text-muted-foreground flex-shrink-0"/>}
              </button>

              {exp && (
                <div className={`px-4 pb-4 space-y-3 border-t border-border/50 ${s.bg}`}>
                  <p className="text-xs text-foreground pt-3 leading-relaxed">{cve.description}</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-2.5 rounded bg-background/50 border border-border">
                      <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Impact</p>
                      <p className="text-xs text-foreground leading-relaxed">{cve.impact}</p>
                    </div>
                    <div className="p-2.5 rounded bg-background/50 border border-border">
                      <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Remediation</p>
                      <p className="text-xs text-foreground leading-relaxed">{cve.remediation}</p>
                    </div>
                  </div>
                  <div>
                    <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Proof of Concept</p>
                    <div className="rounded bg-black border border-border font-mono text-[10px] text-red-300 p-2.5 whitespace-pre-wrap break-all leading-relaxed">
                      {cve.poc}
                    </div>
                  </div>
                  {cve.evidence.length>0 && (
                    <div>
                      <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest mb-1">Detection Evidence</p>
                      {cve.evidence.map((ev,i)=>(
                        <div key={i} className="flex items-start gap-1.5 text-xs mb-0.5">
                          <span className="text-green-400 flex-shrink-0 mt-0.5">▸</span>
                          <span className="text-foreground">{ev}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex gap-4 text-[9px] font-mono flex-wrap">
                    <span className="text-muted-foreground">CWE: <span className="text-foreground">{cve.cwe}</span></span>
                    <span className="text-muted-foreground">MITRE: <span className="text-foreground">{cve.mitre}</span></span>
                    <span className="text-muted-foreground">Type: <span className="text-foreground">{cve.exploit_type.replace(/_/g," ")}</span></span>
                    <a href={cve.patch_url} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-1 text-blue-400 hover:text-blue-300">
                      Patch Advisory <ExternalLink className="h-2.5 w-2.5"/>
                    </a>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  // ── Ports tab ─────────────────────────────────────────────────────────────────
  function PortsTab({ports}:{ports:OpenPort[]}) {
    if (!ports.length)
      return <p className="py-10 text-center font-mono text-sm text-muted-foreground">No open ports discovered</p>;
    return (
      <div className="space-y-1.5">
        {ports.map(p=>{
          const risk = p.risk as Sev;
          const s = SEV_STYLE[risk]??SEV_STYLE.low;
          return (
            <div key={p.port} className={`flex items-start gap-3 px-3 py-2.5 rounded-md border ${s.border} ${s.bg}`}>
              <Server className={`h-4 w-4 mt-0.5 flex-shrink-0 ${s.text}`}/>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-foreground">{p.port}</span>
                  <span className={`font-mono text-xs font-bold ${s.text}`}>{p.service}</span>
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${s.bg} ${s.text} ${s.border}`}>{p.risk.toUpperCase()}</span>
                </div>
                <p className="text-xs text-muted-foreground">{p.desc}</p>
                {p.banner && <p className="font-mono text-[9px] text-muted-foreground/50 mt-0.5 truncate">↳ {p.banner}</p>}
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  // ── TLS tab ───────────────────────────────────────────────────────────────────
  function TLSTab({tls}:{tls:TLSInfo}) {
    if (tls.error) return (
      <div className="py-8 flex flex-col items-center gap-2">
        <Lock className="h-8 w-8 text-muted-foreground"/>
        <p className="font-mono text-sm text-muted-foreground">TLS info unavailable: {tls.error}</p>
      </div>
    );
    return (
      <div className="space-y-3">
        {tls.weak_tls && (
          <div className="flex items-center gap-2 p-3 rounded-md bg-red-500/10 border border-red-500/30 text-red-400 text-sm font-mono">
            <AlertCircle className="h-4 w-4 flex-shrink-0"/>
            Weak TLS version detected: {tls.version} — vulnerable to POODLE/BEAST/CRIME attacks
          </div>
        )}
        <div className="grid grid-cols-2 gap-2">
          {[
            ["Version",  tls.version||"–"],
            ["Cipher",   tls.cipher||"–"],
            ["Subject",  tls.subject?.commonName||tls.subject?.CN||"–"],
            ["Issuer",   tls.issuer?.organizationName||tls.issuer?.O||"–"],
            ["Valid From", tls.not_before||"–"],
            ["Valid To",   tls.not_after||"–"],
          ].map(([k,v])=>(
            <div key={k} className="flex justify-between px-3 py-2 rounded bg-muted/20 border border-border gap-2">
              <span className="text-[10px] font-mono text-muted-foreground flex-shrink-0">{k}</span>
              <span className={`text-[10px] font-mono font-bold text-right truncate ${k==="Version"&&tls.weak_tls?"text-red-400":"text-foreground"}`}>{v}</span>
            </div>
          ))}
        </div>
        {(tls.sans||[]).length > 0 && (
          <div>
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2">Subject Alternative Names ({tls.sans!.length})</p>
            <div className="flex flex-wrap gap-1.5">
              {tls.sans!.map(s=>(
                <span key={s} className="px-2 py-0.5 rounded bg-muted/20 border border-border font-mono text-[10px] text-foreground">{s}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ── Headers tab ───────────────────────────────────────────────────────────────
  function HeadersTab({audit,raw}:{audit:HdrAudit[];raw:Record<string,string>}) {
    return (
      <div className="space-y-4">
        <div>
          <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2">Security Header Audit</p>
          <div className="space-y-1.5">
            {audit.map(h=>(
              <div key={h.key} className={`flex items-start gap-3 px-3 py-2.5 rounded-md border ${h.present?"bg-green-500/5 border-green-500/20":"bg-red-500/5 border-red-500/20"}`}>
                {h.present ? <CheckCircle className="h-4 w-4 text-green-400 flex-shrink-0 mt-0.5"/>
                           : <XCircle    className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5"/>}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-foreground">{h.name}</span>
                    <span className={`text-[9px] font-mono font-bold ${h.present?"text-green-400":"text-red-400"}`}>
                      {h.present?"PRESENT":"MISSING"}
                    </span>
                    <span className={`text-[9px] font-mono px-1 py-0.5 rounded border ${
                      h.importance==="critical"?"text-red-400 border-red-500/20 bg-red-500/10":
                      h.importance==="high"?"text-orange-400 border-orange-500/20 bg-orange-500/10":
                      "text-muted-foreground border-border bg-muted/20"
                    }`}>{h.importance.toUpperCase()}</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{h.desc}</p>
                  {h.value && <p className="font-mono text-[9px] text-muted-foreground/60 mt-0.5 truncate">{h.value}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
        {Object.keys(raw).length > 0 && (
          <div>
            <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-2">Response Headers</p>
            <div className="space-y-1">
              {Object.entries(raw).map(([k,v])=>(
                <div key={k} className="flex gap-2 px-3 py-1.5 rounded bg-muted/20 border border-border min-w-0">
                  <span className="font-mono text-[10px] text-muted-foreground flex-shrink-0">{k}:</span>
                  <span className="font-mono text-[10px] text-foreground truncate">{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // ── Kill Chain tab ────────────────────────────────────────────────────────────
  function KillChainTab({chain}:{chain:KillStep[]}) {
    return (
      <div className="space-y-1">
        <p className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest mb-3">
          MITRE ATT&amp;CK Kill Chain — Simulated Exploit Path
        </p>
        {chain.map((step,i)=>(
          <div key={i} className="flex gap-3">
            <div className="flex flex-col items-center flex-shrink-0 pt-1">
              <div className={`h-6 w-6 rounded-full border-2 flex items-center justify-center text-[9px] font-mono font-bold ${
                step.status==="complete"   ?"border-green-400 text-green-400 bg-green-500/5":
                step.status==="exploitable"?"border-red-400 text-red-400 bg-red-500/5":
                step.status==="potential"  ?"border-orange-400 text-orange-400 bg-orange-500/5":
                step.status==="client_side"?"border-purple-400 text-purple-400 bg-purple-500/5":
                "border-muted-foreground text-muted-foreground bg-muted/20"
              }`}>{i+1}</div>
              {i<chain.length-1 && <div className="w-px flex-1 bg-border mt-1 min-h-[16px]"/>}
            </div>
            <div className={`flex-1 mb-1 p-3 rounded-md border ${STEP_STYLE[step.status]}`}>
              <div className="flex items-center gap-2 flex-wrap mb-0.5">
                <span className="font-mono text-xs font-bold text-foreground">{step.phase}</span>
                <span className="font-mono text-[9px] text-muted-foreground">{step.tactic}</span>
                <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ml-auto ${
                  step.status==="complete"    ?"text-green-400 border-green-500/20":
                  step.status==="exploitable" ?"text-red-400 border-red-500/20":
                  step.status==="potential"   ?"text-orange-400 border-orange-500/20":
                  step.status==="client_side" ?"text-purple-400 border-purple-500/20":
                  "text-muted-foreground border-border"
                }`}>{step.status.replace("_"," ").toUpperCase()}</span>
                {step.cve && <span className="text-[9px] font-mono text-red-400 font-bold">{step.cve}</span>}
              </div>
              <p className="text-xs text-foreground">{step.action}</p>
            </div>
          </div>
        ))}
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  const TABS: {id:Tab; label:(r:ScanResult)=>string; icon:React.ReactNode}[] = [
    {id:"overview",  label:()=>"Overview",                          icon:<Eye className="h-3 w-3"/>},
    {id:"cves",      label:r=>`CVEs (${r.total_cves})`,             icon:<AlertCircle className="h-3 w-3"/>},
    {id:"ports",     label:r=>`Ports (${r.open_ports.length})`,     icon:<Server className="h-3 w-3"/>},
    {id:"tls",       label:()=>"TLS",                               icon:<Lock className="h-3 w-3"/>},
    {id:"headers",   label:()=>"Headers",                           icon:<Shield className="h-3 w-3"/>},
    {id:"topology",  label:()=>"Topology",                          icon:<Network className="h-3 w-3"/>},
    {id:"killchain", label:()=>"Kill Chain",                        icon:<Target className="h-3 w-3"/>},
  ];

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Web Security" tool="Sniper" />
      <ToolHeader title="Sniper — Automatic Exploiter" description="CVE matching · exploit paths · network topology · kill chain simulation" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Target configuration"
              footer={
                <RunButton
                  onClick={handleScan}
                  disabled={scanning || !target.trim()}
                  className="bg-destructive hover:bg-destructive/90"
                >
                  {scanning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
                  {scanning ? "Exploiting..." : "Launch"}
                </RunButton>
              }
            >
              <Field label="Target">
                <ToolInput
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !scanning && handleScan()}
                  placeholder="https://target.com or 192.168.1.1"
                  disabled={scanning}
                />
              </Field>

              <button
                onClick={() => setShowOpts(v => !v)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start"
              >
                <Settings className="h-3.5 w-3.5" /> Attack options
              </button>

              {showOpts && (
                <div className="grid grid-cols-1 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">Attack mode</label>
                    <div className="flex gap-1">
                      {(["remote", "client", "both"] as const).map(m => (
                        <button
                          key={m}
                          onClick={() => setMode(m)}
                          className={`flex-1 py-1.5 rounded text-[10px] font-mono font-bold border transition-colors ${
                            mode === m ? "bg-destructive/15 text-destructive border-destructive/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {m.toUpperCase()}
                        </button>
                      ))}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-1">
                      {mode === "remote" ? "Port scan + CVE matching only" : mode === "client" ? "Header/client-side checks only" : "Full remote + client-side scan"}
                    </p>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">
                      Intensity: <span className="text-destructive">{["", "LOW", "MEDIUM", "HIGH"][intensity]}</span>
                    </label>
                    <div className="flex gap-1">
                      {[1, 2, 3].map(l => (
                        <button
                          key={l}
                          onClick={() => setIntensity(l)}
                          className={`flex-1 py-1.5 rounded text-[10px] font-mono font-bold border transition-colors ${
                            intensity === l ? "bg-destructive/15 text-destructive border-destructive/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {["LOW", "MEDIUM", "HIGH"][l - 1]}
                        </button>
                      ))}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-1">
                      {intensity === 1 ? "12 ports, fastest" : intensity === 2 ? "20 ports, balanced" : "All 34 ports, thorough"}
                    </p>
                  </div>
                </div>
              )}

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && (
              <StatusCard status="Running" message={progMsg} progress={progress} elapsed="" />
            )}

            {result && (
              <div className={`bg-card border-2 rounded-md p-4 flex flex-col gap-3 ${riskBorderL(result.risk_grade).replace("border-l-", "border-")}`}>
                <div className="flex items-baseline gap-1.5">
                  <span className={`font-mono text-3xl font-black ${riskTextColor(result.risk_grade)}`}>{result.risk_score}</span>
                  <span className="font-mono text-sm text-muted-foreground">/100</span>
                  <span className={`ml-auto px-2 py-1 rounded font-mono text-xs font-black border ${
                    SEV_STYLE[result.risk_grade.toLowerCase() as Sev]?.bg ?? ""} ${SEV_STYLE[result.risk_grade.toLowerCase() as Sev]?.text ?? ""} ${SEV_STYLE[result.risk_grade.toLowerCase() as Sev]?.border ?? ""}`}>
                    {result.risk_grade}
                  </span>
                </div>
                <p className="font-mono text-xs text-muted-foreground truncate">{result.hostname} · {result.ip}</p>
                <div className="flex gap-2">
                  <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> JSON</SecondaryButton>
                  <SecondaryButton onClick={copyReport}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}</SecondaryButton>
                </div>
              </div>
            )}
          </>
        }
        right={
          <>
            {!scanning && !result && !error && (
              <ResultsCard title="What Sniper does">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["CVE Database Matching", "15 critical CVEs matched against HTTP fingerprint, headers, open ports and body content"],
                    ["Tech Stack Detection",  "Identifies 20+ frameworks/servers from headers and HTML — WordPress, Spring, Django, Confluence, etc."],
                    ["Port Scanning",         "Discovers exposed services across 34 high-value ports, flags critical risks like Redis, MongoDB, Docker API"],
                    ["TLS Analysis",          "Checks certificate validity, negotiated cipher, weak TLS version (SSLv3, TLS 1.0/1.1)"],
                    ["Kill Chain Simulation", "MITRE ATT&CK-aligned exploit path from reconnaissance to data exfiltration"],
                    ["Network Topology",      "Visualises CDN layers, proxies, and exposed high-risk services in an attack graph"],
                  ] as [string, string][]).map(([t, d]) => (
                    <div key={t} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <Crosshair className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
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
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {([
                    ["CVEs Found",    result.total_cves,                        <Activity className="h-4 w-4 text-destructive" />, "text-destructive"],
                    ["Critical/High", result.critical_count + result.high_count, <Zap className="h-4 w-4 text-orange-400" />,       "text-orange-400"],
                    ["Open Ports",    result.open_ports.length,                 <Server className="h-4 w-4 text-primary" />,       "text-primary"],
                    ["Header Fails",  result.header_fail,                       <Shield className="h-4 w-4 text-warning" />,       "text-warning"],
                  ] as [string, number, React.ReactNode, string][]).map(([label, val, icon, tc]) => (
                    <div key={label} className="bg-card border border-border rounded-md p-3">
                      <div className="flex items-center gap-2 mb-1">{icon}<span className="text-xl font-bold text-foreground">{val}</span></div>
                      <p className={`text-[11px] ${tc}`}>{label}</p>
                    </div>
                  ))}
                </div>

                <ResultsCard title="Findings">
                  <div className="border-b border-border">
                    <div className="flex overflow-x-auto">
                      {TABS.map(tab => (
                        <button
                          key={tab.id}
                          onClick={() => setActiveTab(tab.id)}
                          className={`flex items-center gap-1.5 px-4 py-2.5 text-[11px] font-medium uppercase tracking-wide transition-colors shrink-0 ${
                            activeTab === tab.id ? "border-b-2 border-destructive text-destructive bg-destructive/5" : "text-muted-foreground hover:text-foreground"
                          }`}
                        >
                          {tab.icon}{tab.label(result)}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="p-4">
                    {activeTab === "overview"  && <OverviewTab  r={result} />}
                    {activeTab === "cves"      && <CVEsTab      cves={result.cves} />}
                    {activeTab === "ports"     && <PortsTab     ports={result.open_ports} />}
                    {activeTab === "tls"       && <TLSTab       tls={result.tls} />}
                    {activeTab === "headers"   && <HeadersTab   audit={result.header_audit} raw={result.headers} />}
                    {activeTab === "topology"  && (
                      <div className="space-y-4">
                        <TopologySVG topo={result.topology} />
                        <div className="flex flex-wrap gap-3 text-[10px] font-mono">
                          {[["bg-red-400", "Attacker"], ["bg-blue-400", "CDN/Proxy"], ["bg-orange-400", "Target"], ["bg-red-400", "Critical Svc"], ["bg-orange-400", "High Risk Svc"]].map(([dot, label]) => (
                            <div key={label} className="flex items-center gap-1.5">
                              <span className={`h-2 w-2 rounded-full ${dot}`} />
                              <span className="text-muted-foreground">{label}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {activeTab === "killchain" && <KillChainTab chain={result.kill_chain} />}
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