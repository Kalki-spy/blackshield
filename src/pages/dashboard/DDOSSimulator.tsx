import { useState, useRef, useEffect, useCallback } from "react";
import {
  ShieldAlert, XCircle, AlertTriangle, ShieldCheck, ShieldX,
  Activity, Globe, Download, Copy, Play, Square, Zap, Radio, X,
} from "lucide-react";
import {
  ToolBreadcrumb, TwoColumn, ConfigCard, Field, ToolSelect, Checkbox,
  ErrorBox, ResultsCard, SecondaryButton, EmptyResults,
} from "@/components/tool/ToolUI";
import { useAuth } from "@/contexts/AuthContext";

const BACKEND = "/api";

interface TrafficPacket { ts: string; src: string; port: number; proto: string; size: number }
interface DDOSAlert {
  type: string; severity: "critical" | "high" | "medium" | "low";
  src: string; detail: string; ts: string; rule: string;
}
interface LiveData {
  running: boolean; total_pkts: number;
  recent:    TrafficPacket[];
  alerts:    DDOSAlert[];
  top_ips:   { ip: string; count: number }[];
  top_ports: { port: number; count: number }[];
  protocols: Record<string, number>;
  avg_latency_ms: number | null;
}
interface HistoryItem { id: number; tool: string; message: string; created_at: string }

// Real, current backend constraints (backend/ddos_server.py) — kept in sync
// with the actual enforced values rather than restated as marketing copy.
const MAX_DURATION_S = 120;   // _run_simulation: duration = max(1, min(duration, 120))
const MAX_PPS        = 2000;  // _run_simulation: pps = max(1, min(pps, 2000))

const SANDBOX_TARGET = { id: "internal-sandbox", label: "BlackShield Sandbox Node (internal, loopback-only)" };

const ATTACK_TYPES = [
  { id: "syn_flood",  label: "SYN flood (network layer)" },
  { id: "udp_flood",  label: "UDP flood (network layer)" },
  { id: "http_flood", label: "HTTP flood (application layer)" },
  { id: "icmp_flood", label: "ICMP ping flood (network layer)" },
  { id: "botnet",     label: "Botnet DDoS (distributed)" },
  { id: "slowloris",  label: "Slowloris (application layer)" },
  { id: "amplify",    label: "Amplification attack (network layer)" },
  { id: "normal",     label: "Normal traffic (baseline)" },
];

const alertSeverityBadge = (s: string) => {
  if (s === "critical") return "bg-destructive/15 text-destructive border border-destructive/40";
  if (s === "high")     return "bg-orange-500/15 text-orange-400 border border-orange-500/40";
  if (s === "medium")   return "bg-warning/15 text-warning border border-warning/40";
  return "bg-primary/15 text-primary border border-primary/40";
};

const alertIcon = (s: string) => {
  if (s === "critical") return <ShieldAlert   className="h-4 w-4 text-destructive shrink-0" />;
  if (s === "high")     return <XCircle       className="h-4 w-4 text-orange-400 shrink-0" />;
  return                       <AlertTriangle className="h-4 w-4 text-warning shrink-0" />;
};

const PROTO_COLORS: Record<string, string> = {
  TCP: "#3b82f6", UDP: "#f97316", HTTP: "#a78bfa",
  HTTPS: "#34d399", ICMP: "#f43f5e", DNS: "#facc15",
  NTP: "#94a3b8", UNKNOWN: "#475569",
};

export default function DDOSSimulator() {
  const { user } = useAuth();

  const [attackType, setAttackType] = useState("syn_flood");
  const [duration,   setDuration]   = useState(20);
  const [pps,        setPps]        = useState(80);
  const [live,       setLive]       = useState<LiveData | null>(null);
  const [error,      setError]      = useState("");
  const [copied,     setCopied]     = useState(false);

  const [confirmScope,      setConfirmScope]      = useState(false);
  const [confirmUnderstand, setConfirmUnderstand] = useState(false);

  const [history,        setHistory]        = useState<HistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const logRef  = useRef<HTMLDivElement>(null);
  const wasRunning = useRef(false);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [live?.recent]);

  const stopPoll = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  const fetchHistory = useCallback(async () => {
    if (!user?.id) return;
    setHistoryLoading(true);
    try {
      const r = await fetch(`${BACKEND}/activity/summary?user_id=${user.id}`);
      const d = await r.json();
      const items: HistoryItem[] = (d.recent_activity ?? []).filter(
        (a: HistoryItem) => a.tool === "DDoS Simulation"
      );
      setHistory(items);
    } catch {
      // History is a nice-to-have on this page — leave the existing list as-is on failure.
    } finally {
      setHistoryLoading(false);
    }
  }, [user?.id]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  const startPoll = useCallback(() => {
    pollRef.current = setInterval(async () => {
      try {
        const r = await fetch(`${BACKEND}/ddos/live`);
        const d: LiveData = await r.json();
        setLive(d);
        if (!d.running) stopPoll();
      } catch {}
    }, 600);
  }, [stopPoll]);

  useEffect(() => () => stopPoll(), [stopPoll]);

  // Re-fetch history once a run transitions from running -> finished.
  useEffect(() => {
    const running = live?.running ?? false;
    if (wasRunning.current && !running) fetchHistory();
    wasRunning.current = running;
  }, [live?.running, fetchHistory]);

  async function startSim() {
    setError("");
    try {
      const fd = new FormData();
      fd.append("attack_type", attackType);
      fd.append("duration",    String(duration));
      fd.append("pps",         String(pps));
      fd.append("target",      SANDBOX_TARGET.id);
      if (user?.id) fd.append("user_id", String(user.id));
      const r = await fetch(`${BACKEND}/ddos/simulate`, { method: "POST", body: fd });
      const d = await r.json();
      if (d.error) throw new Error(d.error);
      startPoll();
    } catch (e: any) {
      setError(e.message || "Failed to reach backend. Is ddos_server.py running on port 8775?");
    }
  }

  async function stopSim() {
    stopPoll();
    try { await fetch(`${BACKEND}/ddos/stop`, { method: "POST" }); } catch {}
    const r = await fetch(`${BACKEND}/ddos/live`).catch(() => null);
    if (r) setLive(await r.json());
    fetchHistory();
  }

  function cancelConfirm() {
    setConfirmScope(false);
    setConfirmUnderstand(false);
  }

  function exportJSON() {
    if (!live) return;
    const blob = new Blob([JSON.stringify(live, null, 2)], { type: "application/json" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `ddos-report-${attackType}.json`; a.click();
  }

  function copyReport() {
    if (!live) return;
    const lines = [
      `DDoS Detection Report — ${attackType}`,
      `Total packets: ${live.total_pkts}`,
      `Alerts: ${live.alerts.length}`,
      "",
      ...live.alerts.map(a => `[${a.severity.toUpperCase()}] ${a.type}: ${a.detail}`),
    ].join("\n");
    navigator.clipboard.writeText(lines).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 2000);
    });
  }

  function historyResult(message: string): { label: string; cls: string } {
    if (message.includes("failed"))    return { label: "Failed",    cls: "text-destructive" };
    if (message.includes("completed")) return { label: "Completed", cls: "text-success" };
    return { label: "Started", cls: "text-muted-foreground" };
  }

  const isRunning  = live?.running ?? false;
  const totalPkts  = live?.total_pkts ?? 0;
  const alertCount = live?.alerts?.length ?? 0;
  const protoData  = live?.protocols ?? {};
  const protoTotal = Object.values(protoData).reduce((a, b) => a + b, 0) || 1;
  const canStart   = confirmScope && confirmUnderstand && !isRunning;

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Security Testing" tool="DDoS Simulator" />

      <div className="flex items-start gap-3 px-4 py-3.5 rounded-md bg-warning/10 border border-warning/30">
        <ShieldAlert className="h-5 w-5 text-warning shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-bold text-warning mb-1">Controlled Security Simulation</p>
          <p className="text-xs text-muted-foreground leading-relaxed">
            This tool generates bounded, rate-limited traffic against systems you own or are
            explicitly authorized to test. It runs only against the sandbox target below and
            never sends any real network traffic — every packet in this simulation is synthetic
            and generated in-memory. This is a simulation for resilience-testing and detection
            demonstration purposes, not a real-world attack capability.
          </p>
        </div>
      </div>

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Simulation configuration"
              description="Test infrastructure resilience against traffic-flood patterns in an isolated environment."
            >
              <Field label="Target environment" hint="Only the registered sandbox target is selectable.">
                <ToolSelect value={SANDBOX_TARGET.id} disabled aria-label="Target environment">
                  <option value={SANDBOX_TARGET.id}>{SANDBOX_TARGET.label}</option>
                </ToolSelect>
              </Field>

              <Field label="Simulation type">
                <ToolSelect
                  value={attackType}
                  disabled={isRunning}
                  onChange={e => setAttackType(e.target.value)}
                  aria-label="Simulation type"
                >
                  {ATTACK_TYPES.map(at => (
                    <option key={at.id} value={at.id}>{at.label}</option>
                  ))}
                </ToolSelect>
              </Field>

              <div>
                <div className="flex justify-between mb-1.5">
                  <span className="text-xs font-medium text-muted-foreground">Duration</span>
                  <span className="text-xs font-mono text-destructive font-bold">{duration} sec</span>
                </div>
                <input type="range" min="5" max={MAX_DURATION_S} value={duration} disabled={isRunning}
                  title="Simulation duration in seconds"
                  aria-label={`Simulation duration: ${duration} seconds`}
                  onChange={e => setDuration(+e.target.value)}
                  className="w-full accent-destructive disabled:opacity-50" />
                <p className="text-[11px] text-muted-foreground/70 mt-1">
                  Maximum simulation duration is capped at {MAX_DURATION_S} seconds.
                </p>
              </div>

              <div>
                <div className="flex justify-between mb-1.5">
                  <span className="text-xs font-medium text-muted-foreground">Traffic limit</span>
                  <span className="text-xs font-mono text-destructive font-bold">{pps} req/s</span>
                </div>
                <input type="range" min="10" max={MAX_PPS} value={pps} disabled={isRunning}
                  title="Traffic rate (requests per second)"
                  aria-label={`Traffic limit: ${pps} requests per second`}
                  onChange={e => setPps(+e.target.value)}
                  className="w-full accent-destructive disabled:opacity-50" />
                <p className="text-[11px] text-muted-foreground/70 mt-1">
                  Hard ceiling enforced by the platform: {MAX_PPS.toLocaleString()} req/s.
                </p>
              </div>
            </ConfigCard>

            <ConfigCard title="Safety status">
              {([
                ["Target scope", "Sandbox-only", true],
                ["Traffic ceiling", "Enforced", true],
                ["Automatic stop", "Enabled at duration limit", true],
                ["Simulated traffic", "No packets ever leave this process", true],
              ] as [string, string, boolean][]).map(([label, val, ok]) => (
                <div key={label} className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{label}</span>
                  <span className={`flex items-center gap-1.5 font-medium ${ok ? "text-success" : "text-destructive"}`}>
                    {ok ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldX className="h-3.5 w-3.5" />}
                    {val}
                  </span>
                </div>
              ))}
            </ConfigCard>
          </>
        }
        right={
          <>
            {!isRunning ? (
              <ConfigCard
                title="Confirm before starting"
                footer={
                  <div className="flex gap-2 flex-wrap items-center">
                    <button
                      onClick={startSim}
                      disabled={!canStart}
                      className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-md bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                    >
                      <Play className="h-4 w-4" /> Start simulation
                    </button>
                    <SecondaryButton onClick={cancelConfirm}>
                      <X className="h-3.5 w-3.5" /> Cancel
                    </SecondaryButton>
                    <span className="text-[11px] text-muted-foreground/70 ml-1">
                      Both confirmations are required before the simulation can be started.
                    </span>
                  </div>
                }
              >
                <Checkbox
                  checked={confirmScope}
                  onChange={setConfirmScope}
                  label={`I confirm ${SANDBOX_TARGET.label} is a sandbox environment I own or am authorized to test.`}
                />
                <Checkbox
                  checked={confirmUnderstand}
                  onChange={setConfirmUnderstand}
                  label="I understand this is a controlled simulation, not a real-world attack, and traffic is bounded by platform limits."
                />
                {error && <ErrorBox message={error} />}
              </ConfigCard>
            ) : (
              <ConfigCard
                title="Simulation running"
                footer={
                  <button onClick={stopSim} className="flex items-center gap-2 px-4 py-2.5 rounded-md bg-muted/30 border border-border text-muted-foreground font-medium text-sm hover:text-foreground transition-colors">
                    <Square className="h-4 w-4" /> Stop simulation
                  </button>
                }
              >
                <div className="flex items-center gap-2 text-sm text-destructive">
                  <span className="h-2 w-2 rounded-full bg-destructive animate-pulse" />
                  Generating synthetic {ATTACK_TYPES.find(a => a.id === attackType)?.label.toLowerCase()} traffic against {SANDBOX_TARGET.label}...
                </div>
              </ConfigCard>
            )}

            <ResultsCard title="Simulation history">
              {historyLoading && history.length === 0 ? (
                <EmptyResults text="Loading history..." />
              ) : history.length === 0 ? (
                <EmptyResults text="No simulations run yet — results will appear here after your first run." />
              ) : (
                <div className="divide-y divide-border">
                  <div className="grid grid-cols-[1fr_auto_auto] gap-3 px-4 py-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                    <span>Type</span><span>Result</span><span>Date</span>
                  </div>
                  {history.map(h => {
                    const res = historyResult(h.message);
                    return (
                      <div key={h.id} className="grid grid-cols-[1fr_auto_auto] gap-3 px-4 py-2.5 items-center">
                        <span className="text-xs font-mono text-foreground truncate">{h.message}</span>
                        <span className={`text-xs font-medium ${res.cls}`}>{res.label}</span>
                        <span className="text-[11px] text-muted-foreground">{new Date(h.created_at).toLocaleDateString()}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </ResultsCard>

            {live && !isRunning && (
              <div className="flex gap-2 justify-end">
                <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> Export</SecondaryButton>
                <SecondaryButton onClick={copyReport}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}</SecondaryButton>
              </div>
            )}

            {live && (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                  {([
                    ["Total Packets", totalPkts,               "text-foreground",  <Activity className="h-4 w-4 text-muted-foreground" />],
                    ["Unique IPs",    live.top_ips.length,     "text-primary",     <Globe className="h-4 w-4 text-primary" />],
                    ["Alerts",        alertCount,               alertCount > 0 ? "text-destructive" : "text-success", <ShieldAlert className="h-4 w-4" />],
                    ["Status",        isRunning ? "LIVE" : "DONE", isRunning ? "text-destructive" : "text-success",   <Radio className="h-4 w-4" />],
                    ["Sandbox Latency", live.avg_latency_ms != null ? `${live.avg_latency_ms}ms` : "—", "text-warning", <Zap className="h-4 w-4 text-warning" />],
                  ] as [string, string | number, string, JSX.Element][]).map(([label, val, cls, icon]) => (
                    <div key={label} className="bg-card border border-border rounded-md p-3">
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</span>
                        {icon}
                      </div>
                      <div className={`font-mono text-lg font-bold ${cls}`}>{val}</div>
                      {isRunning && label === "Status" && (
                        <div className="flex items-center gap-1 mt-1">
                          <span className="h-1.5 w-1.5 rounded-full bg-destructive animate-pulse" />
                          <span className="text-[9px] text-destructive">DETECTING</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <ResultsCard title="Protocol breakdown">
                    <div className="p-4 space-y-3">
                      {Object.entries(protoData).sort((a, b) => b[1] - a[1]).map(([proto, cnt]) => {
                        const pct = Math.round((cnt / protoTotal) * 100);
                        const col = PROTO_COLORS[proto] ?? PROTO_COLORS.UNKNOWN;
                        return (
                          <div key={proto}>
                            <div className="flex justify-between mb-0.5">
                              <span className="font-mono text-xs text-foreground">{proto}</span>
                              <span className="font-mono text-xs text-muted-foreground">{cnt} pkts ({pct}%)</span>
                            </div>
                            <div className="h-1.5 bg-muted/30 rounded-full overflow-hidden">
                              <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, backgroundColor: col }} />
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </ResultsCard>

                  <ResultsCard title="Top source IPs">
                    <div className="p-4 space-y-2">
                      {live.top_ips.slice(0, 8).map(({ ip, count }) => {
                        const pct = Math.round((count / totalPkts) * 100);
                        const isHigh = pct > 20;
                        return (
                          <div key={ip} className="flex items-center gap-2">
                            <span className={`font-mono text-[10px] w-28 truncate ${isHigh ? "text-destructive" : "text-muted-foreground"}`}>{ip}</span>
                            <div className="flex-1 h-1.5 bg-muted/30 rounded-full overflow-hidden">
                              <div className={`h-full rounded-full transition-all duration-300 ${isHigh ? "bg-destructive" : "bg-primary"}`} style={{ width: `${pct}%` }} />
                            </div>
                            <span className="font-mono text-[10px] text-muted-foreground w-10 text-right">{pct}%</span>
                          </div>
                        );
                      })}
                    </div>
                  </ResultsCard>
                </div>

                {live.alerts.length > 0 && (
                  <ResultsCard title={`DDoS alerts triggered (${live.alerts.length})`}>
                    <div className="p-4 space-y-2">
                      {live.alerts.map((a, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/20 border border-border hover:border-primary/20 transition-colors">
                          {alertIcon(a.severity)}
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="font-mono text-sm font-semibold text-foreground">{a.type}</span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${alertSeverityBadge(a.severity)}`}>{a.severity.toUpperCase()}</span>
                              <span className="text-[10px] text-muted-foreground ml-auto">{a.ts}</span>
                            </div>
                            <p className="text-xs text-muted-foreground">{a.detail}</p>
                            <p className="text-[10px] text-muted-foreground/60 mt-0.5">Rule: {a.rule}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}

                <ResultsCard title="Live packet log">
                  <div ref={logRef} className="h-48 overflow-y-auto font-mono text-[10px] space-y-0.5 p-4 scrollbar-thin">
                    {live.recent.slice().reverse().map((pkt, i) => (
                      <div key={i} className="flex items-center gap-3 px-2 py-0.5 rounded hover:bg-muted/20">
                        <span className="text-muted-foreground/60 w-14">{pkt.ts}</span>
                        <span className={`w-20 font-bold ${pkt.proto === "HTTP" || pkt.proto === "HTTPS" ? "text-purple-400" : pkt.proto === "UDP" ? "text-orange-400" : pkt.proto === "ICMP" ? "text-pink-400" : "text-primary"}`}>{pkt.proto}</span>
                        <span className="text-muted-foreground w-28 truncate">{pkt.src}</span>
                        <span className="text-muted-foreground">→ :{pkt.port}</span>
                        <span className="text-muted-foreground/50 ml-auto">{pkt.size}B</span>
                      </div>
                    ))}
                    {live.recent.length === 0 && <p className="text-muted-foreground/40 text-center pt-4">Waiting for traffic...</p>}
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