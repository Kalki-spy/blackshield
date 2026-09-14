import { useState } from "react";
import {
  KeyRound, Eye, EyeOff, CheckCircle,
  AlertTriangle, XCircle, Loader2, Upload,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, ToolInput,
  ToolTextarea, RunButton, ErrorBox, ResultsCard,
} from "@/components/tool/ToolUI";

const BACKEND = "/api";

interface CharClasses { lower: boolean; upper: boolean; digit: boolean; symbol: boolean }
interface Finding { check: string; status: string; severity: string; detail: string }
interface PwdResult {
  length: number; entropy: number; crack_time: string; strength: string;
  score: number; score_pct: number; char_classes: CharClasses;
  findings: Finding[]; suggestions: string[]; hash_sha1_prefix: string; hash_md5: string;
  error?: string;
}
type Tab = "single" | "bulk";

const strengthCls = (s: string) => {
  if (s === "Very Strong" || s === "Strong") return "text-success";
  if (s === "Moderate") return "text-warning";
  if (s === "Weak") return "text-orange-400";
  return "text-destructive";
};
const strengthBarCls = (pct: number) => {
  if (pct >= 85) return "bg-success";
  if (pct >= 65) return "bg-success/70";
  if (pct >= 45) return "bg-warning";
  if (pct >= 25) return "bg-orange-500";
  return "bg-destructive";
};
const findingIcon = (s: string) => {
  if (s === "pass") return <CheckCircle className="h-4 w-4 text-success shrink-0" />;
  if (s === "warn") return <AlertTriangle className="h-4 w-4 text-warning shrink-0" />;
  return <XCircle className="h-4 w-4 text-destructive shrink-0" />;
};

export default function PasswordAuditor() {
  const [tab, setTab]           = useState<Tab>("single");
  const [pwd, setPwd]           = useState("");
  const [show, setShow]         = useState(false);
  const [loading, setLoading]   = useState(false);
  const [result, setResult]     = useState<PwdResult | null>(null);
  const [bulkText, setBulkText] = useState("");
  const [bulkRes, setBulkRes]   = useState<any>(null);
  const [error, setError]       = useState("");

  async function analyze() {
    if (!pwd) return;
    setError(""); setResult(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/password/analyze`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: pwd }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setResult(d);
    } catch (e: any) { setError(e.message || "Failed to reach password_auditor_server.py (port 8778)"); }
    finally { setLoading(false); }
  }

  async function analyzeBulk() {
    const passwords = bulkText.split("\n").map(p => p.trim()).filter(Boolean);
    if (!passwords.length) return;
    setError(""); setBulkRes(null); setLoading(true);
    try {
      const r = await fetch(`${BACKEND}/password/bulk`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ passwords }),
      });
      const text = await r.text();
      if (!text) throw new Error("Server returned empty response — make sure all backend servers are running (npm run dev)");
      const d = JSON.parse(text);
      if (d.error) throw new Error(d.error);
      setBulkRes(d);
    } catch (e: any) { setError(e.message || "Failed to reach password_auditor_server.py (port 8778)"); }
    finally { setLoading(false); }
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Credential Security" tool="Password Auditor" />
      <ToolHeader title="Password Auditor" description="Entropy analysis · Crack time estimation · Policy compliance · Bulk audit" />

      <div className="flex gap-1 p-1 rounded-md bg-muted/30 border border-border w-fit">
        {(["single", "bulk"] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => { setTab(t); setError(""); setResult(null); setBulkRes(null); }}
            className={`flex items-center gap-1.5 px-4 py-2 rounded text-xs font-medium transition-colors ${
              tab === t ? "bg-primary/20 border border-primary/40 text-primary" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "single" ? <><KeyRound className="h-3.5 w-3.5" /> Single</> : <><Upload className="h-3.5 w-3.5" /> Bulk Audit</>}
          </button>
        ))}
      </div>

      <TwoColumn
        left={
          tab === "single" ? (
            <ConfigCard
              title="Password"
              description="Passwords are analyzed locally — never stored or transmitted externally."
              footer={
                <RunButton onClick={analyze} disabled={loading || !pwd}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                  {loading ? "Analyzing..." : "Analyze"}
                </RunButton>
              }
            >
              <div className="relative">
                <ToolInput
                  type={show ? "text" : "password"}
                  value={pwd}
                  onChange={e => setPwd(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !loading && analyze()}
                  placeholder="Enter password to audit"
                  disabled={loading}
                  className="pr-10"
                />
                <button
                  onClick={() => setShow(s => !s)}
                  title={show ? "Hide password" : "Show password"}
                  aria-label={show ? "Hide password" : "Show password"}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          ) : (
            <ConfigCard
              title="Bulk audit"
              description="One password per line, max 50."
              footer={
                <RunButton onClick={analyzeBulk} disabled={loading || !bulkText.trim()}>
                  {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
                  {loading ? "Analyzing..." : "Audit all"}
                </RunButton>
              }
            >
              <ToolTextarea
                value={bulkText}
                onChange={e => setBulkText(e.target.value)}
                rows={10}
                placeholder={"password123\nP@ssw0rd!\nadmin\nTr0ub4dor&3"}
              />
              {error && <ErrorBox message={error} />}
            </ConfigCard>
          )
        }
        right={
          <>
            {tab === "single" && !result && (
              <ResultsCard title="Results">
                <div className="py-14 text-center text-sm text-muted-foreground">Analyze a password to see results here.</div>
              </ResultsCard>
            )}
            {tab === "bulk" && !bulkRes && (
              <ResultsCard title="Results">
                <div className="py-14 text-center text-sm text-muted-foreground">Audit a list to see results here.</div>
              </ResultsCard>
            )}

            {result && tab === "single" && (
              <>
                <div className="bg-card border border-border rounded-md p-4">
                  <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
                    <div>
                      <p className={`text-3xl font-black ${strengthCls(result.strength)}`}>{result.strength}</p>
                      <p className="text-xs text-muted-foreground mt-1">Score {result.score_pct}% · {result.entropy} bits entropy · Cracks in: <span className="text-foreground font-bold">{result.crack_time}</span></p>
                    </div>
                    <div className="flex gap-2">
                      {(["lower", "upper", "digit", "symbol"] as const).map(cls => (
                        <div key={cls} className={`px-2 py-1 rounded font-mono text-[10px] font-bold border ${result.char_classes[cls] ? "bg-primary/10 text-primary border-primary/30" : "bg-muted/20 text-muted-foreground/40 border-border"}`}>
                          {cls === "lower" ? "a-z" : cls === "upper" ? "A-Z" : cls === "digit" ? "0-9" : "!@#"}
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between">
                      <span className="text-[10px] text-muted-foreground uppercase">Strength</span>
                      <span className="text-[10px] text-muted-foreground">{result.score_pct}%</span>
                    </div>
                    <div className="h-2 bg-muted/30 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full transition-all duration-700 ${strengthBarCls(result.score_pct)}`} style={{ width: `${result.score_pct}%` }} />
                    </div>
                  </div>
                </div>

                <ResultsCard title="Policy checks">
                  <div className="p-4 space-y-2">
                    {result.findings.map((f, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/20 border border-border">
                        {findingIcon(f.status)}
                        <div>
                          <p className="text-xs font-bold text-foreground">{f.check}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{f.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </ResultsCard>

                {result.suggestions.length > 0 && (
                  <ResultsCard title="Recommendations">
                    <div className="p-4 space-y-2">
                      {result.suggestions.map((s, i) => (
                        <div key={i} className="flex items-start gap-2 p-2.5 rounded-md bg-primary/5 border border-primary/20">
                          <CheckCircle className="h-3.5 w-3.5 text-primary mt-0.5 shrink-0" />
                          <p className="text-xs text-muted-foreground">{s}</p>
                        </div>
                      ))}
                    </div>
                  </ResultsCard>
                )}
              </>
            )}

            {bulkRes && tab === "bulk" && (
              <>
                <div className="grid grid-cols-3 gap-2">
                  {([
                    ["Total audited", bulkRes.total,  "text-foreground"],
                    ["Weak / medium", bulkRes.weak,   bulkRes.weak > 0 ? "text-destructive" : "text-success"],
                    ["Strong",        bulkRes.strong, "text-success"],
                  ] as [string, number, string][]).map(([l, v, c]) => (
                    <div key={l} className="bg-card border border-border rounded-md p-3 text-center">
                      <div className={`font-mono text-xl font-bold ${c}`}>{v}</div>
                      <div className="text-[10px] text-muted-foreground mt-1">{l}</div>
                    </div>
                  ))}
                </div>
                <ResultsCard title="Results">
                  <div className="p-4 space-y-2">
                    {bulkRes.results.map((r: any, i: number) => (
                      <div key={i} className="flex items-center gap-3 p-2.5 rounded-md bg-muted/20 border border-border">
                        <div className={`h-2 w-2 rounded-full shrink-0 ${strengthBarCls(r.score_pct)}`} />
                        <span className="font-mono text-xs text-muted-foreground w-40 truncate">{r.password}</span>
                        <span className={`font-mono text-xs font-bold ${strengthCls(r.strength)}`}>{r.strength}</span>
                        <span className="font-mono text-[10px] text-muted-foreground ml-auto">{r.entropy}b · {r.crack_time}</span>
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
