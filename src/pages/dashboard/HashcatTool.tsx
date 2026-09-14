import { useState } from "react";
import {
  Loader2, Search, XCircle, CheckCircle, Copy,
  Download, KeyRound, Hash, Settings,
} from "lucide-react";
import {
  ToolBreadcrumb, ToolHeader, TwoColumn, ConfigCard, Field, ToolInput,
  ToolTextarea, RunButton, StatusCard, ErrorBox, ResultsCard, SecondaryButton,
} from "@/components/tool/ToolUI";

const BACKEND = "/api/hashcat";

type HashMode = "wordlist" | "bruteforce" | "both";
type HashType = "auto" | "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512";

interface CrackResult {
  hash: string; hash_type: string; detected_types: string[]; mode: string;
  cracked: boolean; plaintext: string | null; attempts: number;
  time_seconds: number; method: string; note?: string;
}

const CRACK_STEPS: [number, string][] = [
  [10, "Loading hash..."],
  [25, "Detecting hash type..."],
  [40, "Running wordlist attack..."],
  [65, "Trying common mutations..."],
  [82, "Running brute-force..."],
  [94, "Finalising..."],
];

const SAMPLE_HASHES: { label: string; hash: string; type: HashType }[] = [
  { label: "MD5 — 'password'",  hash: "5f4dcc3b5aa765d61d8327deb882cf99", type: "md5" },
  { label: "MD5 — 'admin'",     hash: "21232f297a57a5a743894a0e4a801fc3", type: "md5" },
  { label: "SHA1 — 'hello'",    hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", type: "sha1" },
  { label: "SHA256 — '123456'", hash: "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", type: "sha256" },
];

export default function HashcatTool() {
  const [hashInput, setHashInput]     = useState("");
  const [hashType, setHashType]       = useState<HashType>("auto");
  const [mode, setMode]               = useState<HashMode>("both");
  const [wordlistRaw, setWordlistRaw] = useState("");
  const [showOptions, setShowOptions] = useState(false);

  const [cracking, setCracking]       = useState(false);
  const [progress, setProgress]       = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [error, setError]             = useState("");
  const [result, setResult]           = useState<CrackResult | null>(null);
  const [copied, setCopied]           = useState(false);

  async function handleCrack() {
    const hash = hashInput.trim();
    if (!hash) return;
    setError(""); setResult(null); setCracking(true); setProgress(0);

    let si = 0;
    const tick = setInterval(() => {
      if (si < CRACK_STEPS.length) {
        setProgress(CRACK_STEPS[si][0]);
        setProgressMsg(CRACK_STEPS[si][1]);
        si++;
      }
    }, 1200);

    try {
      const body: any = { hash, hash_type: hashType, mode };
      if (wordlistRaw.trim()) {
        body.wordlist = wordlistRaw.split("\n").map(w => w.trim()).filter(Boolean);
      }
      const res  = await fetch(`${BACKEND}/crack`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      clearInterval(tick);
      if (data.error) throw new Error(data.error);
      setProgress(100);
      setProgressMsg("Complete.");
      await new Promise(r => setTimeout(r, 200));
      setResult(data as CrackResult);
    } catch (e: any) {
      clearInterval(tick);
      setError(e.message || "Failed to reach backend. Is hashcat_server.py running?");
    } finally {
      setCracking(false);
    }
  }

  function loadSample(s: typeof SAMPLE_HASHES[0]) {
    setHashInput(s.hash);
    setHashType(s.type);
    setResult(null);
    setError("");
  }

  function copyResult() {
    if (!result?.plaintext) return;
    navigator.clipboard.writeText(result.plaintext).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function exportJSON() {
    if (!result) return;
    const blob = new Blob(
      [JSON.stringify({ ...result, timestamp: new Date().toISOString() }, null, 2)],
      { type: "application/json" }
    );
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `hashcat-result-${Date.now()}.json`;
    a.click();
  }

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Credential Security" tool="Hashcat" />
      <ToolHeader title="Hashcat" description="Password hash cracking via wordlist, mutation, and brute-force attacks" />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Hash to crack"
              footer={
                <RunButton onClick={handleCrack} disabled={cracking || !hashInput.trim()}>
                  {cracking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                  {cracking ? "Cracking..." : "Crack"}
                </RunButton>
              }
            >
              <div className="flex flex-wrap gap-1.5">
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest self-center mr-1">Samples:</span>
                {SAMPLE_HASHES.map(s => (
                  <button
                    key={s.hash}
                    onClick={() => loadSample(s)}
                    className="px-2 py-1 rounded bg-muted border border-border text-[10px] text-muted-foreground hover:text-foreground hover:border-primary/30 transition-colors"
                  >
                    {s.label}
                  </button>
                ))}
              </div>

              <Field label="Hash">
                <ToolInput
                  value={hashInput}
                  onChange={e => setHashInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !cracking && handleCrack()}
                  placeholder="5f4dcc3b5aa765d61d8327deb882cf99"
                  disabled={cracking}
                />
              </Field>

              <button onClick={() => setShowOptions(v => !v)} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start">
                <Settings className="h-3.5 w-3.5" /> Attack options
              </button>

              {showOptions && (
                <div className="flex flex-col gap-4">
                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">Hash type</label>
                    <div className="flex flex-wrap gap-1">
                      {(["auto", "md5", "sha1", "sha256", "sha512"] as HashType[]).map(t => (
                        <button
                          key={t}
                          onClick={() => setHashType(t)}
                          className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold border transition-colors ${
                            hashType === t ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {t.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-muted-foreground mb-1.5">Attack mode</label>
                    <div className="flex gap-1">
                      {(["wordlist", "bruteforce", "both"] as HashMode[]).map(m => (
                        <button
                          key={m}
                          onClick={() => setMode(m)}
                          className={`flex-1 py-1.5 rounded text-[10px] font-mono font-bold border transition-colors ${
                            mode === m ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border hover:text-foreground"
                          }`}
                        >
                          {m.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <Field label="Custom wordlist" hint="One password per line — optional">
                    <ToolTextarea
                      value={wordlistRaw}
                      onChange={e => setWordlistRaw(e.target.value)}
                      placeholder={"mypassword\nletmein\nhunter2"}
                      rows={3}
                      className="text-xs"
                    />
                  </Field>
                </div>
              )}

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {cracking && <StatusCard status="Running" message={progressMsg} progress={progress} elapsed="" />}
          </>
        }
        right={
          <>
            {!cracking && !result && !error && (
              <ResultsCard title="Supported attacks">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4">
                  {([
                    ["Wordlist Attack", "Tests thousands of common passwords and known weak credentials"],
                    ["Mutation Engine", "Applies capitalization, number suffixes, and symbol variants"],
                    ["Brute-Force",     "Exhaustive character-set search for short passwords (≤4 chars)"],
                    ["Auto-Detection",  "Identifies hash type by length — MD5, SHA1, SHA256, SHA512"],
                  ] as [string, string][]).map(([title, desc]) => (
                    <div key={title} className="flex gap-2.5 p-3 rounded-md bg-muted/20 border border-border">
                      <KeyRound className="h-4 w-4 text-primary mt-0.5 shrink-0" />
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
              <ResultsCard
                title={result.cracked ? "Hash cracked" : "Not cracked"}
                meta={
                  result.cracked && (
                    <div className="flex gap-2">
                      <SecondaryButton onClick={copyResult}><Copy className="h-3.5 w-3.5" /> {copied ? "Copied!" : "Copy"}</SecondaryButton>
                      <SecondaryButton onClick={exportJSON}><Download className="h-3.5 w-3.5" /> Export</SecondaryButton>
                    </div>
                  )
                }
              >
                <div className="p-4 flex flex-col gap-4">
                  <div className="flex items-center gap-3">
                    {result.cracked ? <CheckCircle className="h-7 w-7 text-success" /> : <XCircle className="h-7 w-7 text-destructive" />}
                    <div>
                      <p className={`text-lg font-bold ${result.cracked ? "text-success" : "text-destructive"}`}>{result.cracked ? "HASH CRACKED" : "NOT CRACKED"}</p>
                      <p className="text-xs text-muted-foreground">{result.method} · {result.attempts.toLocaleString("en-US")} attempts · {result.time_seconds}s</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <div>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Hash</p>
                        <p className="font-mono text-xs text-foreground break-all">{result.hash}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Algorithm</p>
                        <p className="font-mono text-sm text-primary uppercase">{result.hash_type}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1">Detected types</p>
                        <div className="flex flex-wrap gap-1">
                          {result.detected_types.map(t => (
                            <span key={t} className="px-2 py-0.5 rounded bg-muted text-[10px] font-mono text-muted-foreground border border-border">{t.toUpperCase()}</span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="space-y-3">
                      {result.cracked ? (
                        <div className="p-4 rounded-md bg-success/10 border border-success/30">
                          <p className="text-[10px] text-success/70 uppercase tracking-widest mb-1">Plaintext password</p>
                          <p className="font-mono text-2xl font-bold text-success">{result.plaintext}</p>
                        </div>
                      ) : (
                        <div className="p-4 rounded-md bg-destructive/10 border border-destructive/30">
                          <p className="text-[10px] text-destructive/70 uppercase tracking-widest mb-1">Result</p>
                          <p className="text-sm text-destructive">
                            Hash not found in wordlist or brute-force range. Try adding a custom wordlist or use a dedicated tool with a larger wordlist.
                          </p>
                          {result.note && <p className="text-xs text-muted-foreground mt-2">{result.note}</p>}
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-2">
                        <div className="p-3 rounded-md bg-muted/20 border border-border text-center">
                          <p className="font-mono text-lg font-bold text-foreground">{result.attempts.toLocaleString("en-US")}</p>
                          <p className="text-[10px] text-muted-foreground">Attempts</p>
                        </div>
                        <div className="p-3 rounded-md bg-muted/20 border border-border text-center">
                          <p className="font-mono text-lg font-bold text-foreground">{result.time_seconds}s</p>
                          <p className="text-[10px] text-muted-foreground">Time</p>
                        </div>
                      </div>
                    </div>
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
