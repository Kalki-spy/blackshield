import { useState } from "react";
import { ScanLine, AlertTriangle, Loader2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import {
  ToolBreadcrumb,
  ToolHeader,
  TwoColumn,
  ConfigCard,
  Field,
  ToolInput,
  RunButton,
  StatusCard,
  ErrorBox,
  ResultsCard,
} from "@/components/tool/ToolUI";

const BACKEND = "/api";

interface PortResult {
  port: number;
  open: boolean;
  service: string;
  latency: number | null;
  risk: "low" | "medium" | "high";
}

export default function PortScanner() {
  const { user } = useAuth();

  const [host, setHost] = useState("");
  const [portsRaw, setPortsRaw] = useState("");
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [results, setResults] = useState<PortResult[]>([]);
  const [scannedHost, setScannedHost] = useState("");

  async function handleScan() {
    const h = host.trim();
    if (!h) return;

    setError("");
    setResults([]);
    setScanning(true);
    setProgress(0);

    let p = 0;
    const tick = setInterval(() => {
      p = Math.min(p + 8, 88);
      setProgress(p);
    }, 800);

    try {
      const response = await fetch(`${BACKEND}/portscan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          host: h,
          ports: portsRaw.trim() || undefined,
          user_id: user?.id,
        }),
      });

      const text = await response.text();

      if (!text) {
        throw new Error(
          "Server returned empty response — is network_server.py running?"
        );
      }

      const data = JSON.parse(text);

      if (data.error) throw new Error(data.error);

      setProgress(100);
      await new Promise((resolve) => setTimeout(resolve, 300));

      setResults(data.results ?? []);
      setScannedHost(h);
    } catch (e: any) {
      setError(e.message || "Scan failed.");
    } finally {
      clearInterval(tick);
      setScanning(false);
    }
  }

  const openPorts = results.filter((p) => p.open);
  const closedPorts = results.filter((p) => !p.open);
  const riskyOpen = openPorts.filter((p) => p.risk === "high");

  return (
    <div className="space-y-6 max-w-6xl">
      <ToolBreadcrumb category="Reconnaissance" tool="Port Scanner" />

      <ToolHeader
        title="Port Scanner"
        description="Parallel TCP probing · Service fingerprinting · Risk scoring"
      />

      <TwoColumn
        left={
          <>
            <ConfigCard
              title="Target Configuration"
              footer={
                <RunButton
                  onClick={handleScan}
                  disabled={scanning || !host.trim()}
                >
                  {scanning ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <ScanLine className="h-4 w-4" />
                  )}
                  {scanning ? "Scanning..." : "Scan Ports"}
                </RunButton>
              }
            >
              <Field label="Host or IP">
                <ToolInput
                  value={host}
                  onChange={(e) => setHost(e.target.value)}
                  onKeyDown={(e) =>
                    e.key === "Enter" && !scanning && handleScan()
                  }
                  placeholder="Host or IP address"
                  disabled={scanning}
                />
              </Field>

              <Field label="Ports" hint="Blank scans common ports">
                <ToolInput
                  value={portsRaw}
                  onChange={(e) => setPortsRaw(e.target.value)}
                  onKeyDown={(e) =>
                    e.key === "Enter" && !scanning && handleScan()
                  }
                  placeholder="80,443 or 1-1024"
                  disabled={scanning}
                />
              </Field>

              {error && <ErrorBox message={error} />}
            </ConfigCard>

            {scanning && (
              <StatusCard
                status="Running"
                message="Probing ports..."
                progress={progress}
                elapsed=""
              />
            )}

            {results.length > 0 && (
              <div className="grid grid-cols-3 gap-2">
                {[
                  ["Open", openPorts.length, "text-foreground"],
                  [
                    "Risky",
                    riskyOpen.length,
                    riskyOpen.length > 0
                      ? "text-destructive"
                      : "text-muted-foreground",
                  ],
                  ["Closed", closedPorts.length, "text-muted-foreground"],
                ].map(([label, val, cls]) => (
                  <div
                    key={label}
                    className="bg-card border border-border rounded-md p-3 text-center"
                  >
                    <div className={`font-mono text-xl font-bold ${cls}`}>
                      {val}
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {label}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        }
        right={
          results.length > 0 ? (
            <ResultsCard
              title="Results"
              meta={
                <>
                  target{" "}
                  <span className="font-mono text-primary">
                    {scannedHost}
                  </span>
                </>
              }
            >
              <div className="space-y-2 p-4">
                {openPorts.map((p) => (
                  <div
                    key={p.port}
                    className="flex items-center gap-3 p-2.5 rounded-md bg-muted/20 border border-border hover:border-primary/30 transition-colors"
                  >
                    <div
                      className={`h-1.5 w-1.5 rounded-full shrink-0 ${
                        p.risk === "high"
                          ? "bg-destructive"
                          : p.risk === "medium"
                          ? "bg-warning"
                          : "bg-muted-foreground"
                      }`}
                    />

                    <span className="font-mono text-sm font-bold text-foreground w-16">
                      :{p.port}
                    </span>

                    <span className="font-mono text-xs text-muted-foreground w-28">
                      {p.service}
                    </span>

                    <span
                      className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border ${
                        p.risk === "high"
                          ? "bg-destructive/10 text-destructive border-destructive/30"
                          : p.risk === "medium"
                          ? "bg-warning/10 text-warning border-warning/30"
                          : "bg-muted text-muted-foreground border-border"
                      }`}
                    >
                      {p.risk === "high"
                        ? "RISKY"
                        : p.risk === "medium"
                        ? "CAUTION"
                        : "OPEN"}
                    </span>

                    {p.latency != null && (
                      <span className="font-mono text-xs text-muted-foreground ml-auto">
                        {p.latency.toFixed(1)} ms
                      </span>
                    )}

                    {p.risk === "high" && (
                      <AlertTriangle className="h-3.5 w-3.5 text-destructive shrink-0" />
                    )}
                  </div>
                ))}

                {closedPorts.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border">
                    <p className="text-[10px] text-muted-foreground mb-2">
                      {closedPorts.length} closed / filtered
                    </p>

                    <div className="flex flex-wrap gap-1.5">
                      {closedPorts.map((p) => (
                        <span
                          key={p.port}
                          className="px-1.5 py-0.5 rounded font-mono text-[9px] bg-muted/40 border border-border text-muted-foreground"
                        >
                          :{p.port}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </ResultsCard>
          ) : (
            <ResultsCard title="Results">
              <div className="py-14 text-center text-sm text-muted-foreground">
                Run a scan to see results here.
              </div>
            </ResultsCard>
          )
        }
      />
    </div>
  );
}