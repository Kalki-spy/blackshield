import { useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

const NAV_SECTIONS = [
  { id: "general",       label: "General" },
  { id: "security",      label: "Security" },
  { id: "notifications", label: "Notifications" },
  { id: "interface",     label: "Interface" },
  { id: "workspace",     label: "Workspace" },
  { id: "privacy",       label: "Privacy" },
];

function loadLocal<T>(key: string, fallback: T): T {
  try { const raw = localStorage.getItem(key); return raw ? JSON.parse(raw) : fallback; } catch { return fallback; }
}
function saveLocal(key: string, value: unknown) {
  localStorage.setItem(key, JSON.stringify(value));
}

function Toggle({ on, onClick }: { on: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`h-5 w-9 rounded-full relative transition-colors shrink-0 ${on ? "bg-primary" : "bg-muted"}`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${on ? "left-[18px]" : "left-0.5"}`} />
    </button>
  );
}

function Row({ title, desc, control }: { title: string; desc: string; control: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between p-4">
      <div>
        <p className="text-sm text-foreground">{title}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
      </div>
      {control}
    </div>
  );
}

function DisabledButton({ label }: { label: string }) {
  return (
    <button title="Not available yet" className="border border-border text-muted-foreground text-xs px-3 py-1.5 rounded-md cursor-not-allowed opacity-60 shrink-0">
      {label}
    </button>
  );
}

export default function Settings() {
  const { user } = useAuth();
  const [active, setActive] = useState(NAV_SECTIONS[0].id);
  const refs = useRef<Record<string, HTMLElement | null>>({});
  const key = user ? `settings_${user.id}` : "settings_guest";

  const [displayName, setDisplayName] = useState("");
  const [timezone, setTimezone]       = useState("UTC");
  const [saved, setSaved]             = useState(false);

  const [reauth, setReauth]               = useState(true);
  const [sessionTimeout, setSessionTimeout] = useState("30 minutes");
  const [notifyCritical, setNotifyCritical] = useState(true);
  const [notifyScan, setNotifyScan]         = useState(true);
  const [weeklyDigest, setWeeklyDigest]     = useState(false);
  const [density, setDensity]               = useState("Comfortable");
  const [landing, setLanding]               = useState("Dashboard");
  const [shareAnalytics, setShareAnalytics] = useState(true);

  useEffect(() => {
    if (!user) return;
    const s = loadLocal(key, {
      displayName: user.username, timezone: "UTC", reauth: true, sessionTimeout: "30 minutes",
      notifyCritical: true, notifyScan: true, weeklyDigest: false,
      density: "Comfortable", landing: "Dashboard", shareAnalytics: true,
    });
    setDisplayName(s.displayName || user.username);
    setTimezone(s.timezone); setReauth(s.reauth); setSessionTimeout(s.sessionTimeout);
    setNotifyCritical(s.notifyCritical); setNotifyScan(s.notifyScan); setWeeklyDigest(s.weeklyDigest);
    setDensity(s.density); setLanding(s.landing); setShareAnalytics(s.shareAnalytics);
  }, [user]);

  function persist(patch: Record<string, unknown>) {
    const current = loadLocal(key, {});
    saveLocal(key, { ...current, ...patch });
  }

  function saveGeneral() {
    persist({ displayName, timezone });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function scrollTo(id: string) {
    setActive(id);
    refs.current[id]?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  return (
    <div className="flex gap-8 max-w-4xl">
      <nav className="hidden md:flex flex-col gap-1 w-[200px] shrink-0 sticky top-6 self-start">
        {NAV_SECTIONS.map(s => (
          <button
            key={s.id}
            onClick={() => scrollTo(s.id)}
            className={`text-left px-3 py-2 rounded-md text-sm transition-colors ${
              active === s.id ? "bg-card text-foreground font-medium" : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {s.label}
          </button>
        ))}
      </nav>

      <div className="flex-1 min-w-0 flex flex-col gap-10">
        {/* General */}
        <section ref={el => (refs.current["general"] = el)} id="general" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">General</h2>
          <p className="text-xs text-muted-foreground mb-1">Basic account and language preferences.</p>
          <div className="bg-card border border-border rounded-md p-5 flex flex-col gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Display name</label>
                <input value={displayName} onChange={e => setDisplayName(e.target.value)} className="bg-muted border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary" />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Timezone</label>
                <select value={timezone} onChange={e => setTimezone(e.target.value)} className="bg-muted border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                  {["UTC", "IST (UTC+5:30)", "EST (UTC-5)", "PST (UTC-8)", "CET (UTC+1)"].map(tz => <option key={tz}>{tz}</option>)}
                </select>
              </div>
            </div>
            <div className="flex items-center justify-end gap-3">
              {saved && <span className="flex items-center gap-1 text-xs text-success"><CheckCircle2 className="h-3.5 w-3.5" /> Saved</span>}
              <button onClick={saveGeneral} className="bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-4 py-2 rounded-md transition-colors">Save changes</button>
            </div>
          </div>
        </section>

        {/* Security */}
        <section ref={el => (refs.current["security"] = el)} id="security" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Security</h2>
          <p className="text-xs text-muted-foreground mb-1">Authentication and access controls for your account.</p>
          <div className="bg-card border border-border rounded-md divide-y divide-border">
            <Row
              title="Require re-authentication for destructive actions"
              desc="Prompt for password before deleting scans or reports"
              control={<Toggle on={reauth} onClick={() => { setReauth(!reauth); persist({ reauth: !reauth }); }} />}
            />
            <Row
              title="Session timeout"
              desc="Automatically sign out after inactivity"
              control={
                <select value={sessionTimeout} onChange={e => { setSessionTimeout(e.target.value); persist({ sessionTimeout: e.target.value }); }} className="bg-muted border border-border rounded-md px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                  {["15 minutes", "30 minutes", "1 hour", "4 hours", "Never"].map(v => <option key={v}>{v}</option>)}
                </select>
              }
            />
          </div>
        </section>

        {/* Notifications */}
        <section ref={el => (refs.current["notifications"] = el)} id="notifications" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Notifications</h2>
          <p className="text-xs text-muted-foreground mb-1">Choose what you're notified about and how.</p>
          <div className="bg-card border border-border rounded-md divide-y divide-border">
            <Row title="Critical findings" desc="Notify immediately when a Critical severity finding is discovered"
              control={<Toggle on={notifyCritical} onClick={() => { setNotifyCritical(!notifyCritical); persist({ notifyCritical: !notifyCritical }); }} />} />
            <Row title="Scan completion" desc="Notify when a scan you started finishes"
              control={<Toggle on={notifyScan} onClick={() => { setNotifyScan(!notifyScan); persist({ notifyScan: !notifyScan }); }} />} />
            <Row title="Weekly digest email" desc="Summary of workspace activity every Monday"
              control={<Toggle on={weeklyDigest} onClick={() => { setWeeklyDigest(!weeklyDigest); persist({ weeklyDigest: !weeklyDigest }); }} />} />
          </div>
        </section>

        {/* Interface */}
        <section ref={el => (refs.current["interface"] = el)} id="interface" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Interface</h2>
          <p className="text-xs text-muted-foreground mb-1">Adjust density and technical display defaults.</p>
          <div className="bg-card border border-border rounded-md divide-y divide-border">
            <Row title="Table density" desc="Compact rows show more results per screen"
              control={
                <select value={density} onChange={e => { setDensity(e.target.value); persist({ density: e.target.value }); }} className="bg-muted border border-border rounded-md px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                  {["Comfortable", "Compact"].map(v => <option key={v}>{v}</option>)}
                </select>
              } />
            <Row title="Default landing page" desc="Page shown after signing in"
              control={
                <select value={landing} onChange={e => { setLanding(e.target.value); persist({ landing: e.target.value }); }} className="bg-muted border border-border rounded-md px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                  {["Dashboard", "Tools", "CTF"].map(v => <option key={v}>{v}</option>)}
                </select>
              } />
          </div>
        </section>

        {/* Workspace */}
        <section ref={el => (refs.current["workspace"] = el)} id="workspace" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Workspace</h2>
          <p className="text-xs text-muted-foreground mb-1">Settings for the current sandboxed environment.</p>
          <div className="bg-card border border-border rounded-md divide-y divide-border">
            <Row title="Workspace name" desc="internal-sandbox" control={<DisabledButton label="Rename" />} />
            <Row title="Registered targets" desc="Manage the authorized scope for this workspace" control={<DisabledButton label="Manage targets" />} />
            <div className="flex items-center justify-between p-4">
              <div>
                <p className="text-sm text-destructive">Delete workspace</p>
                <p className="text-xs text-muted-foreground mt-0.5">Permanently remove this workspace and all associated data</p>
              </div>
              <button title="Not available yet" className="border border-destructive/40 text-destructive text-xs px-3 py-1.5 rounded-md cursor-not-allowed opacity-60 shrink-0">Delete</button>
            </div>
          </div>
        </section>

        {/* Privacy */}
        <section ref={el => (refs.current["privacy"] = el)} id="privacy" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Privacy</h2>
          <p className="text-xs text-muted-foreground mb-1">Control how your usage data is handled.</p>
          <div className="bg-card border border-border rounded-md divide-y divide-border">
            <Row title="Share anonymized usage analytics" desc="Helps improve tool accuracy and platform reliability"
              control={<Toggle on={shareAnalytics} onClick={() => { setShareAnalytics(!shareAnalytics); persist({ shareAnalytics: !shareAnalytics }); }} />} />
            <Row title="Export my data" desc="Download all findings, scans and account data" control={<DisabledButton label="Request export" />} />
          </div>
        </section>
      </div>
    </div>
  );
}
