import { useEffect, useRef, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

const NAV_SECTIONS = [
  { id: "profile-info", label: "Profile information" },
  { id: "account-info", label: "Account information" },
  { id: "security",     label: "Security" },
  { id: "sessions",     label: "Sessions" },
  { id: "preferences",  label: "Preferences" },
];

function loadLocal<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch { return fallback; }
}

export default function Profile() {
  const { user } = useAuth();
  const [active, setActive] = useState(NAV_SECTIONS[0].id);
  const refs = useRef<Record<string, HTMLElement | null>>({});

  const storageKey = user ? `profile_${user.id}` : "profile_guest";

  const [fullName, setFullName]   = useState("");
  const [org, setOrg]             = useState("");
  const [bio, setBio]             = useState("");
  const [saved, setSaved]         = useState(false);

  const [emailDigest, setEmailDigest]     = useState(true);
  const [compactTables, setCompactTables] = useState(false);

  useEffect(() => {
    if (!user) return;
    const stored = loadLocal(storageKey, { fullName: user.username, org: "", bio: "" });
    setFullName(stored.fullName || user.username);
    setOrg(stored.org || "");
    setBio(stored.bio || "");
    setEmailDigest(loadLocal(`${storageKey}_digest`, true));
    setCompactTables(loadLocal(`${storageKey}_compact`, false));
  }, [user]);

  function saveProfile() {
    localStorage.setItem(storageKey, JSON.stringify({ fullName, org, bio }));
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  function toggleDigest() {
    const v = !emailDigest;
    setEmailDigest(v);
    localStorage.setItem(`${storageKey}_digest`, JSON.stringify(v));
  }
  function toggleCompact() {
    const v = !compactTables;
    setCompactTables(v);
    localStorage.setItem(`${storageKey}_compact`, JSON.stringify(v));
  }

  function scrollTo(id: string) {
    setActive(id);
    refs.current[id]?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const joinDate = user?.created_at
    ? new Date(user.created_at).toLocaleDateString("en-US", { month: "long", year: "numeric" })
    : "—";

  return (
    <div className="flex gap-8 max-w-4xl">
      {/* Section nav */}
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
        {/* Profile information */}
        <section ref={el => (refs.current["profile-info"] = el)} id="profile-info" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Profile information</h2>
          <p className="text-xs text-muted-foreground mb-1">Visible to other members of your workspace.</p>
          <div className="bg-card border border-border rounded-md p-5 flex flex-col gap-4">
            <div className="flex items-center gap-4">
              <div className="h-16 w-16 rounded-full bg-primary/15 border border-primary/30 flex items-center justify-center shrink-0">
                <span className="text-2xl font-bold text-primary">{(fullName || user?.username || "?")[0]?.toUpperCase()}</span>
              </div>
              <div className="flex flex-col gap-1.5">
                <span className="text-[11px] text-muted-foreground">Avatar is generated from your name — no upload needed.</span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Full name</label>
                <input
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  className="bg-muted border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Organization</label>
                <input
                  value={org}
                  onChange={e => setOrg(e.target.value)}
                  placeholder="Optional"
                  className="bg-muted border border-border rounded-md px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>
              <div className="sm:col-span-2 flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Bio</label>
                <textarea
                  value={bio}
                  onChange={e => setBio(e.target.value)}
                  rows={3}
                  placeholder="Tell your team a bit about yourself"
                  className="bg-muted border border-border rounded-md px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary resize-none"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-3">
              {saved && <span className="flex items-center gap-1 text-xs text-success"><CheckCircle2 className="h-3.5 w-3.5" /> Saved</span>}
              <button onClick={saveProfile} className="bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-4 py-2 rounded-md transition-colors">
                Save changes
              </button>
            </div>
          </div>
        </section>

        {/* Account information */}
        <section ref={el => (refs.current["account-info"] = el)} id="account-info" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Account information</h2>
          <p className="text-xs text-muted-foreground mb-1">Your login and organization details.</p>
          <div className="bg-card border border-border rounded-md p-5 flex flex-col gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Email</label>
                <div className="bg-muted border border-border rounded-md px-3 py-2">
                  <span className="font-mono text-sm text-foreground">{user?.email ?? "—"}</span>
                </div>
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-medium text-muted-foreground">Username</label>
                <div className="bg-muted border border-border rounded-md px-3 py-2">
                  <span className="font-mono text-sm text-foreground">{user?.username ?? "—"}</span>
                </div>
              </div>
            </div>
            <div className="border-t border-border pt-3 flex items-center justify-between">
              <span className="text-xs text-muted-foreground">Member since</span>
              <span className="font-mono text-xs text-muted-foreground">{joinDate}</span>
            </div>
          </div>
        </section>

        {/* Security */}
        <section ref={el => (refs.current["security"] = el)} id="security" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Security</h2>
          <p className="text-xs text-muted-foreground mb-1">Manage password and two-factor authentication.</p>
          <div className="bg-card border border-border rounded-md overflow-hidden">
            <div className="flex items-center justify-between p-4">
              <div>
                <p className="text-sm text-foreground">Password</p>
                <p className="text-xs text-muted-foreground mt-0.5">Change your account password</p>
              </div>
              <button title="Not available yet" className="border border-border text-muted-foreground text-xs px-3 py-1.5 rounded-md cursor-not-allowed opacity-60">
                Change password
              </button>
            </div>
            <div className="border-t border-border flex items-center justify-between p-4">
              <div>
                <p className="text-sm text-foreground">Two-factor authentication</p>
                <p className="text-xs text-muted-foreground mt-0.5">Not set up yet</p>
              </div>
              <button title="Not available yet" className="border border-border text-muted-foreground text-xs px-3 py-1.5 rounded-md cursor-not-allowed opacity-60">
                Set up
              </button>
            </div>
          </div>
        </section>

        {/* Sessions */}
        <section ref={el => (refs.current["sessions"] = el)} id="sessions" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Sessions</h2>
          <p className="text-xs text-muted-foreground mb-1">Devices currently signed in to your account.</p>
          <div className="bg-card border border-border rounded-md p-4 flex items-center justify-between">
            <div>
              <p className="text-sm text-foreground">This device</p>
              <p className="text-xs text-muted-foreground mt-0.5 font-mono">Current session</p>
            </div>
            <span className="text-xs text-success">Active now</span>
          </div>
        </section>

        {/* Preferences */}
        <section ref={el => (refs.current["preferences"] = el)} id="preferences" className="flex flex-col gap-1">
          <h2 className="text-sm font-semibold text-foreground">Preferences</h2>
          <p className="text-xs text-muted-foreground mb-1">Personal display and notification defaults.</p>
          <div className="bg-card border border-border rounded-md overflow-hidden">
            <button onClick={toggleDigest} className="w-full flex items-center justify-between p-4 text-left">
              <div>
                <p className="text-sm text-foreground">Email digest</p>
                <p className="text-xs text-muted-foreground mt-0.5">Weekly summary of findings and scan activity</p>
              </div>
              <span className={`h-4 w-4 rounded-sm border ${emailDigest ? "bg-primary border-primary" : "bg-transparent border-border"}`} />
            </button>
            <div className="border-t border-border" />
            <button onClick={toggleCompact} className="w-full flex items-center justify-between p-4 text-left">
              <div>
                <p className="text-sm text-foreground">Compact tables</p>
                <p className="text-xs text-muted-foreground mt-0.5">Reduce row height in findings and scan tables</p>
              </div>
              <span className={`h-4 w-4 rounded-sm border ${compactTables ? "bg-primary border-primary" : "bg-transparent border-border"}`} />
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
