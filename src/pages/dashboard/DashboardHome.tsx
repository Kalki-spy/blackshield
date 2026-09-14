import { useNavigate, Link } from "react-router-dom";
import {
  Activity, AlertTriangle, Bot, FileText, PlayCircle, Radar, Search, Swords, ShieldCheck, Compass,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useTeamMode, TeamMode } from "@/contexts/TeamModeContext";
import { allDocEntries } from "@/data/docsContent";

const modeInfo: Record<TeamMode, { label: string; icon: typeof Swords; color: string }> = {
  red: { label: "Red Team", icon: Swords, color: "text-red-400" },
  blue: { label: "Blue Team", icon: ShieldCheck, color: "text-blue-400" },
  explorer: { label: "Explorer", icon: Compass, color: "text-emerald-400" },
};

const TOOL_COUNT = allDocEntries.filter((e) => e.route?.startsWith("/dashboard/tools/")).length;

function PanelHeader({ icon: Icon, title, action }: { icon: typeof Activity; title: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-border px-4 py-2.5">
      <div className="flex items-center gap-2">
        <Icon className="h-3 w-3 text-muted-foreground" />
        <span className="font-semibold text-[11px] text-muted-foreground tracking-[1.5px] uppercase">{title}</span>
      </div>
      {action}
    </div>
  );
}

function EmptyRow({ text, cta, to }: { text: string; cta?: string; to?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-10 px-4 text-center">
      <p className="text-sm text-muted-foreground max-w-sm">{text}</p>
      {cta && to && (
        <Link to={to} className="text-xs font-medium text-primary hover:underline">
          {cta}
        </Link>
      )}
    </div>
  );
}

const DashboardHome = () => {
  const { user } = useAuth();
  const { mode } = useTeamMode();
  const navigate = useNavigate();
  const info = modeInfo[mode];

  return (
    <div className="flex flex-col xl:flex-row gap-6">
      {/* Main column */}
      <div className="flex-1 flex flex-col gap-6 min-w-0">
        {/* Workspace status strip */}
        <div className="bg-card border border-border rounded-md flex flex-wrap divide-x divide-border overflow-hidden">
          <div className="flex items-center gap-2.5 px-5 py-3.5">
            <span className="h-2 w-2 rounded-full bg-emerald-500 shrink-0" />
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Workspace</p>
              <p className="text-sm font-medium text-foreground">Sandboxed environment</p>
            </div>
          </div>
          <div className="px-5 py-3.5">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Signed in as</p>
            <p className="text-sm font-mono text-foreground">{user?.username ?? "—"}</p>
          </div>
          <div className="px-5 py-3.5">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Active mode</p>
            <p className={`text-sm font-medium flex items-center gap-1.5 ${info.color}`}>
              <info.icon className="h-3.5 w-3.5" /> {info.label}
            </p>
          </div>
          <div className="px-5 py-3.5">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Tools available</p>
            <p className="text-sm font-mono text-foreground">{TOOL_COUNT}</p>
          </div>
        </div>

        {/* Active Scans */}
        <div className="bg-card border border-border rounded-md">
          <PanelHeader icon={Activity} title="Active Scans" />
          <EmptyRow
            text="No scans are currently running. Each tool runs independently and doesn't yet report progress back to this dashboard."
            cta="Browse Security Tools"
            to="/dashboard/tools"
          />
        </div>

        {/* Recent Findings */}
        <div className="bg-card border border-border rounded-md">
          <PanelHeader
            icon={AlertTriangle}
            title="Recent Findings"
            action={<span className="text-[11px] text-muted-foreground">Not aggregated yet</span>}
          />
          <EmptyRow text="Findings aren't collected across tools in one place yet — open a tool's results panel directly to review what it returned." />
        </div>

        {/* Recent Activity */}
        <div className="bg-card border border-border rounded-md">
          <PanelHeader icon={Radar} title="Recent Activity" />
          <EmptyRow text="Nothing to show yet. Activity will appear here once you run a scan or check." />
        </div>
      </div>

      {/* Right sidebar */}
      <div className="w-full xl:w-[320px] flex flex-col gap-6 shrink-0">
        <div className="bg-card/40 border border-border rounded-md">
          <PanelHeader icon={ShieldCheck} title="Severity Overview" />
          <div className="px-4 py-8 text-center">
            <p className="text-sm text-muted-foreground">No findings recorded yet.</p>
          </div>
        </div>

        <div className="bg-card/40 border border-border rounded-md">
          <PanelHeader icon={Search} title="Quick Actions" />
          <div className="flex flex-col gap-2 p-3">
            <button
              onClick={() => navigate("/dashboard/tools")}
              className="flex items-center gap-2.5 bg-muted/40 border border-border rounded-md px-3 py-2.5 text-sm font-medium text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
            >
              <PlayCircle className="h-4 w-4" /> Run a tool
            </button>
            <button
              onClick={() => navigate("/docs")}
              className="flex items-center gap-2.5 bg-muted/40 border border-border rounded-md px-3 py-2.5 text-sm font-medium text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
            >
              <FileText className="h-4 w-4" /> View documentation
            </button>
            <button
              onClick={() => navigate("/dashboard/ai-assistant")}
              className="flex items-center gap-2.5 bg-muted/40 border border-border rounded-md px-3 py-2.5 text-sm font-medium text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
            >
              <Bot className="h-4 w-4" /> Open AI Assistant
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardHome;
