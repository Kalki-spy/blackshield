import { Outlet, Link } from "react-router-dom";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { DashboardSidebar } from "@/components/DashboardSidebar";
import { TeamModeProvider, useTeamMode } from "@/contexts/TeamModeContext";
import { Shield, Wifi } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

function DashboardInner() {
  const { mode } = useTeamMode();
  const { user } = useAuth();
  const modeLabel = mode === "red" ? "Red Team" : mode === "blue" ? "Blue Team" : "Explorer";
  const modeColor = mode === "red" ? "bg-red-500" : mode === "blue" ? "bg-blue-500" : "bg-emerald-500";

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full bg-background">
        <DashboardSidebar />
        <div className="flex-1 flex flex-col">
          <header className="h-14 flex items-center border-b border-border px-4 gap-4 glass justify-between">
            <div className="flex items-center gap-4">
              <SidebarTrigger className="text-muted-foreground hover:text-foreground" />
              <Link to="/" className="flex items-center gap-2 hover:opacity-80 transition-opacity">
                <Shield className="h-5 w-5 text-primary" />
                <span className="font-mono text-sm font-bold tracking-[1.4px] text-foreground uppercase">BlackShield</span>
              </Link>
            </div>
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1.5 text-xs font-mono text-muted-foreground">
                <Wifi className="h-3.5 w-3.5" /> SANDBOX
              </span>
              {user && (
                <span className="text-xs font-mono text-primary border border-primary/30 px-2 py-0.5 rounded">
                  {user.username}
                </span>
              )}
            </div>
          </header>
          <main className="flex-1 p-6 overflow-y-auto">
            <Outlet />
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}

const DashboardLayout = () => (
  <TeamModeProvider>
    <DashboardInner />
  </TeamModeProvider>
);

export default DashboardLayout;