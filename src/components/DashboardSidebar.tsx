import { useState } from "react";
import {
  LayoutDashboard,
  Search,
  Trophy,
  GraduationCap,
  Bot,
  User,
  Settings,
  LogOut,
  ChevronRight,
  Shield,
  Network,
  Globe,
  Crosshair,
  KeyRound,
  Eye,
  ShieldHalf,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

const mainItems = [
  { title: "Dashboard", url: "/dashboard", icon: LayoutDashboard },
];

const toolCategories = [
  {
    label: "Reconnaissance",
    icon: Network,
    items: [
      { title: "Network Analyzer", url: "/dashboard/tools/network-analyzer" },
      { title: "Port Scanner", url: "/dashboard/tools/port-scanner" },
      { title: "Nmap Scanner", url: "/dashboard/tools/nmap" },
      { title: "Directory Scanner", url: "/dashboard/tools/directory-scanner" },
      { title: "Subdomain Finder", url: "/dashboard/tools/subdomain-finder" },
    ],
  },
  {
    label: "Web Security",
    icon: Globe,
    items: [
      { title: "SQL Injection Scanner", url: "/dashboard/tools/sqli-scanner" },
      { title: "SSL Analyzer", url: "/dashboard/tools/ssl-analyzer" },
      { title: "SSL Inspector", url: "/dashboard/tools/ssl-inspector" },
      { title: "Sniper", url: "/dashboard/tools/sniper" },
    ],
  },
  {
    label: "Security Testing",
    icon: Crosshair,
    items: [
      { title: "Metasploit", url: "/dashboard/tools/metasploit" },
      { title: "Firewall Tester", url: "/dashboard/tools/firewall-tester" },
      { title: "DDoS Simulator", url: "/dashboard/tools/ddos-simulator" },
    ],
  },
  {
    label: "Credential Security",
    icon: KeyRound,
    items: [
      { title: "Hashcat", url: "/dashboard/tools/hashcat" },
      { title: "Password Auditor", url: "/dashboard/tools/password-auditor" },
    ],
  },
  {
    label: "Defensive Analysis",
    icon: Eye,
    items: [
      { title: "IDS Analyzer", url: "/dashboard/tools/ids-analyzer" },
      { title: "CVE Scanner", url: "/dashboard/tools/cve-scanner" },
    ],
  },
];

const trainingItems = [
  { title: "CTFs", url: "/dashboard/ctf", icon: Trophy },
  { title: "Scenarios", url: "/dashboard/scenarios", icon: GraduationCap },
  { title: "AI Assistant", url: "/dashboard/ai-assistant", icon: Bot },
];

const accountItems = [
  { title: "Profile", url: "/dashboard/profile", icon: User },
  { title: "Settings", url: "/dashboard/settings", icon: Settings },
];

const linkBase =
  "text-[13px] text-muted-foreground hover:text-foreground hover:bg-secondary rounded-none border-l-2 border-transparent pl-[14px]";

const linkActive =
  "!bg-secondary !text-foreground border-l-2 !border-primary font-medium";

function NavItem({
  item,
  collapsed,
}: {
  item: { title: string; url: string; icon: any };
  collapsed: boolean;
}) {
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild>
        <NavLink
          to={item.url}
          end={item.url === "/dashboard" || item.url === "/dashboard/tools"}
          className={linkBase}
          activeClassName={linkActive}
        >
          <item.icon className="h-4 w-4" />
          {!collapsed && <span>{item.title}</span>}
        </NavLink>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

export function DashboardSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";

  const { signOut } = useAuth();
  const navigate = useNavigate();

  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>(
    () => Object.fromEntries(toolCategories.map((c) => [c.label, true]))
  );

  const handleLogout = async () => {
    await signOut();
    navigate("/auth");
  };

  const toggleCategory = (label: string) =>
    setOpenCategories((prev) => ({
      ...prev,
      [label]: !prev[label],
    }));

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border">
      <SidebarHeader className="h-14 border-b border-sidebar-border bg-sidebar flex flex-row items-center gap-2.5 px-4">
        <ShieldHalf className="h-[18px] w-[18px] text-primary shrink-0" />

        {!collapsed && (
          <span className="font-mono font-semibold text-sm tracking-[1.4px] text-foreground uppercase">
            Blackshield
          </span>
        )}
      </SidebarHeader>

      <SidebarContent className="bg-sidebar pt-2">
        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel className="text-[10px] font-semibold text-muted-label tracking-[1.6px] uppercase">
              Workspace
            </SidebarGroupLabel>
          )}

          <SidebarGroupContent>
            <SidebarMenu>
              {mainItems.map((item) => (
                <NavItem
                  key={item.title}
                  item={item}
                  collapsed={collapsed}
                />
              ))}

              <NavItem
                item={{
                  title: "All Tools",
                  url: "/dashboard/tools",
                  icon: Search,
                }}
                collapsed={collapsed}
              />
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel className="text-[10px] font-semibold text-muted-label tracking-[1.6px] uppercase flex items-center gap-1.5">
              <Shield className="h-3 w-3" />
              Security Tools
            </SidebarGroupLabel>
          )}

          <SidebarGroupContent>
            <SidebarMenu>
              {toolCategories.map((cat) => (
                <Collapsible
                  key={cat.label}
                  open={collapsed ? true : openCategories[cat.label]}
                  onOpenChange={() => toggleCategory(cat.label)}
                >
                  <SidebarMenuItem>
                    <CollapsibleTrigger asChild>
                      <SidebarMenuButton className="text-muted-foreground hover:text-foreground hover:bg-secondary">
                        <cat.icon className="h-4 w-4" />

                        {!collapsed && (
                          <>
                            <span className="text-[13px] font-medium flex-1 text-left">
                              {cat.label}
                            </span>

                            <ChevronRight
                              className={`h-3.5 w-3.5 transition-transform ${
                                openCategories[cat.label] ? "rotate-90" : ""
                              }`}
                            />
                          </>
                        )}
                      </SidebarMenuButton>
                    </CollapsibleTrigger>

                    {!collapsed && (
                      <CollapsibleContent>
                        <SidebarMenuSub>
                          {cat.items.map((item) => (
                            <SidebarMenuSubItem key={item.title}>
                              <SidebarMenuSubButton asChild>
                                <NavLink
                                  to={item.url}
                                  className={linkBase}
                                  activeClassName={linkActive}
                                >
                                  <span>{item.title}</span>
                                </NavLink>
                              </SidebarMenuSubButton>
                            </SidebarMenuSubItem>
                          ))}
                        </SidebarMenuSub>
                      </CollapsibleContent>
                    )}
                  </SidebarMenuItem>
                </Collapsible>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel className="text-[10px] font-semibold text-muted-label tracking-[1.6px] uppercase">
              Training
            </SidebarGroupLabel>
          )}

          <SidebarGroupContent>
            <SidebarMenu>
              {trainingItems.map((item) => (
                <NavItem
                  key={item.title}
                  item={item}
                  collapsed={collapsed}
                />
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel className="text-[10px] font-semibold text-muted-label tracking-[1.6px] uppercase">
              Account
            </SidebarGroupLabel>
          )}

          <SidebarGroupContent>
            <SidebarMenu>
              {accountItems.map((item) => (
                <NavItem
                  key={item.title}
                  item={item}
                  collapsed={collapsed}
                />
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <div className="mt-auto px-3 pb-4">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-xs font-mono text-muted-foreground hover:text-destructive hover:bg-destructive/10 border border-transparent hover:border-destructive/30 transition-all"
          >
            <LogOut className="h-4 w-4" />
            {!collapsed && "Logout"}
          </button>

          {!collapsed && (
            <p className="text-[10px] font-mono text-muted-label tracking-wider mt-3 px-1">
              SANDBOXED ENV · v1.0
            </p>
          )}
        </div>
      </SidebarContent>
    </Sidebar>
  );
}