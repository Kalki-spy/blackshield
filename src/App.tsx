import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import Index from "./pages/Index";
import Auth from "./pages/Auth";
import ServiceDetail from "./pages/ServiceDetail";
import DashboardLayout from "./pages/DashboardLayout";
import DashboardHome from "./pages/dashboard/DashboardHome";
import Profile from "./pages/dashboard/Profile";
import Tools from "./pages/dashboard/Tools";
import CTF from "./pages/dashboard/CTF";
import Scenarios from "./pages/dashboard/Scenarios";
import AIAssistant from "./pages/dashboard/AIAssistant";
import SettingsPage from "./pages/dashboard/Settings";
import SSLAnalyzer from "./pages/dashboard/SSLAnalyzer";
import SubdomainFinder from "./pages/dashboard/SubdomainFinder";
import GobusterTool from "./pages/dashboard/GobusterTool";
import SQLMapTool from "./pages/dashboard/SQLMapTool";
import SniperTool from "./pages/dashboard/SniperTool";
import HashcatTool from "./pages/dashboard/HashcatTool";
import MetasploitTool from "./pages/dashboard/MetasploitTool";
import IDSAnalyzer from "./pages/dashboard/IDSAnalyzer";
import DDOSSimulator from "./pages/dashboard/DDOSSimulator";
import PortScanner from "./pages/dashboard/PortScanner";
import NetworkAnalyzer from "./pages/dashboard/NetworkAnalyzer";
import SSLInspector from "./pages/dashboard/SSLInspector";
import FirewallTester from "./pages/dashboard/FirewallTester";
import PasswordAuditor from "./pages/dashboard/PasswordAuditor";
import CVEScanner from "./pages/dashboard/CVEScanner";
import NotFound from "./pages/NotFound";
import SubServiceDetail from "./pages/SubServiceDetail";
import NmapTool from "./pages/dashboard/NmapTool";
import Documentation from "./pages/Documentation";

const queryClient = new QueryClient();

// Protect dashboard routes — redirect to /auth if not logged in
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <span className="font-mono text-primary animate-pulse">Initializing...</span>
      </div>
    );
  }
  if (!user) return <Navigate to="/auth" replace />;
  return <>{children}</>;
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/auth" element={<Auth />} />
            <Route path="/services/:serviceId" element={<ServiceDetail />} />
            <Route path="/services/:serviceId/:subServiceId" element={<SubServiceDetail />} />
            <Route path="/docs" element={<Documentation />} />
            <Route path="/docs/:slug" element={<Documentation />} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <DashboardLayout />
                </ProtectedRoute>
              }
            >
              <Route index element={<DashboardHome />} />
              <Route path="profile" element={<Profile />} />
              <Route path="tools" element={<Tools />} />
              <Route path="tools/ssl-analyzer" element={<SSLAnalyzer />} />
              <Route path="tools/subdomain-finder" element={<SubdomainFinder />} />
              <Route path="tools/directory-scanner" element={<GobusterTool />} />
              <Route path="tools/sqli-scanner" element={<SQLMapTool />} />
              <Route path="tools/sniper" element={<SniperTool />} />
              <Route path="tools/hashcat" element={<HashcatTool />} />
              <Route path="tools/metasploit" element={<MetasploitTool />} />
              <Route path="tools/ids-analyzer" element={<IDSAnalyzer />} />
              <Route path="tools/ddos-simulator" element={<DDOSSimulator />} />
              <Route path="tools/port-scanner" element={<PortScanner />} />
              <Route path="tools/network-analyzer" element={<NetworkAnalyzer />} />
              <Route path="tools/ssl-inspector" element={<SSLInspector />} />
              <Route path="tools/firewall-tester" element={<FirewallTester />} />
              <Route path="tools/password-auditor" element={<PasswordAuditor />} />
              <Route path="tools/cve-scanner" element={<CVEScanner />} />
              <Route path="ctf" element={<CTF />} />
              <Route path="scenarios" element={<Scenarios />} />
              <Route path="ai-assistant" element={<AIAssistant />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="tools/nmap" element={<NmapTool />} />
            </Route>
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;