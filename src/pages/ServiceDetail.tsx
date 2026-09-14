import { useEffect } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { CheckCircle2 } from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { getServiceBySlug, toolsForCategory, workflowSteps } from "@/data/servicesCatalog";
import { useAuth } from "@/contexts/AuthContext";

const TRAINING_LINKS = [
  { name: "CTF", description: "Capture-the-flag style challenges.", route: "/dashboard/ctf" },
  { name: "Scenarios", description: "Guided training scenarios.", route: "/dashboard/scenarios" },
  { name: "AI Assistant", description: "In-platform assistant for training support.", route: "/dashboard/ai-assistant" },
];

const severityClass: Record<string, string> = {
  Critical: "border-destructive text-destructive bg-destructive/5",
  High: "border-warning text-warning bg-warning/5",
  Medium: "border-warning/70 text-warning bg-warning/5",
  Informational: "border-border text-muted-foreground bg-muted/5",
};

const ServiceDetail = () => {
  const { serviceId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => { window.scrollTo(0, 0); }, [serviceId]);

  const service = getServiceBySlug(serviceId ?? "");
  const tools = service?.slug === "security-training" ? TRAINING_LINKS : toolsForCategory(serviceId ?? "").map(t => ({ name: t.name, description: t.description, route: t.route }));

  if (!service) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <Navbar />
        <div className="flex-1 flex items-center justify-center">
          <p className="text-muted-foreground">Service not found.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      <main className="pt-24">
        {/* Hero */}
        <section className="border-b border-border">
          <div className="container mx-auto px-6 max-w-[1280px] py-12 grid grid-cols-1 lg:grid-cols-12 gap-8">
            <div className="lg:col-span-7 flex flex-col gap-5">
              <span className="inline-flex items-center gap-2 self-start bg-primary/5 border border-primary/30 rounded px-2.5 py-1">
                <span className="font-mono text-xs text-primary">SERVICE CATEGORY</span>
              </span>
              <h1 className="text-3xl md:text-4xl font-bold text-foreground">{service.title}</h1>
              <p className="text-lg text-muted-foreground max-w-xl">{service.tagline}</p>
              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => navigate(user ? "/dashboard/tools" : "/auth")}
                  className="bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-5 py-2.5 rounded-md transition-colors"
                >
                  Open in workspace
                </button>
                <Link to="/docs" className="border border-border text-foreground text-sm font-medium px-5 py-2.5 rounded-md hover:bg-muted/30 transition-colors">
                  View documentation
                </Link>
              </div>
            </div>

            <div className="lg:col-span-5">
              <div className="bg-card border border-border rounded-lg p-5 flex flex-col gap-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">At a glance</p>
                {([
                  ["Included tools", `${service.atAGlance.includedTools} tools`],
                  ["Typical duration", service.atAGlance.duration],
                  ["Skill level", service.atAGlance.skillLevel],
                  ["Output", service.atAGlance.output],
                ] as [string, string][]).map(([k, v], i, arr) => (
                  <div key={k} className={`flex items-center justify-between ${i < arr.length - 1 ? "border-b border-border pb-3" : ""}`}>
                    <span className="text-sm text-muted-foreground">{k}</span>
                    <span className="text-sm font-medium text-foreground">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        {/* Tools in this category */}
        <section className="border-b border-border">
          <div className="container mx-auto px-6 max-w-[1280px] py-14">
            <h2 className="text-xl font-semibold text-foreground mb-1">Tools in this category</h2>
            <p className="text-sm text-muted-foreground mb-6">Each tool below has a dedicated workspace with its own configuration and results view.</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-border border border-border rounded-lg overflow-hidden">
              {tools.map((tool) => (
                <Link key={tool.name} to={tool.route} className="bg-card hover:bg-muted/30 transition-colors p-6 flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-base font-medium text-foreground">{tool.name}</h3>
                    <p className="text-sm text-muted-foreground mt-1">{tool.description}</p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </section>

        {/* Capabilities */}
        <section className="border-b border-border">
          <div className="container mx-auto px-6 max-w-[1280px] py-14">
            <h2 className="text-xl font-semibold text-foreground mb-8">Capabilities</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
              {service.capabilities.map((cap) => (
                <div key={cap.title} className="flex gap-4">
                  <CheckCircle2 className="h-4 w-4 text-primary mt-1 shrink-0" />
                  <div>
                    <h3 className="text-base font-medium text-foreground">{cap.title}</h3>
                    <p className="text-sm text-muted-foreground mt-1">{cap.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Workflow */}
        <section className="border-b border-border">
          <div className="container mx-auto px-6 max-w-[1280px] py-14">
            <h2 className="text-xl font-semibold text-foreground mb-10">How this service works</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 relative">
              <div className="hidden lg:block absolute top-4 left-0 right-0 h-px bg-border" />
              {workflowSteps.map((step, i) => (
                <div key={step.title} className="relative flex flex-col gap-1.5 bg-background pr-4">
                  <span className={`h-8 w-8 rounded-full flex items-center justify-center text-sm font-semibold ${i === 0 ? "bg-primary text-primary-foreground" : "bg-card border border-border text-muted-foreground"}`}>
                    {i + 1}
                  </span>
                  <h3 className="text-sm font-medium text-foreground pt-2">{step.title}</h3>
                  <p className="text-sm text-muted-foreground">{step.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Sample findings */}
        {service.sampleFindings.length > 0 && (
          <section className="border-b border-border">
            <div className="container mx-auto px-6 max-w-[1280px] py-14">
              <h2 className="text-xl font-semibold text-foreground mb-1">Sample findings output</h2>
              <p className="text-sm text-muted-foreground mb-6">An illustrative example of results this service category can produce — not live scan data.</p>
              <div className="border border-border rounded-lg overflow-hidden">
                <div className="bg-card grid grid-cols-4 px-4 py-3">
                  {["Severity", "Finding", "Endpoint", "Tool"].map(h => (
                    <span key={h} className="text-[11px] font-medium text-muted-foreground uppercase tracking-wide">{h}</span>
                  ))}
                </div>
                {service.sampleFindings.map((f, i) => (
                  <div key={i} className="grid grid-cols-4 px-4 py-3.5 border-t border-border items-center">
                    <span className={`self-start text-xs font-medium px-2.5 py-0.5 rounded border-l-2 ${severityClass[f.severity]}`}>{f.severity}</span>
                    <span className="text-sm text-foreground">{f.finding}</span>
                    <span className="font-mono text-xs text-muted-foreground">{f.endpoint}</span>
                    <span className="text-sm text-muted-foreground">{f.tool}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* CTA */}
        <section className="container mx-auto px-6 max-w-[1280px] py-14">
          <div className="bg-card border border-border rounded-lg p-8 flex flex-wrap items-center justify-between gap-6">
            <div>
              <h2 className="text-xl font-semibold text-foreground">Run this service on your target</h2>
              <p className="text-sm text-muted-foreground mt-1">Open the workspace and start a {service.title} assessment now.</p>
            </div>
            <button
              onClick={() => navigate(user ? "/dashboard/tools" : "/auth")}
              className="bg-primary hover:bg-primary/90 text-primary-foreground text-sm font-medium px-5 py-2.5 rounded-md transition-colors"
            >
              Open in workspace
            </button>
          </div>
        </section>
      </main>
    </div>
  );
};

export default ServiceDetail;
