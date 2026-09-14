import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Clock, BarChart2, ChevronRight, Package, Wrench, CheckCircle, AlertTriangle, Terminal } from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { serviceDetails } from "@/data/serviceDetails";
import { services } from "@/data/services";
import { useEffect } from "react";

const accentClasses: Record<string, { border: string; text: string; bg: string; badge: string; bar: string }> = {
  red:     { border: "border-red-500/30",     text: "text-red-400",     bg: "bg-red-500/10",     badge: "bg-red-500/20 text-red-400 border-red-500/30",     bar: "bg-red-500" },
  blue:    { border: "border-blue-500/30",    text: "text-blue-400",    bg: "bg-blue-500/10",    badge: "bg-blue-500/20 text-blue-400 border-blue-500/30",    bar: "bg-blue-500" },
  emerald: { border: "border-emerald-500/30", text: "text-emerald-400", bg: "bg-emerald-500/10", badge: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30", bar: "bg-emerald-500" },
};

const difficultyColor = (d?: string) => {
  switch (d) {
    case "Expert":       return "bg-red-500/20 text-red-400 border-red-500/30";
    case "Advanced":     return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "Intermediate": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "Beginner":     return "bg-green-500/20 text-green-400 border-green-500/30";
    default:             return "bg-muted text-muted-foreground border-border";
  }
};

const severityColor = (s: string) => {
  switch (s) {
    case "CRITICAL": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "HIGH":     return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "MEDIUM":   return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    default:         return "bg-muted text-muted-foreground border-border";
  }
};

export default function SubServiceDetail() {
  const { serviceId, subServiceId } = useParams();
  const detail = serviceDetails.find(d => d.id === subServiceId && d.parentId === serviceId);
  const parent = services.find(s => s.id === serviceId);

  useEffect(() => { window.scrollTo(0, 0); }, [subServiceId]);

  if (!detail || !parent) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground font-mono">Service not found.</p>
      </div>
    );
  }

  const ac = accentClasses[detail.accentColor] || accentClasses.red;
  const Icon = detail.icon;

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      <div className="pt-24 pb-20">
        <div className="container mx-auto px-4 max-w-5xl">

          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm font-mono mb-8 flex-wrap">
            <Link to="/" className="text-muted-foreground hover:text-foreground transition-colors">Home</Link>
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
            <Link to={`/services/${serviceId}`} className="text-muted-foreground hover:text-foreground transition-colors">{parent.title}</Link>
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
            <span className={ac.text}>{detail.title}</span>
          </div>

          {/* Hero */}
          <div className={`neon-card rounded-xl p-8 mb-8 border ${ac.border}`}>
            <div className="flex items-start gap-5 flex-wrap">
              <div className={`h-14 w-14 rounded-xl ${ac.bg} flex items-center justify-center flex-shrink-0`}>
                <Icon className={`h-7 w-7 ${ac.text}`} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 flex-wrap mb-2">
                  <h1 className="text-2xl md:text-3xl font-bold font-mono text-foreground">{detail.title}</h1>
                  {detail.difficulty && (
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${difficultyColor(detail.difficulty)}`}>
                      {detail.difficulty}
                    </span>
                  )}
                </div>
                <p className={`font-mono text-sm ${ac.text} mb-3`}>{detail.tagline}</p>
                <p className="text-muted-foreground leading-relaxed">{detail.overview}</p>
              </div>
            </div>

            {/* Meta */}
            {(detail.duration) && (
              <div className="flex items-center gap-6 mt-6 pt-5 border-t border-border flex-wrap">
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground">
                  <Clock className={`h-4 w-4 ${ac.text}`} />
                  <span>Duration: <span className="text-foreground">{detail.duration}</span></span>
                </div>
                <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground">
                  <BarChart2 className={`h-4 w-4 ${ac.text}`} />
                  <span>Difficulty: <span className="text-foreground">{detail.difficulty}</span></span>
                </div>
              </div>
            )}
          </div>

          {/* Grid: What We Do + CVEs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            {/* What We Do */}
            <div className="lg:col-span-2 neon-card rounded-xl p-6">
              <p className={`text-[10px] font-mono tracking-widest uppercase ${ac.text} mb-4`}>// What We Do</p>
              <ul className="space-y-2.5">
                {detail.whatWeDo.map((item, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <CheckCircle className={`h-4 w-4 ${ac.text} flex-shrink-0 mt-0.5`} />
                    <span className="text-sm text-muted-foreground">{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Tools */}
            <div className="neon-card rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Wrench className={`h-4 w-4 ${ac.text}`} />
                <p className={`text-[10px] font-mono tracking-widest uppercase ${ac.text}`}>// Tools Used</p>
              </div>
              <div className="space-y-3">
                {detail.tools.map((tool, i) => (
                  <div key={i} className={`p-3 rounded-lg ${ac.bg} border ${ac.border}`}>
                    <p className="font-mono text-xs font-bold text-foreground">{tool.name}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{tool.purpose}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Phases */}
          <div className="neon-card rounded-xl p-6 mb-8">
            <p className={`text-[10px] font-mono tracking-widest uppercase ${ac.text} mb-6`}>// Engagement Phases</p>
            <div className="space-y-0">
              {detail.phases.map((phase, i) => (
                <div key={i} className="relative flex gap-4">
                  {/* Timeline line */}
                  {i < detail.phases.length - 1 && (
                    <div className={`absolute left-5 top-10 bottom-0 w-px ${ac.bg} border-l border-dashed ${ac.border}`} />
                  )}
                  {/* Phase number */}
                  <div className={`h-10 w-10 rounded-full ${ac.bg} border ${ac.border} flex items-center justify-center flex-shrink-0 z-10`}>
                    <span className={`font-mono text-sm font-bold ${ac.text}`}>{phase.number}</span>
                  </div>
                  {/* Content */}
                  <div className={`flex-1 pb-8 ${i === detail.phases.length - 1 ? "pb-0" : ""}`}>
                    <div className="mb-2">
                      <h3 className="font-mono font-bold text-foreground">{phase.name}</h3>
                      <p className="text-sm text-muted-foreground">{phase.description}</p>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {phase.tasks.map((task, j) => (
                        <div key={j} className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                          <Terminal className={`h-3 w-3 ${ac.text} flex-shrink-0`} />
                          {task}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* CVEs + Deliverables */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            {/* Deliverables */}
            <div className="neon-card rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Package className={`h-4 w-4 ${ac.text}`} />
                <p className={`text-[10px] font-mono tracking-widest uppercase ${ac.text}`}>// Deliverables</p>
              </div>
              <ul className="space-y-2.5">
                {detail.deliverables.map((d, i) => (
                  <li key={i} className="flex items-center gap-3">
                    <div className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ${ac.bar}`} />
                    <span className="text-sm text-muted-foreground font-mono">{d}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* CVEs if present */}
            {detail.cves && detail.cves.length > 0 ? (
              <div className="neon-card rounded-xl p-6">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className={`h-4 w-4 ${ac.text}`} />
                  <p className={`text-[10px] font-mono tracking-widest uppercase ${ac.text}`}>// Common CVEs Tested</p>
                </div>
                <div className="space-y-2">
                  {detail.cves.map((cve, i) => (
                    <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border ${severityColor(cve.severity)}`}>
                        {cve.severity}
                      </span>
                      <div>
                        <span className="font-mono text-xs font-bold text-foreground">{cve.id}</span>
                        <span className="font-mono text-xs text-muted-foreground ml-2">{cve.name}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="neon-card rounded-xl p-6 flex items-center justify-center">
                <div className="text-center">
                  <Icon className={`h-10 w-10 ${ac.text} mx-auto mb-2 opacity-30`} />
                  <p className="text-xs font-mono text-muted-foreground">Framework-based assessment</p>
                </div>
              </div>
            )}
          </div>

          {/* CTA */}
          <div className={`neon-card rounded-xl p-8 text-center border ${ac.border}`}>
            <h2 className="text-xl font-bold font-mono text-foreground mb-2">Ready to get started?</h2>
            <p className="text-sm text-muted-foreground mb-6">Our team is available for scoping calls and custom engagements.</p>
            <div className="flex items-center justify-center gap-3 flex-wrap">
              <Link
                to="/auth"
                className={`px-6 py-2.5 rounded-lg ${ac.bg} border ${ac.border} ${ac.text} font-mono text-sm font-semibold hover:opacity-80 transition-opacity`}
              >
                Launch Dashboard
              </Link>
              <Link
                to={`/services/${serviceId}`}
                className="px-6 py-2.5 rounded-lg bg-muted border border-border text-muted-foreground font-mono text-sm hover:text-foreground transition-colors flex items-center gap-2"
              >
                <ArrowLeft className="h-4 w-4" /> Back to {parent.title}
              </Link>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}