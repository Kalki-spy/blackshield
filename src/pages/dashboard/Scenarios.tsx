import { useEffect, useState } from "react";
import { ChevronDown, ChevronUp, Circle, CheckCircle2 } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { scenarios, type Scenario } from "@/data/scenarios";

const diffClass = (d: string) => {
  if (d === "Beginner") return "border-success/40 text-success";
  if (d === "Intermediate") return "border-warning/40 text-warning";
  return "border-destructive/40 text-destructive";
};

function loadDone(key: string): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(key) || "{}"); } catch { return {}; }
}

function ScenarioCard({
  scenario, doneSteps, onToggleStep,
}: { scenario: Scenario; doneSteps: Record<string, boolean>; onToggleStep: (stepKey: string) => void }) {
  const [open, setOpen] = useState(false);
  const completedCount = scenario.steps.filter((_, i) => doneSteps[`${scenario.id}:${i}`]).length;
  const allDone = completedCount === scenario.steps.length;

  return (
    <div className="bg-card border border-border rounded-md overflow-hidden">
      <button onClick={() => setOpen(v => !v)} className="w-full flex items-center justify-between p-4 text-left">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-[10px] text-muted-foreground uppercase tracking-wide">{scenario.category}</span>
            <span className={`border rounded px-1.5 py-0.5 text-[10px] font-medium ${diffClass(scenario.difficulty)}`}>{scenario.difficulty}</span>
            {allDone && <span className="flex items-center gap-1 text-[10px] text-success"><CheckCircle2 className="h-3 w-3" /> Complete</span>}
          </div>
          <h3 className="text-sm font-semibold text-foreground">{scenario.title}</h3>
          <p className="text-xs text-muted-foreground mt-1">{scenario.summary}</p>
        </div>
        <div className="flex items-center gap-3 shrink-0 pl-4">
          <span className="text-xs font-mono text-muted-foreground">{completedCount}/{scenario.steps.length}</span>
          {open ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
        </div>
      </button>

      {open && (
        <div className="border-t border-border p-4 flex flex-col gap-3">
          {scenario.steps.map((step, i) => {
            const stepKey = `${scenario.id}:${i}`;
            const done = !!doneSteps[stepKey];
            return (
              <button
                key={stepKey}
                onClick={() => onToggleStep(stepKey)}
                className="flex items-start gap-3 text-left p-3 rounded-md bg-muted/20 border border-border hover:border-primary/30 transition-colors"
              >
                {done ? <CheckCircle2 className="h-4 w-4 text-success mt-0.5 shrink-0" /> : <Circle className="h-4 w-4 text-muted-foreground mt-0.5 shrink-0" />}
                <div>
                  <p className={`text-sm font-medium ${done ? "text-muted-foreground line-through" : "text-foreground"}`}>{step.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{step.instruction}</p>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function Scenarios() {
  const { user } = useAuth();
  const key = user ? `scenario_steps_${user.id}` : "scenario_steps_guest";
  const [doneSteps, setDoneSteps] = useState<Record<string, boolean>>({});

  useEffect(() => { setDoneSteps(loadDone(key)); }, [key]);

  function toggleStep(stepKey: string) {
    setDoneSteps(prev => {
      const next = { ...prev, [stepKey]: !prev[stepKey] };
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }

  const totalSteps = scenarios.reduce((s, sc) => s + sc.steps.length, 0);
  const completedSteps = scenarios.reduce(
    (s, sc) => s + sc.steps.filter((_, i) => doneSteps[`${sc.id}:${i}`]).length, 0
  );

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-lg font-semibold text-foreground">Scenarios</h1>
        <p className="text-sm text-muted-foreground">Guided, step-by-step walkthroughs using the platform's own tools.</p>
      </div>

      <div className="bg-card border border-border rounded-md p-4 flex items-center gap-4">
        <span className="text-xs text-muted-foreground">Overall progress</span>
        <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
          <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${totalSteps ? (completedSteps / totalSteps) * 100 : 0}%` }} />
        </div>
        <span className="font-mono text-xs text-muted-foreground">{completedSteps}/{totalSteps} steps</span>
      </div>

      <div className="flex flex-col gap-4">
        {scenarios.map(sc => (
          <ScenarioCard key={sc.id} scenario={sc} doneSteps={doneSteps} onToggleStep={toggleStep} />
        ))}
      </div>
    </div>
  );
}
