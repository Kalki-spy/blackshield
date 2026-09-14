import { useEffect, useMemo, useState } from "react";
import {
  Flag,
  Download,
  CheckCircle2,
  Lightbulb,
  Trophy,
  AlertCircle,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import {
  ctfChallenges,
  totalPoints,
  type CTFChallenge,
} from "@/data/ctfChallenges";

const difficultyStyle: Record<CTFChallenge["difficulty"], string> = {
  Beginner: "text-success bg-success/10",
  Intermediate: "text-warning bg-warning/10",
  Advanced: "text-destructive bg-destructive/10",
};

function loadSolved(key: string): string[] {
  try {
    return JSON.parse(localStorage.getItem(key) || "[]");
  } catch {
    return [];
  }
}

function ChallengeCard({
  challenge,
  solved,
  onSolve,
}: {
  challenge: CTFChallenge;
  solved: boolean;
  onSolve: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [input, setInput] = useState("");
  const [wrong, setWrong] = useState(false);

  function submit() {
    if (input.trim() === challenge.flag) {
      onSolve(challenge.id);
      setWrong(false);
    } else {
      setWrong(true);
    }
  }

  return (
    <div className="bg-card border border-border rounded-lg p-5 flex flex-col gap-3">
      {/* Challenge header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div
            className={`h-9 w-9 rounded-lg flex items-center justify-center shrink-0 ${
              solved ? "bg-success/10" : "bg-secondary"
            }`}
          >
            {solved ? (
              <CheckCircle2 className="h-4 w-4 text-success" />
            ) : (
              <Flag className="h-4 w-4 text-primary" />
            )}
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-foreground">{challenge.title}</h3>
            <span className="text-xs text-muted-label">{challenge.category}</span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${difficultyStyle[challenge.difficulty]}`}>
            {challenge.difficulty}
          </span>
          <span className="text-sm font-semibold text-primary">{challenge.points}pts</span>
        </div>
      </div>

      {/* Asset link, if this challenge ships a file */}
      {challenge.assetUrl && (
        <a
          href={challenge.assetUrl}
          download={!challenge.assetUrl.endsWith(".html")}
          target={challenge.assetUrl.endsWith(".html") ? "_blank" : undefined}
          rel="noreferrer"
          className="flex items-center gap-1 text-xs text-primary hover:underline self-start"
        >
          <Download className="h-3 w-3" />
          {challenge.assetLabel ?? "Download asset"}
        </a>
      )}

      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="border border-border rounded-md py-2 text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
        >
          {solved ? "Review challenge" : "Open challenge"}
        </button>
      )}

      {open && (
        <div className="flex flex-col gap-3 pt-3 border-t border-border">
          <pre className="bg-background border border-border rounded-md p-3 text-xs font-mono text-muted-foreground whitespace-pre-wrap break-all">
            {challenge.brief}
          </pre>

          <button
            onClick={() => setShowHint((s) => !s)}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground self-start"
          >
            <Lightbulb className="h-3 w-3" />
            {showHint ? "Hide hint" : "Show hint"}
          </button>
          {showHint && (
            <p className="text-xs text-muted-foreground bg-secondary rounded-md px-3 py-2">{challenge.hint}</p>
          )}

          {!solved ? (
            <>
              <div className="flex gap-2 pt-1">
                <input
                  value={input}
                  onChange={(e) => {
                    setInput(e.target.value);
                    setWrong(false);
                  }}
                  onKeyDown={(e) => e.key === "Enter" && submit()}
                  placeholder="BLACKSHIELD{...}"
                  className="flex-1 min-w-0 h-9 px-3 rounded-md bg-secondary border border-border text-sm font-mono text-foreground placeholder:text-muted-label focus:outline-none focus:border-primary/50"
                />
                <button
                  onClick={submit}
                  disabled={!input.trim()}
                  className="h-9 px-4 rounded-md bg-primary text-primary-foreground text-sm font-medium disabled:opacity-50"
                >
                  Submit
                </button>
              </div>
              {wrong && (
                <p className="flex items-center gap-1.5 text-xs text-destructive">
                  <AlertCircle className="h-3 w-3" /> Not quite — try again.
                </p>
              )}
            </>
          ) : (
            <p className="text-xs font-mono text-success break-all">{challenge.flag}</p>
          )}

          <button
            onClick={() => setOpen(false)}
            className="text-xs text-muted-label hover:text-foreground self-start"
          >
            Close challenge
          </button>
        </div>
      )}
    </div>
  );
}

export default function CTF() {
  const { user } = useAuth();
  const key = user ? `ctf_solved_${user.id}` : "ctf_solved_guest";
  const [solved, setSolved] = useState<string[]>([]);
  const [category, setCategory] = useState("all");
  const [difficulty, setDifficulty] = useState("all");

  useEffect(() => {
    setSolved(loadSolved(key));
  }, [key]);

  function handleSolve(id: string) {
    setSolved((prev) => {
      if (prev.includes(id)) return prev;
      const next = [...prev, id];
      localStorage.setItem(key, JSON.stringify(next));
      return next;
    });
  }

  const categories = useMemo(
    () => ["all", ...Array.from(new Set(ctfChallenges.map((c) => c.category)))],
    [],
  );
  const difficulties = ["all", "Beginner", "Intermediate", "Advanced"];

  const filtered = useMemo(
    () =>
      ctfChallenges.filter(
        (c) =>
          (category === "all" || c.category === category) &&
          (difficulty === "all" || c.difficulty === difficulty),
      ),
    [category, difficulty],
  );

  const grouped = useMemo(() => {
    const map = new Map<string, CTFChallenge[]>();
    for (const c of filtered) {
      if (!map.has(c.category)) map.set(c.category, []);
      map.get(c.category)!.push(c);
    }
    return Array.from(map.entries());
  }, [filtered]);

  const pointsEarned = ctfChallenges
    .filter((c) => solved.includes(c.id))
    .reduce((s, c) => s + c.points, 0);
  const pct = Math.round((solved.length / ctfChallenges.length) * 100);

  return (
    <div className="p-6 flex flex-col gap-6 max-w-[1000px] mx-auto">
      {/* Page header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Capture the Flag</h1>
          <p className="text-sm text-muted-label">
            {solved.length}/{ctfChallenges.length} solved · practical challenges to build and
            validate offensive security skills.
          </p>
        </div>
        <div className="flex items-center gap-2 bg-secondary border border-border rounded-md px-4 py-2">
          <Trophy className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold text-foreground">{pointsEarned}</span>
          <span className="text-sm text-muted-label">/ {totalPoints} pts</span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-card border border-border rounded-md px-3 py-2 text-xs text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {categories.map((c) => (
              <option key={c} value={c}>
                {c === "all" ? "All categories" : c}
              </option>
            ))}
          </select>
          <select
            value={difficulty}
            onChange={(e) => setDifficulty(e.target.value)}
            className="bg-card border border-border rounded-md px-3 py-2 text-xs text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {difficulties.map((d) => (
              <option key={d} value={d}>
                {d === "all" ? "All difficulties" : d}
              </option>
            ))}
          </select>
        </div>
        <span className="text-xs text-muted-label">
          Showing {filtered.length} of {ctfChallenges.length} challenges
        </span>
      </div>

      {/* Progress overview */}
      <div className="bg-card border border-border rounded-md p-4 flex items-center gap-6 flex-wrap">
        <div>
          <p className="text-[10px] text-muted-label uppercase tracking-wide">Completed</p>
          <p className="font-mono text-lg font-bold text-foreground">
            {solved.length} <span className="text-sm font-normal text-muted-label">/ {ctfChallenges.length}</span>
          </p>
        </div>
        <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden min-w-[120px]">
          <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${pct}%` }} />
        </div>
        <div>
          <p className="text-[10px] text-muted-label uppercase tracking-wide">Points earned</p>
          <p className="font-mono text-lg font-bold text-foreground">
            {pointsEarned} <span className="text-sm font-normal text-muted-label">/ {totalPoints}</span>
          </p>
        </div>
      </div>

      {/* Challenge groups */}
      {grouped.map(([categoryName, items]) => (
        <div key={categoryName} className="flex flex-col gap-3">
          <h2 className="text-xs font-semibold text-muted-label tracking-wider uppercase">{categoryName}</h2>
          <div className="grid grid-cols-[repeat(auto-fit,minmax(320px,1fr))] gap-4">
            {items.map((c) => (
              <ChallengeCard key={c.id} challenge={c} solved={solved.includes(c.id)} onSolve={handleSolve} />
            ))}
          </div>
        </div>
      ))}

      {filtered.length === 0 && (
        <p className="text-sm text-muted-foreground text-center py-8">No challenges match this filter.</p>
      )}
    </div>
  );
}