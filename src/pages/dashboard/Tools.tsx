import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Search, ArrowRight } from "lucide-react";
import { toolsCatalog, totalToolCount, statusLabel, statusClass } from "@/data/toolsCatalog";

const Tools = () => {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string>("all");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return toolsCatalog
      .filter((cat) => category === "all" || cat.id === category)
      .map((cat) => ({
        ...cat,
        tools: cat.tools.filter(
          (t) => !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q),
        ),
      }))
      .filter((cat) => cat.tools.length > 0);
  }, [query, category]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Tools</h1>
          <p className="text-sm text-muted-foreground">
            {totalToolCount} tools across {toolsCatalog.length} workflow categories.
          </p>
        </div>
        <div className="flex gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search tools…"
              className="w-64 bg-card border border-border rounded-md pl-9 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="bg-card border border-border rounded-md px-3 py-2 text-sm text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="all">All categories</option>
            {toolsCatalog.map((cat) => (
              <option key={cat.id} value={cat.id}>{cat.label}</option>
            ))}
          </select>
        </div>
      </div>

      {filtered.length === 0 && (
        <p className="text-sm text-muted-foreground py-12 text-center">No tools match your search.</p>
      )}

      {filtered.map((cat) => (
        <div key={cat.id} className="flex flex-col gap-3">
          <h2 className="font-semibold text-[11px] text-muted-foreground tracking-[1.5px] uppercase">{cat.label}</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-px bg-border border border-border rounded-md overflow-hidden">
            {cat.tools.map((tool) => (
              <Link
                key={tool.name}
                to={tool.route}
                className="bg-card hover:bg-muted/30 transition-colors p-4 flex flex-col gap-3 group"
              >
                <div className="flex items-start justify-between">
                  <tool.icon className="h-4 w-4 text-primary" />
                  <span className={`text-[10px] border rounded px-1.5 py-0.5 ${statusClass[tool.status]}`}>
                    {statusLabel[tool.status]}
                  </span>
                </div>
                <div>
                  <h3 className="text-sm font-medium text-foreground">{tool.name}</h3>
                  <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{tool.description}</p>
                </div>
                <span className="flex items-center gap-1 text-xs text-primary mt-auto pt-1 opacity-80 group-hover:opacity-100">
                  Open tool <ArrowRight className="h-3 w-3" />
                </span>
              </Link>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default Tools;
