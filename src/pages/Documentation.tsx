import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ChevronLeft, ChevronRight, ExternalLink, Search, Shield, Terminal } from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { docCategories, allDocEntries, getDocEntry } from "@/data/docsContent";

export default function Documentation() {
  const { slug } = useParams();
  const navigate = useNavigate();
  const [query, setQuery] = useState("");

  const activeSlug = slug ?? allDocEntries[0].slug;
  const entry = getDocEntry(activeSlug) ?? allDocEntries[0];

  const flatIndex = useMemo(() => allDocEntries.findIndex((e) => e.slug === entry.slug), [entry.slug]);
  const prevEntry = flatIndex > 0 ? allDocEntries[flatIndex - 1] : undefined;
  const nextEntry = flatIndex < allDocEntries.length - 1 ? allDocEntries[flatIndex + 1] : undefined;

  const filteredCategories = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return docCategories;
    return docCategories
      .map((cat) => ({
        ...cat,
        entries: cat.entries.filter(
          (e) => e.title.toLowerCase().includes(q) || e.summary.toLowerCase().includes(q),
        ),
      }))
      .filter((cat) => cat.entries.length > 0);
  }, [query]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Navbar />

      <div className="flex-1 w-full max-w-7xl mx-auto px-4 md:px-6 pt-24 pb-16 grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-8">
        {/* Docs sidebar */}
        <aside className="md:sticky md:top-24 md:self-start">
          <div className="flex items-center gap-2 mb-4 text-foreground">
            <Shield className="h-4 w-4 text-primary" />
            <span className="font-mono text-sm font-bold tracking-wide">Documentation</span>
          </div>

          <div className="relative mb-4">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search docs..."
              aria-label="Search documentation"
              className="w-full bg-muted/30 border border-border rounded-md pl-8 pr-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          <nav className="space-y-5 max-h-[70vh] overflow-y-auto pr-1">
            {filteredCategories.map((cat) => (
              <div key={cat.id}>
                <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-[1.6px] mb-1.5 px-1">
                  {cat.label}
                </p>
                <ul className="space-y-0.5">
                  {cat.entries.map((e) => (
                    <li key={e.slug}>
                      <button
                        onClick={() => navigate(`/docs/${e.slug}`)}
                        className={`w-full text-left px-2.5 py-1.5 rounded-md text-sm transition-colors ${
                          e.slug === entry.slug
                            ? "bg-primary/15 text-primary border border-primary/30"
                            : "text-muted-foreground hover:text-foreground hover:bg-muted/40 border border-transparent"
                        }`}
                      >
                        {e.title}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {filteredCategories.length === 0 && (
              <p className="text-sm text-muted-foreground px-1">No matching pages.</p>
            )}
          </nav>
        </aside>

        {/* Content */}
        <main className="min-w-0">
          <div className="flex items-center gap-2 text-xs text-muted-foreground mb-3">
            <span className="uppercase tracking-widest">{cat_label(entry.category)}</span>
            <span>/</span>
            <span className="text-foreground">{entry.title}</span>
          </div>

          <h1 className="text-2xl md:text-3xl font-bold text-foreground mb-2">{entry.title}</h1>
          <p className="text-sm text-muted-foreground mb-6">{entry.summary}</p>

          {(entry.route || entry.endpoint) && (
            <div className="flex flex-wrap gap-2 mb-6">
              {entry.route && (
                <Link
                  to={entry.route}
                  className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-border bg-muted/30 text-foreground hover:border-primary/40 transition-colors"
                >
                  Open in dashboard <ExternalLink className="h-3 w-3" />
                </Link>
              )}
              {entry.endpoint && (
                <span className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-md border border-border bg-muted/10 text-muted-foreground">
                  <Terminal className="h-3 w-3" /> {entry.endpoint}
                </span>
              )}
            </div>
          )}

          <div className="space-y-6">
            {entry.sections.map((s) => (
              <section key={s.heading}>
                <h2 className="text-sm font-semibold text-foreground uppercase tracking-wide mb-2">
                  {s.heading}
                </h2>
                {s.body.map((p, i) => (
                  <p key={i} className="text-sm text-muted-foreground leading-relaxed mb-2">
                    {p}
                  </p>
                ))}
                {s.list && s.list.length > 0 && (
                  <ul className="mt-2 space-y-1.5">
                    {s.list.map((item, i) => (
                      <li key={i} className="text-sm text-muted-foreground flex gap-2">
                        <span className="text-primary mt-0.5">›</span>
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            ))}
          </div>

          {/* Prev / Next */}
          <div className="flex items-center justify-between mt-12 pt-6 border-t border-border">
            {prevEntry ? (
              <button
                onClick={() => navigate(`/docs/${prevEntry.slug}`)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                <ChevronLeft className="h-3.5 w-3.5" /> {prevEntry.title}
              </button>
            ) : <span />}
            {nextEntry ? (
              <button
                onClick={() => navigate(`/docs/${nextEntry.slug}`)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {nextEntry.title} <ChevronRight className="h-3.5 w-3.5" />
              </button>
            ) : <span />}
          </div>
        </main>
      </div>
    </div>
  );
}

function cat_label(id: string): string {
  const found = docCategories.find((c) => c.id === id);
  return found ? found.label : id;
}
