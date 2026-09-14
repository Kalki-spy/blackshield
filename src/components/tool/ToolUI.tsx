import { Link } from "react-router-dom";
import type { InputHTMLAttributes, ReactNode, TextareaHTMLAttributes, SelectHTMLAttributes, ButtonHTMLAttributes } from "react";

// Shared presentational shell for tool pages, matching the Figma tool-page
// design: a config card + status card on the left, results on the right.
// Each tool page keeps its own state and API calls — these components are
// purely structural/visual so every tool page looks consistent.

export function ToolBreadcrumb({ category, tool }: { category: string; tool: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <Link to="/dashboard/tools" className="hover:text-foreground transition-colors">Tools</Link>
      <span>/</span>
      <span>{category}</span>
      <span>/</span>
      <span className="text-foreground font-medium">{tool}</span>
    </div>
  );
}

export function ToolHeader({ title, description }: { title: string; description: string }) {
  return (
    <div>
      <h1 className="text-2xl font-bold text-foreground">{title}</h1>
      <p className="text-sm text-muted-foreground mt-1">{description}</p>
    </div>
  );
}

export function TwoColumn({ left, right }: { left: ReactNode; right: ReactNode }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      <div className="lg:col-span-4 flex flex-col gap-6">{left}</div>
      <div className="lg:col-span-8 flex flex-col gap-6 min-w-0">{right}</div>
    </div>
  );
}

export function ConfigCard({
  title, description, children, footer,
}: { title: string; description?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-md overflow-hidden">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        {description && <p className="text-xs text-muted-foreground mt-1 leading-relaxed">{description}</p>}
      </div>
      <div className="p-4 flex flex-col gap-4">{children}</div>
      {footer && <div className="border-t border-border px-4 py-3">{footer}</div>}
    </div>
  );
}

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label className="text-xs font-medium text-muted-foreground">{label}</label>
      {children}
      {hint && <p className="text-[11px] text-muted-foreground/70">{hint}</p>}
    </div>
  );
}

const inputClass =
  "w-full bg-muted border border-border rounded-md px-3 py-2 text-sm font-mono text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50 transition-colors";

export function ToolInput(props: InputHTMLAttributes<HTMLInputElement>) {
  const { className, ...rest } = props;
  return <input {...rest} className={`${inputClass} ${className ?? ""}`} />;
}

export function ToolTextarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const { className, ...rest } = props;
  return <textarea {...rest} className={`${inputClass} resize-none ${className ?? ""}`} />;
}

export function ToolSelect(props: SelectHTMLAttributes<HTMLSelectElement>) {
  const { className, ...rest } = props;
  return (
    <select {...rest} className={`${inputClass} font-sans appearance-none ${className ?? ""}`}>
      {props.children}
    </select>
  );
}

export function Checkbox({
  checked, onChange, label,
}: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="h-4 w-4 rounded border-border accent-primary"
      />
      {label}
    </label>
  );
}

export function RunButton({ children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={`w-full bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground font-medium text-sm rounded-md py-2.5 flex items-center justify-center gap-2 transition-colors ${className ?? ""}`}
    >
      {children}
    </button>
  );
}

export function SecondaryButton({ children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-muted/40 border border-border text-muted-foreground hover:text-foreground text-xs font-medium transition-colors disabled:opacity-50 ${className ?? ""}`}
    >
      {children}
    </button>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 p-3 rounded-md bg-destructive/10 border border-destructive/30">
      <p className="text-xs text-destructive">{message}</p>
    </div>
  );
}

export function StatusCard({
  status, message, detail, progress, elapsed,
}: { status: string; message: string; detail?: string; progress?: number; elapsed?: string }) {
  return (
    <div className="bg-card border border-border rounded-md p-4 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-muted-foreground tracking-[1.2px] uppercase">Scan status</span>
        <span className="text-xs font-mono text-primary">{status}</span>
      </div>
      <p className="text-sm text-foreground pt-1">{message}</p>
      {detail && <p className="text-xs text-muted-foreground">{detail}</p>}
      {progress != null && (
        <>
          <div className="h-1.5 bg-muted rounded-full overflow-hidden mt-1">
            <div className="h-full bg-primary rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>
          <div className="flex justify-between text-[11px] font-mono text-muted-foreground">
            <span>{elapsed}</span>
            <span>{progress}%</span>
          </div>
        </>
      )}
    </div>
  );
}

export function ResultsCard({
  title, meta, children,
}: { title: string; meta?: ReactNode; children: ReactNode }) {
  return (
    <div className="bg-card border border-border rounded-md overflow-hidden">
      <div className="border-b border-border px-4 py-3 flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        {meta && <span className="text-xs text-muted-foreground">{meta}</span>}
      </div>
      <div>{children}</div>
    </div>
  );
}

export function EmptyResults({ text }: { text: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 px-4 text-center">
      <p className="text-sm text-muted-foreground max-w-sm">{text}</p>
    </div>
  );
}

const severityBorder: Record<string, string> = {
  critical: "border-destructive text-destructive",
  high: "border-warning text-warning",
  medium: "border-warning text-warning",
  low: "border-success text-success",
  informational: "border-border text-muted-foreground",
  info: "border-border text-muted-foreground",
};

export function SeverityTag({ level }: { level: string }) {
  const key = level.toLowerCase();
  const cls = severityBorder[key] ?? "border-border text-muted-foreground";
  return (
    <span className={`border-l-2 pl-2.5 text-xs font-medium capitalize ${cls}`}>
      {level}
    </span>
  );
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="bg-muted border border-border rounded px-2 py-1 text-xs font-mono text-muted-foreground">
      {children}
    </span>
  );
}
