import { useState, useEffect, useRef, useCallback } from "react";
import {
  Bot, Send, User, AlertCircle, Wifi, WifiOff, Terminal,
  Copy, FileText, MessageSquarePlus,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { toast } from "@/hooks/use-toast";

interface Message {
  role: "user" | "ai";
  content: string;
}
interface Conversation {
  id: number;
  title: string;
  updated_at: string;
}

const CHAT_API = "/api/chat";
const ASSISTANT_API = "/api/assistant";
const ACTIVITY_API = "/api/activity";

const SUGGESTED_QUESTIONS = [
  "Summarize my recent findings",
  "What should I prioritize first?",
  "Explain my most recent scan result",
  "Help me draft a report section",
];

const GREETING: Message = {
  role: "ai",
  content:
    "**CyberBot online.**\n\nRunning on your local Ollama instance — fully private, no data leaves your machine.\n\nAsk about a finding, a tool, or your recent scans.",
};

function renderContent(content: string) {
  const parts = content.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i} className="font-semibold">{part.slice(2, -2)}</strong>;
    }
    return part.split("\n").map((line, j, arr) => (
      <span key={`${i}-${j}`}>
        {line}
        {j < arr.length - 1 && <br />}
      </span>
    ));
  });
}

export default function AIAssistant() {
  const { user } = useAuth();
  const [messages, setMessages] = useState<Message[]>([GREETING]);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [context, setContext] = useState<{ activeScan: string | null; finding: string | null }>({
    activeScan: null,
    finding: null,
  });
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ollamaStatus, setOllamaStatus] = useState<"unknown" | "ready" | "down">("unknown");
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const loadConversations = useCallback(() => {
    if (!user?.id) return;
    fetch(`${ASSISTANT_API}/conversations?user_id=${user.id}`)
      .then((r) => r.json())
      .then(setConversations)
      .catch(() => {});
  }, [user?.id]);

  useEffect(() => {
    loadConversations();
    if (user?.id) {
      fetch(`${ACTIVITY_API}/summary?user_id=${user.id}`)
        .then((r) => r.json())
        .then((d) =>
          setContext({
            activeScan: d.active_scans?.[0]?.tool ?? null,
            finding: d.recent_findings?.[0]?.title ?? null,
          }),
        )
        .catch(() => {});
    }
  }, [user?.id, loadConversations]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => setOllamaStatus(d.ready ? "ready" : "down"))
      .catch(() => setOllamaStatus("down"));
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
  };

  const loadConversation = async (id: number) => {
    if (!user?.id) return;
    const res = await fetch(`${ASSISTANT_API}/conversations/${id}/messages?user_id=${user.id}`);
    if (!res.ok) return;
    const msgs = await res.json();
    setConversationId(id);
    setMessages(msgs.map((m: any) => ({ role: m.role === "assistant" ? "ai" : "user", content: m.content })));
  };

  const startNewConversation = () => {
    setConversationId(null);
    setMessages([GREETING]);
  };

  const handleSend = async (text?: string) => {
    const content = (text ?? input).trim();
    if (!content || loading || !user?.id) return;
    const userMsg: Message = { role: "user", content };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    if (inputRef.current) inputRef.current.style.height = "auto";
    setLoading(true);
    setError(null);

    let convId = conversationId;
    if (!convId) {
      const res = await fetch(`${ASSISTANT_API}/conversations`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id: user.id, title: content.slice(0, 60) }),
      });
      const created = await res.json();
      convId = created.id;
      setConversationId(convId);
    }
    fetch(`${ASSISTANT_API}/conversations/${convId}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role: "user", content }),
    }).catch(() => {});

    try {
      const res = await fetch(CHAT_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role === "ai" ? "assistant" : "user", content: m.content })),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Ollama returned an error.");
        setOllamaStatus("down");
      } else {
        setMessages((prev) => [...prev, { role: "ai", content: data.reply }]);
        setOllamaStatus("ready");
        fetch(`${ASSISTANT_API}/conversations/${convId}/messages`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ role: "assistant", content: data.reply }),
        }).catch(() => {});
        loadConversations();
      }
    } catch {
      setError("Cannot reach CyberBot server. Is Ollama running?");
      setOllamaStatus("down");
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const copyResponse = (content: string) => {
    navigator.clipboard.writeText(content);
    toast({ title: "Copied to clipboard" });
  };

  const addToReport = async (content: string) => {
    if (!user?.id) return;
    try {
      const res = await fetch(`${ASSISTANT_API}/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id: user.id, title: "AI Assistant notes" }),
      });
      const report = await res.json();
      await fetch(`${ASSISTANT_API}/reports/${report.id}/items`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content, source: "ai-assistant" }),
      });
      toast({ title: "Added to report" });
    } catch {
      toast({ title: "Couldn't save to report", variant: "destructive" });
    }
  };

  const statusConfig = {
    ready: { icon: Wifi, label: "OLLAMA READY", cls: "bg-success/10 border border-success/25 text-success", dot: "bg-success" },
    down: { icon: WifiOff, label: "OLLAMA OFFLINE", cls: "bg-destructive/10 border border-destructive/25 text-destructive", dot: "bg-destructive" },
    unknown: { icon: Wifi, label: "CHECKING…", cls: "bg-secondary border border-border text-muted-foreground", dot: "bg-muted-foreground" },
  }[ollamaStatus];
  const StatusIcon = statusConfig.icon;

  return (
    <div className="flex h-[calc(100vh-3.5rem)]">
      {/* Left aside: context, suggested questions, recent conversations */}
      <div className="hidden lg:flex flex-col gap-4 w-[280px] shrink-0 border-r border-border p-4 overflow-y-auto">
        <div className="flex flex-col gap-2">
          <h2 className="text-[11px] font-semibold text-muted-label tracking-wider uppercase">Context</h2>
          <div className="bg-card border border-border rounded-md p-3 flex flex-col gap-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-muted-label">Active scan</span>
              <span className="font-mono text-muted-foreground">{context.activeScan ?? "None"}</span>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-muted-label shrink-0">Recent finding</span>
              <span className="font-mono text-primary text-right truncate">{context.finding ?? "None yet"}</span>
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <h2 className="text-[11px] font-semibold text-muted-label tracking-wider uppercase">Suggested questions</h2>
          <div className="flex flex-col gap-1.5">
            {SUGGESTED_QUESTIONS.map((q) => (
              <button
                key={q}
                onClick={() => handleSend(q)}
                className="text-left border border-border rounded-md px-3 py-2 text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground transition-colors"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <h2 className="text-[11px] font-semibold text-muted-label tracking-wider uppercase">Recent conversations</h2>
            <button onClick={startNewConversation} className="text-muted-label hover:text-foreground" aria-label="New conversation">
              <MessageSquarePlus className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="flex flex-col gap-0.5">
            {conversations.length === 0 && (
              <p className="text-xs text-muted-label px-1">No conversations yet.</p>
            )}
            {conversations.map((c) => (
              <button
                key={c.id}
                onClick={() => loadConversation(c.id)}
                className={`text-left px-3 py-2 rounded-md text-xs truncate transition-colors ${
                  conversationId === c.id ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-secondary/60"
                }`}
              >
                {c.title}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Main chat */}
      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex items-center justify-between px-6 py-3 border-b border-border shrink-0">
          <h1 className="text-sm font-medium text-foreground">AI Assistant</h1>
          <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] ${statusConfig.cls}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.dot}`} />
            <StatusIcon className="w-3 h-3" />
            {statusConfig.label}
          </div>
        </div>

        {ollamaStatus === "down" && (
          <div className="m-4 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
            <div className="flex items-center gap-2 mb-2 font-semibold">
              <AlertCircle className="w-3.5 h-3.5" />
              Ollama not running — fix it:
            </div>
            <ol className="space-y-1 list-decimal list-inside text-destructive/80">
              <li>Install: <span className="text-foreground">https://ollama.com/download</span></li>
              <li>Start: <span className="text-foreground font-bold">ollama serve</span></li>
              <li>Pull model: <span className="text-foreground font-bold">ollama pull llama3</span></li>
            </ol>
          </div>
        )}

        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {messages.map((msg, i) => (
            <div key={i} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              {msg.role === "ai" && (
                <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
                  <Bot className="w-3.5 h-3.5 text-primary" />
                </div>
              )}
              <div className="flex flex-col gap-1.5 max-w-[78%]">
                <div
                  className={`rounded-xl px-4 py-3 text-sm leading-relaxed ${
                    msg.role === "user"
                      ? "bg-primary/10 border border-primary/20 text-foreground rounded-tr-sm"
                      : "bg-card border border-border text-foreground rounded-tl-sm"
                  }`}
                >
                  <p className="whitespace-pre-wrap">{renderContent(msg.content)}</p>
                </div>
                {msg.role === "ai" && i > 0 && (
                  <div className="flex items-center gap-3 pl-1">
                    <button onClick={() => copyResponse(msg.content)} className="flex items-center gap-1 text-[11px] text-muted-label hover:text-foreground">
                      <Copy className="h-3 w-3" /> Copy
                    </button>
                    <button onClick={() => addToReport(msg.content)} className="flex items-center gap-1 text-[11px] text-muted-label hover:text-foreground">
                      <FileText className="h-3 w-3" /> Add to report
                    </button>
                  </div>
                )}
              </div>
              {msg.role === "user" && (
                <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
                  <User className="w-3.5 h-3.5 text-muted-foreground" />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 justify-start">
              <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center">
                <Bot className="w-3.5 h-3.5 text-primary animate-pulse" />
              </div>
              <div className="bg-card border border-border rounded-xl rounded-tl-sm px-4 py-3 flex items-center gap-3">
                <span className="flex gap-1">
                  {[0, 150, 300].map((delay) => (
                    <span key={delay} className="w-1.5 h-1.5 rounded-full bg-muted-foreground animate-bounce" style={{ animationDelay: `${delay}ms` }} />
                  ))}
                </span>
                <span className="text-xs text-muted-foreground">Thinking…</span>
              </div>
            </div>
          )}

          {error && (
            <div className="flex gap-3 justify-start">
              <div className="w-7 h-7 rounded-full bg-destructive/20 border border-destructive/30 flex items-center justify-center">
                <AlertCircle className="w-3.5 h-3.5 text-destructive" />
              </div>
              <div className="bg-destructive/10 border border-destructive/30 rounded-xl rounded-tl-sm px-4 py-3 text-sm text-destructive max-w-[78%]">
                {error}
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        <div className="border-t border-border p-4 shrink-0">
          <div className="flex items-end gap-2 rounded-xl border border-border bg-card p-2 focus-within:border-primary/50 transition-colors">
            <Terminal className="w-4 h-4 text-muted-foreground mb-2.5 ml-1 shrink-0" />
            <textarea
              ref={inputRef}
              value={input}
              onChange={handleInputChange}
              onKeyDown={handleKeyDown}
              rows={1}
              className="flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground resize-none py-2 px-1 leading-relaxed"
              placeholder="Ask about a finding, tool, or request a report summary… (Enter to send, Shift+Enter for newline)"
              disabled={loading}
              style={{ minHeight: "36px", maxHeight: "120px" }}
            />
            <button
              onClick={() => handleSend()}
              disabled={loading || !input.trim()}
              className={`p-2 rounded-lg transition-all shrink-0 mb-0.5 ${
                loading || !input.trim() ? "bg-secondary text-muted-foreground opacity-40 cursor-not-allowed" : "bg-primary text-white hover:bg-primary/90"
              }`}
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
          <p className="text-[11px] text-muted-label text-center mt-2">
            Responses come from your local Ollama model. Always verify before acting on critical systems.
          </p>
        </div>
      </div>
    </div>
  );
}
