import { useState, useEffect, useRef } from "react";
import { useTeamMode } from "@/contexts/TeamModeContext";
import {
  Bot, Send, User, Sparkles, Shield, Swords, BookOpen,
  AlertCircle, Wifi, WifiOff, Terminal, Zap
} from "lucide-react";

interface Message {
  role: "user" | "ai";
  content: string;
}

const modeInfo = {
  red: {
    icon: Swords,
    label: "Red Team Assist",
    color: "text-red-400",
    accent: "red",
    badge: "bg-red-500/10 border-red-500/20 text-red-400",
    desc: "Offensive security — powered by Groq (Llama 3.3)",
    systemHint:
      "You are a Red Team AI assistant. Focus on offensive security, penetration testing, CVEs, exploitation techniques, and attack scenarios. Be technical, precise, and practical.",
    greeting:
      "🗡️ **Red Team AI online.**\n\nWhat attack scenario, CVE, or exploitation technique would you like to explore?",
  },
  blue: {
    icon: Shield,
    label: "Blue Team SOC Assist",
    color: "text-blue-400",
    accent: "blue",
    badge: "bg-blue-500/10 border-blue-500/20 text-blue-400",
    desc: "Defensive security — powered by Groq (Llama 3.3)",
    systemHint:
      "You are a Blue Team SOC AI assistant. Focus on defensive security, threat detection, log analysis, incident response, SIEM, and system hardening. Be thorough and methodical.",
    greeting:
      "🛡️ **Blue Team SOC Assistant ready.**\n\nPaste a log, describe an alert, or ask about defensive techniques.",
  },
  explorer: {
    icon: BookOpen,
    label: "AI Educator",
    color: "text-emerald-400",
    accent: "emerald",
    badge: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
    desc: "Cybersecurity learning — powered by Groq (Llama 3.3)",
    systemHint:
      "You are a cybersecurity educator AI. Explain concepts clearly with real-world examples, analogies, and step-by-step breakdowns. Make complex topics accessible without losing accuracy.",
    greeting:
      "📚 **AI Educator active.**\n\nWhat cybersecurity topic would you like to learn about?",
  },
};

const CHAT_API = "/api/chat";

// Simple markdown-like renderer for bold (**text**) and newlines
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

const AiAssistant = () => {
  const { mode } = useTeamMode();
  const info = modeInfo[mode];
  const ModeIcon = info.icon;

  const makeInitial = (m: typeof modeInfo[keyof typeof modeInfo]): Message[] => [
    { role: "ai", content: m.greeting },
  ];

  const [messages, setMessages] = useState<Message[]>(makeInitial(info));
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [aiStatus, setAiStatus] = useState<"unknown" | "ready" | "down">("unknown");
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setMessages(makeInitial(modeInfo[mode]));
    setError(null);
  }, [mode]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Check AI backend health via proxy
  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((d) => setAiStatus(d.ready ? "ready" : "down"))
      .catch(() => setAiStatus("down"));
  }, []);

  // Auto-resize textarea
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
  };

  const handleSend = async () => {
    if (!input.trim() || loading) return;
    const userMsg: Message = { role: "user", content: input.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    if (inputRef.current) inputRef.current.style.height = "auto";
    setLoading(true);
    setError(null);

    const apiMessages = [
      { role: "user", content: info.systemHint },
      { role: "assistant", content: "Understood. I'll focus accordingly." },
      ...newMessages.map((m) => ({
        role: m.role === "ai" ? "assistant" : "user",
        content: m.content,
      })),
    ];

    try {
      const res = await fetch(CHAT_API, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: apiMessages }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "The AI assistant returned an error.");
        setAiStatus("down");
      } else {
        setMessages((prev) => [...prev, { role: "ai", content: data.reply }]);
        setAiStatus("ready");
      }
    } catch {
      setError("Cannot reach the CyberBot server.");
      setAiStatus("down");
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

  const statusConfig = {
    ready: {
      icon: Wifi,
      label: "OLLAMA READY",
      cls: "bg-emerald-500/10 border border-emerald-500/25 text-emerald-400",
      dot: "bg-emerald-400",
    },
    down: {
      icon: WifiOff,
      label: "OLLAMA OFFLINE",
      cls: "bg-red-500/10 border border-red-500/25 text-red-400",
      dot: "bg-red-400",
    },
    unknown: {
      icon: Wifi,
      label: "CHECKING...",
      cls: "bg-secondary border border-border text-muted-foreground",
      dot: "bg-muted-foreground",
    },
  }[aiStatus];

  const StatusIcon = statusConfig.icon;

  return (
    <div className="flex flex-col h-[calc(100vh-7.5rem)] font-mono">

      {/* ── Header ── */}
      <div className="flex items-center justify-between pb-4 border-b border-border/60">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-md bg-secondary border border-border/60`}>
            <ModeIcon className={`w-4 h-4 ${info.color}`} />
          </div>
          <div>
            <h2 className="text-sm font-bold text-foreground flex items-center gap-2">
              {info.label}
              <Sparkles className="w-3 h-3 text-amber-400" />
            </h2>
            <p className="text-[10px] text-muted-foreground">{info.desc}</p>
          </div>
        </div>

        {/* Status pill */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] ${statusConfig.cls}`}>
          <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.dot} ${aiStatus === "ready" ? "animate-pulse" : ""}`} />
          <StatusIcon className="w-3 h-3" />
          {statusConfig.label}
        </div>
      </div>

      {/* ── AI offline banner ── */}
      {aiStatus === "down" && (
        <div className="mt-3 rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
          <div className="flex items-center gap-2 mb-2 text-red-400 font-semibold">
            <AlertCircle className="w-3.5 h-3.5" />
            AI assistant isn't configured yet:
          </div>
          <ol className="space-y-1 list-decimal list-inside text-red-300/80">
            <li>Get a free key: <span className="text-white">console.groq.com/keys</span></li>
            <li>Set <span className="text-white font-bold">GROQ_API_KEY</span> in your environment (backend/.env locally, or your host's dashboard)</li>
            <li>Restart the chat server</li>
          </ol>
        </div>
      )}

      {/* ── Messages ── */}
      <div className="flex-1 overflow-y-auto py-5 space-y-5 scrollbar-thin scrollbar-thumb-border">
        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}>

            {msg.role === "ai" && (
              <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
                <Bot className={`w-3.5 h-3.5 ${info.color}`} />
              </div>
            )}

            <div
              className={`max-w-[78%] rounded-xl px-4 py-3 text-sm leading-relaxed ${
                msg.role === "user"
                  ? "bg-primary/10 border border-primary/20 text-foreground rounded-tr-sm"
                  : "bg-card border border-border text-foreground rounded-tl-sm"
              }`}
            >
              <p className="whitespace-pre-wrap">{renderContent(msg.content)}</p>
            </div>

            {msg.role === "user" && (
              <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
                <User className="w-3.5 h-3.5 text-muted-foreground" />
              </div>
            )}
          </div>
        ))}

        {/* Typing indicator */}
        {loading && (
          <div className="flex gap-3 justify-start">
            <div className="w-7 h-7 rounded-full bg-secondary border border-border flex items-center justify-center">
              <Bot className={`w-3.5 h-3.5 ${info.color} animate-pulse`} />
            </div>
            <div className="bg-card border border-border rounded-xl rounded-tl-sm px-4 py-3 flex items-center gap-3">
              <span className="flex gap-1">
                {[0, 150, 300].map((delay) => (
                  <span
                    key={delay}
                    className="w-1.5 h-1.5 rounded-full bg-muted-foreground animate-bounce"
                    style={{ animationDelay: `${delay}ms` }}
                  />
                ))}
              </span>
              <span className="text-xs text-muted-foreground">Thinking...</span>
            </div>
          </div>
        )}

        {/* Error bubble */}
        {error && (
          <div className="flex gap-3 justify-start">
            <div className="w-7 h-7 rounded-full bg-red-500/20 border border-red-500/30 flex items-center justify-center">
              <AlertCircle className="w-3.5 h-3.5 text-red-400" />
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl rounded-tl-sm px-4 py-3 text-sm text-red-400 max-w-[78%]">
              {error}
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* ── Input bar ── */}
      <div className="pt-4 border-t border-border/60">
        <div className="flex items-end gap-2 rounded-xl border border-border bg-card p-2 focus-within:border-primary/50 transition-colors">
          <Terminal className="w-4 h-4 text-muted-foreground mb-2.5 ml-1 shrink-0" />
          <textarea
            ref={inputRef}
            value={input}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            rows={1}
            className="flex-1 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground resize-none py-2 px-1 leading-relaxed"
            placeholder={`Ask ${info.label}… (Enter to send, Shift+Enter for newline)`}
            disabled={loading}
            style={{ minHeight: "36px", maxHeight: "120px" }}
          />
          <button
            onClick={handleSend}
            disabled={loading || !input.trim()}
            className={`p-2 rounded-lg transition-all shrink-0 mb-0.5 ${
              loading || !input.trim()
                ? "bg-secondary text-muted-foreground opacity-40 cursor-not-allowed"
                : "bg-primary text-primary-foreground hover:bg-primary/80 active:scale-95"
            }`}
          >
            {loading ? (
              <Zap className="w-4 h-4 animate-pulse" />
            ) : (
              <Send className="w-4 h-4" />
            )}
          </button>
        </div>

        <p className="text-[10px] text-muted-foreground text-center mt-2 flex items-center justify-center gap-1">
          <span>🔒</span>
          <span>Powered by Groq — responses are generated by a hosted AI model</span>
        </p>
      </div>
    </div>
  );
};

export default AiAssistant;