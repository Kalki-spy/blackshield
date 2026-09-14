import { useState, useRef, useEffect } from "react";
import {
  MessageCircle, X, Send, Bot, User,
  Terminal, Zap, Shield, ChevronRight,
  Loader2, RotateCcw, Copy, Check,
} from "lucide-react";

interface Message {
  id: number;
  text: string;
  sender: "user" | "bot";
  timestamp: Date;
  typing?: boolean;
}

const QUICK_PROMPTS = [
  { label: "SQL Injection",    icon: "🗄️", text: "How do I detect SQL injection vulnerabilities?" },
  { label: "TLS Weaknesses",   icon: "🔒", text: "What TLS misconfigurations should I look for?" },
  { label: "Subdomain Recon",  icon: "🌐", text: "What's the best approach for subdomain enumeration?" },
  { label: "CVE Exploitation", icon: "💀", text: "How does Log4Shell exploitation work?" },
  { label: "XSS Attacks",      icon: "📜", text: "Explain reflected vs stored XSS with examples" },
  { label: "Burp Suite Tips",  icon: "🛠️", text: "What are essential Burp Suite techniques for web pentesting?" },
];

function formatMessage(text: string) {
  const lines = text.split("\n");
  const elements: JSX.Element[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      elements.push(
        <CodeBlock key={i} code={codeLines.join("\n")} lang={lang} />
      );
    }
    // Bullet
    else if (line.match(/^[-*]\s/)) {
      elements.push(
        <div key={i} className="flex gap-2 items-start">
          <span className="text-red-400 mt-0.5 flex-shrink-0">▸</span>
          <span>{renderInline(line.slice(2))}</span>
        </div>
      );
    }
    // Numbered list
    else if (line.match(/^\d+\.\s/)) {
      const num = line.match(/^(\d+)\./)?.[1];
      elements.push(
        <div key={i} className="flex gap-2 items-start">
          <span className="text-red-400 font-mono text-[10px] mt-0.5 flex-shrink-0 w-4">{num}.</span>
          <span>{renderInline(line.replace(/^\d+\.\s/, ""))}</span>
        </div>
      );
    }
    // Empty line → spacer
    else if (line.trim() === "") {
      elements.push(<div key={i} className="h-1" />);
    }
    // Normal paragraph
    else {
      elements.push(<p key={i}>{renderInline(line)}</p>);
    }
    i++;
  }
  return <div className="space-y-1 text-sm leading-relaxed">{elements}</div>;
}

function renderInline(text: string): (string | JSX.Element)[] {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="px-1.5 py-0.5 rounded bg-black/40 border border-border font-mono text-[11px] text-red-300">
          {part.slice(1, -1)}
        </code>
      );
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return <strong key={i} className="font-bold text-foreground">{part.slice(2, -2)}</strong>;
    }
    return part;
  });
}

function CodeBlock({ code, lang }: { code: string; lang: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-border overflow-hidden my-1">
      <div className="flex items-center justify-between px-3 py-1.5 bg-black/40 border-b border-border">
        <span className="font-mono text-[9px] text-muted-foreground uppercase tracking-widest">{lang || "code"}</span>
        <button
          onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
          className="flex items-center gap-1 text-[9px] font-mono text-muted-foreground hover:text-foreground transition-colors"
        >
          {copied ? <><Check className="h-2.5 w-2.5 text-green-400" /> Copied</> : <><Copy className="h-2.5 w-2.5" /> Copy</>}
        </button>
      </div>
      <pre className="p-3 text-[11px] font-mono text-green-300 overflow-x-auto bg-black/30 leading-relaxed whitespace-pre-wrap break-all">
        {code}
      </pre>
    </div>
  );
}

function TypingDots() {
  return (
    <div className="flex items-center gap-1 px-1 py-0.5">
      {[0, 1, 2].map(i => (
        <span
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-red-400 animate-bounce"
          style={{ animationDelay: `${i * 150}ms`, animationDuration: "900ms" }}
        />
      ))}
    </div>
  );
}

export function Chatbot() {
  const [isOpen,     setIsOpen]     = useState(false);
  const [isTyping,   setIsTyping]   = useState(false);
  const [input,      setInput]      = useState("");
  const [showQuick,  setShowQuick]  = useState(true);
  const [messages,   setMessages]   = useState<Message[]>([
    {
      id: 1,
      text: "Online. I'm **CyberBot** — BlackShield's AI security assistant.\n\nAsk me about the platform tools, CVEs, pentest techniques, or any security topic. I'll give you straight answers.",
      sender: "bot",
      timestamp: new Date(),
    },
  ]);

  const bottomRef  = useRef<HTMLDivElement>(null);
  const inputRef   = useRef<HTMLInputElement>(null);
  const scrollRef  = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isTyping]);

  useEffect(() => {
    if (isOpen) setTimeout(() => inputRef.current?.focus(), 100);
  }, [isOpen]);

  async function sendMessage(text?: string) {
    const msg = (text ?? input).trim();
    if (!msg || isTyping) return;

    setInput("");
    setShowQuick(false);

    const userMsg: Message = { id: Date.now(), text: msg, sender: "user", timestamp: new Date() };
    const history = [...messages, userMsg];
    setMessages(history);
    setIsTyping(true);

    try {
      const res  = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: history.map(m => ({
            role:    m.sender === "user" ? "user" : "assistant",
            content: m.text,
          })),
        }),
      });
      const data = await res.json();
      setMessages(prev => [...prev, {
        id: Date.now() + 1, text: data.reply, sender: "bot", timestamp: new Date(),
      }]);
    } catch {
      setMessages(prev => [...prev, {
        id: Date.now() + 1,
        text: "⚠️ **Connection error** — chatbot server offline.\n\nMake sure `chatbot_server.py` is running on port 8000.",
        sender: "bot",
        timestamp: new Date(),
      }]);
    } finally {
      setIsTyping(false);
    }
  }

  function clearChat() {
    setMessages([{
      id: Date.now(), sender: "bot", timestamp: new Date(),
      text: "Chat cleared. What do you want to know?",
    }]);
    setShowQuick(true);
  }

  const timeStr = (d: Date) =>
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  return (
    <>
      {/* ── Floating trigger ── */}
      <button
        onClick={() => setIsOpen(v => !v)}
        aria-label="Toggle chat"
        className={`fixed bottom-6 right-6 z-50 h-14 w-14 rounded-full flex items-center justify-center shadow-lg transition-all duration-300 ${
          isOpen
            ? "bg-muted border border-border hover:bg-muted/80"
            : "bg-red-500/20 border border-red-500/40 hover:bg-red-500/30 pulse-glow"
        }`}
      >
        {isOpen
          ? <X className="h-5 w-5 text-muted-foreground" />
          : <MessageCircle className="h-5 w-5 text-red-400" />
        }
        {/* Unread dot */}
        {!isOpen && (
          <span className="absolute top-1 right-1 h-2.5 w-2.5 rounded-full bg-red-500 border-2 border-background" />
        )}
      </button>

      {/* ── Chat window ── */}
      {isOpen && (
        <div
          className="fixed bottom-24 right-6 z-50 flex flex-col rounded-xl neon-card overflow-hidden shadow-2xl"
          style={{ width: 380, height: 560 }}
        >
          {/* Header */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border bg-muted/30 flex-shrink-0">
            <div className="relative">
              <div className="h-9 w-9 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center">
                <Shield className="h-4 w-4 text-red-400" />
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-green-500 border-2 border-background" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="font-mono text-sm font-bold text-foreground">CyberBot</p>
              <div className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                <p className="text-[10px] font-mono text-muted-foreground">BlackShield AI · Online</p>
              </div>
            </div>
            <button
              onClick={clearChat}
              title="Clear chat"
              className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
            >
              <RotateCcw className="h-3.5 w-3.5" />
            </button>
          </div>

          {/* Messages */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-3 space-y-3 scrollbar-thin">
            {messages.map(msg => (
              <div
                key={msg.id}
                className={`flex gap-2 ${msg.sender === "user" ? "justify-end" : "justify-start"}`}
              >
                {msg.sender === "bot" && (
                  <div className="h-6 w-6 rounded-md bg-red-500/10 border border-red-500/20 flex-shrink-0 flex items-center justify-center mt-1">
                    <Bot className="h-3 w-3 text-red-400" />
                  </div>
                )}
                <div className={`flex flex-col gap-0.5 max-w-[85%] ${msg.sender === "user" ? "items-end" : "items-start"}`}>
                  <div
                    className={`rounded-xl px-3 py-2.5 ${
                      msg.sender === "user"
                        ? "bg-red-500/20 border border-red-500/30 text-foreground rounded-br-sm"
                        : "bg-muted/50 border border-border text-foreground rounded-bl-sm"
                    }`}
                  >
                    {msg.sender === "bot" ? formatMessage(msg.text) : (
                      <p className="text-sm leading-relaxed">{msg.text}</p>
                    )}
                  </div>
                  <span className="text-[9px] font-mono text-muted-foreground/50 px-1">
                    {timeStr(msg.timestamp)}
                  </span>
                </div>
                {msg.sender === "user" && (
                  <div className="h-6 w-6 rounded-md bg-muted/50 border border-border flex-shrink-0 flex items-center justify-center mt-1">
                    <User className="h-3 w-3 text-muted-foreground" />
                  </div>
                )}
              </div>
            ))}

            {/* Typing indicator */}
            {isTyping && (
              <div className="flex gap-2 justify-start">
                <div className="h-6 w-6 rounded-md bg-red-500/10 border border-red-500/20 flex-shrink-0 flex items-center justify-center mt-1">
                  <Bot className="h-3 w-3 text-red-400" />
                </div>
                <div className="bg-muted/50 border border-border rounded-xl rounded-bl-sm px-3 py-2.5">
                  <TypingDots />
                </div>
              </div>
            )}

            {/* Quick prompts */}
            {showQuick && messages.length === 1 && (
              <div className="pt-1">
                <p className="text-[9px] font-mono text-muted-foreground uppercase tracking-widest px-1 mb-2">
                  Quick questions
                </p>
                <div className="grid grid-cols-2 gap-1.5">
                  {QUICK_PROMPTS.map(q => (
                    <button
                      key={q.label}
                      onClick={() => sendMessage(q.text)}
                      className="flex items-center gap-1.5 px-2.5 py-2 rounded-lg bg-muted/30 border border-border hover:border-red-500/30 hover:bg-red-500/5 text-left transition-all group"
                    >
                      <span className="text-sm flex-shrink-0">{q.icon}</span>
                      <span className="font-mono text-[10px] text-muted-foreground group-hover:text-foreground transition-colors leading-tight">
                        {q.label}
                      </span>
                      <ChevronRight className="h-2.5 w-2.5 text-muted-foreground/40 ml-auto flex-shrink-0 group-hover:text-red-400 transition-colors" />
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="px-3 pb-3 pt-2 border-t border-border flex-shrink-0">
            <div className="flex gap-2 items-center">
              <div className="flex-1 relative">
                <Terminal className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/50 pointer-events-none" />
                <input
                  ref={inputRef}
                  type="text"
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
                  placeholder="Ask about CVEs, tools, techniques..."
                  disabled={isTyping}
                  className="w-full pl-8 pr-3 py-2 bg-muted/30 border border-border rounded-lg font-mono text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-red-500/40 focus:border-red-500/30 disabled:opacity-50 transition-colors"
                />
              </div>
              <button
                onClick={() => sendMessage()}
                disabled={isTyping || !input.trim()}
                className="h-9 w-9 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 flex items-center justify-center hover:bg-red-500/30 transition-colors disabled:opacity-30 disabled:cursor-not-allowed flex-shrink-0"
              >
                {isTyping
                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : <Send className="h-3.5 w-3.5" />
                }
              </button>
            </div>
            <p className="text-[9px] font-mono text-muted-foreground/30 text-center mt-1.5">
              Powered by LLaMA 3 · BlackShield AI
            </p>
          </div>
        </div>
      )}
    </>
  );
}
export default Chatbot;