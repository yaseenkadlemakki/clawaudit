"use client"
import { useState, useRef, useEffect } from "react"
import { Send, Bot, User, Loader2, Key } from "lucide-react"
import { cn } from "@/lib/utils"

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:18790/api/v1"

const SUGGESTED_QUESTIONS = [
  "Which skills allow shell execution?",
  "Show me the critical findings",
  "Which skills have unknown publishers?",
  "What policies failed in the last scan?",
  "Which skills contact external domains?",
  "Explain the supply chain risks detected",
]

interface Message {
  id: number
  role: "user" | "assistant"
  content: string
  error?: boolean
}

export default function ChatPage() {
  const [messages, setMessages]     = useState<Message[]>([])
  const [input, setInput]           = useState("")
  const [loading, setLoading]       = useState(false)
  const [mode, setMode]             = useState<"openclaw" | "byollm">("openclaw")
  const [apiKey, setApiKey]         = useState("")
  const [showApiKey, setShowApiKey] = useState(false)
  const msgIdRef  = useRef(0)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef  = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  const addMessage = (role: "user" | "assistant", content: string, error = false): number => {
    const id = ++msgIdRef.current
    setMessages(prev => [...prev, { id, role, content, error }])
    return id
  }

  const sendQuestion = async (question: string) => {
    if (!question.trim() || loading) return
    setInput("")
    addMessage("user", question)
    setLoading(true)

    try {
      const res = await fetch(`${API_BASE}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question,
          mode,
          api_key: mode === "byollm" ? apiKey || null : null,
        }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        addMessage("assistant", `Error: ${err.detail ?? "Request failed"}`, true)
        return
      }

      const data = await res.json()
      addMessage("assistant", data.answer)
    } catch (err) {
      addMessage("assistant", `Network error: ${(err as Error).message}`, true)
    } finally {
      setLoading(false)
      inputRef.current?.focus()
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      sendQuestion(input)
    }
  }

  return (
    <div className="flex flex-col h-[calc(100vh-2rem)] p-4 gap-4 max-w-4xl mx-auto">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Security Investigation</h1>

        {/* Mode switcher */}
        <div className="flex items-center gap-3">
          <div className="flex bg-secondary rounded-lg p-1 gap-1">
            {(["openclaw", "byollm"] as const).map(m => (
              <button
                key={m}
                onClick={() => { setMode(m); setShowApiKey(m === "byollm") }}
                className={cn(
                  "px-3 py-1 rounded text-xs font-medium transition-colors",
                  mode === m ? "bg-primary text-white" : "text-muted-foreground hover:text-foreground"
                )}
              >
                {m === "openclaw" ? "OpenClaw" : "BYOLLM"}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* BYOLLM API key input */}
      {showApiKey && (
        <div className="flex items-center gap-2 bg-card border border-border rounded-lg p-3">
          <Key size={14} className="text-muted-foreground shrink-0" />
          <input
            type="password"
            placeholder="Anthropic API key (sk-ant-...)"
            value={apiKey}
            onChange={e => setApiKey(e.target.value)}
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          {apiKey && (
            <span className="text-xs text-green-400">✓ key set</span>
          )}
        </div>
      )}

      {/* Message history */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-1">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full gap-6 text-center">
            <Bot size={40} className="text-primary opacity-60" />
            <div>
              <p className="text-muted-foreground text-sm mb-1">Ask anything about your security scans</p>
              <p className="text-xs text-muted-foreground">Run a Full Audit first to get meaningful answers</p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 w-full max-w-xl">
              {SUGGESTED_QUESTIONS.map(q => (
                <button
                  key={q}
                  onClick={() => sendQuestion(q)}
                  className="text-left text-xs bg-card border border-border rounded-lg p-3 hover:border-primary/50 transition-colors text-muted-foreground hover:text-foreground"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map(msg => (
          <div
            key={msg.id}
            className={cn(
              "flex gap-3",
              msg.role === "user" ? "justify-end" : "justify-start"
            )}
          >
            {msg.role === "assistant" && (
              <div className="w-7 h-7 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 mt-1">
                <Bot size={14} className="text-primary" />
              </div>
            )}

            <div
              className={cn(
                "max-w-[80%] rounded-lg px-4 py-3 text-sm whitespace-pre-wrap",
                msg.role === "user"
                  ? "bg-primary text-white ml-auto"
                  : msg.error
                    ? "bg-red-500/10 border border-red-500/20 text-red-400"
                    : "bg-card border border-border text-foreground"
              )}
            >
              {msg.content}
            </div>

            {msg.role === "user" && (
              <div className="w-7 h-7 rounded-full bg-secondary flex items-center justify-center shrink-0 mt-1">
                <User size={14} className="text-muted-foreground" />
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
              <Bot size={14} className="text-primary" />
            </div>
            <div className="bg-card border border-border rounded-lg px-4 py-3">
              <Loader2 size={14} className="animate-spin text-muted-foreground" />
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex gap-2 items-end bg-card border border-border rounded-lg p-3">
        <textarea
          ref={inputRef}
          rows={1}
          placeholder="Ask about your security scan…"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-transparent text-sm resize-none outline-none placeholder:text-muted-foreground max-h-32"
        />
        <button
          onClick={() => sendQuestion(input)}
          disabled={!input.trim() || loading}
          aria-label="Send"
          className={cn(
            "p-2 rounded-md transition-colors shrink-0",
            input.trim() && !loading
              ? "bg-primary text-white hover:bg-primary/80"
              : "bg-secondary text-muted-foreground cursor-not-allowed"
          )}
        >
          <Send size={14} />
        </button>
      </div>
    </div>
  )
}
