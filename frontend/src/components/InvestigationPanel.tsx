"use client"
import { useState, useRef, useEffect } from "react"
import { Send, Bot, User, Loader2, Key, ChevronDown, ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"
import { API_BASE, API_TOKEN } from "@/lib/api"

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

interface InvestigationPanelProps {
  defaultExpanded?: boolean
}

export function InvestigationPanel({ defaultExpanded = false }: InvestigationPanelProps) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const [messages, setMessages]     = useState<Message[]>([])
  const [input, setInput]           = useState("")
  const [loading, setLoading]       = useState(false)
  const [mode, setMode]             = useState<"openclaw" | "byollm">("openclaw")
  const [apiKey, setApiKey]         = useState("")
  const [showApiKey, setShowApiKey] = useState(false)
  const [gatewayUnavailable, setGatewayUnavailable] = useState(false)
  const msgIdRef  = useRef(0)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef  = useRef<HTMLTextAreaElement>(null)
  const apiKeyRef = useRef<HTMLInputElement>(null)

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
      // Build paired history from alternating user/assistant messages
      const history: Array<{question: string; answer: string}> = []
      for (let i = 0; i < messages.length - 1; i += 2) {
        if (messages[i]?.role === "user" && messages[i + 1]?.role === "assistant") {
          history.push({
            question: messages[i].content,
            answer: messages[i + 1].content,
          })
        }
      }
      const recentHistory = history.slice(-10)

      const res = await fetch(`${API_BASE}/chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(API_TOKEN ? { Authorization: `Bearer ${API_TOKEN}` } : {}),
        },
        body: JSON.stringify({
          question,
          mode,
          api_key: mode === "byollm" ? apiKey || null : null,
          history: recentHistory,
        }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        if (res.status === 503 && mode === "openclaw") {
          setGatewayUnavailable(true)
          addMessage("assistant", `Error: ${err.detail ?? "Gateway unavailable"}`, true)
        } else {
          addMessage("assistant", `Error: ${err.detail ?? "Request failed"}`, true)
        }
        return
      }

      setGatewayUnavailable(false)
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
    <div className="bg-card border border-border rounded-lg" data-testid="investigation-panel">
      {/* Header / toggle */}
      <button
        onClick={() => setExpanded(prev => !prev)}
        className="w-full flex items-center gap-2 px-6 py-4 text-left hover:bg-secondary/30 transition-colors rounded-lg"
        aria-expanded={expanded}
        aria-label="Toggle investigation panel"
      >
        {expanded ? <ChevronDown size={16} className="text-muted-foreground" /> : <ChevronRight size={16} className="text-muted-foreground" />}
        <h2 className="text-sm font-bold tracking-wide text-foreground">Security Investigation</h2>
      </button>

      {/* Collapsible body */}
      {expanded && (
        <div className="px-6 pb-6 flex flex-col gap-4">
          {/* Mode switcher */}
          <div className="flex items-center justify-end">
            <div className="flex bg-secondary rounded-lg p-1 gap-1">
              {(["openclaw", "byollm"] as const).map(m => (
                <button
                  key={m}
                  onClick={() => { setMode(m); setShowApiKey(m === "byollm"); setGatewayUnavailable(false) }}
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

          {/* BYOLLM API key input */}
          {showApiKey && (
            <div className="flex items-center gap-2 bg-card border border-border rounded-lg p-3">
              <Key size={14} className="text-muted-foreground shrink-0" />
              <input
                ref={apiKeyRef}
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

          {/* Gateway unavailable warning banner */}
          {gatewayUnavailable && (
            <div className="flex items-center gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-300">
              <span>⚠️</span>
              <span className="flex-1">OpenClaw gateway unavailable. Switch to BYOLLM mode with your Anthropic API key for full AI analysis.</span>
              <button
                onClick={() => {
                  setMode("byollm")
                  setShowApiKey(true)
                  setGatewayUnavailable(false)
                  setTimeout(() => apiKeyRef.current?.focus(), 100)
                }}
                className="whitespace-nowrap rounded bg-yellow-500/20 px-3 py-1 text-yellow-200 hover:bg-yellow-500/30"
              >
                Switch to BYOLLM →
              </button>
            </div>
          )}

          {/* Message history */}
          <div className="overflow-y-auto space-y-4 pr-1 max-h-[50vh]">
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center gap-6 text-center py-8">
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
      )}
    </div>
  )
}
