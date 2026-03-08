"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Activity, AlertTriangle, Shield, Zap, Filter } from "lucide-react"
import { API_BASE } from "@/lib/api"

interface ToolEvent {
  id: string
  session_id: string
  skill_name: string | null
  tool_name: string
  params_summary: string
  timestamp: string
  duration_ms: number | null
  outcome: string
  alert_triggered: boolean
  alert_reasons: string[]
}

interface HookStats {
  total_events: number
  total_alerts: number
  events_by_tool: Record<string, number>
  events_by_skill: Record<string, number>
}

async function fetchEvents(params: {
  limit?: number
  alerts_only?: boolean
  session_id?: string
  skill_name?: string
}): Promise<ToolEvent[]> {
  const qs = new URLSearchParams()
  if (params.limit) qs.set("limit", String(params.limit))
  if (params.alerts_only) qs.set("alerts_only", "true")
  if (params.session_id) qs.set("session_id", params.session_id)
  if (params.skill_name) qs.set("skill_name", params.skill_name)
  const res = await fetch(`${API_BASE}/hooks/events?${qs}`, {
    headers: { "Content-Type": "application/json" },
  })
  if (!res.ok) throw new Error(`API ${res.status}`)
  return res.json()
}

async function fetchStats(): Promise<HookStats> {
  const res = await fetch(`${API_BASE}/hooks/stats`, {
    headers: { "Content-Type": "application/json" },
  })
  if (!res.ok) throw new Error(`API ${res.status}`)
  return res.json()
}

function StatCard({ label, value, icon: Icon, accent }: {
  label: string
  value: string | number
  icon: typeof Activity
  accent: string
}) {
  return (
    <div className="border border-border rounded-lg p-4 bg-card">
      <div className="flex items-center gap-2 mb-2">
        <Icon size={16} className={accent} />
        <span className="text-xs text-muted-foreground uppercase tracking-wide">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  )
}

export default function HooksPage() {
  const [alertsOnly, setAlertsOnly] = useState(false)
  const [skillFilter, setSkillFilter] = useState("")
  const [selectedEvent, setSelectedEvent] = useState<ToolEvent | null>(null)
  const [liveEvents, setLiveEvents] = useState<ToolEvent[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  const { data: stats } = useQuery({
    queryKey: ["hook-stats"],
    queryFn: fetchStats,
    refetchInterval: 10000,
  })

  const { data: events } = useQuery({
    queryKey: ["hook-events", alertsOnly, skillFilter],
    queryFn: () => fetchEvents({
      limit: 100,
      alerts_only: alertsOnly,
      skill_name: skillFilter || undefined,
    }),
    refetchInterval: 5000,
  })

  // WebSocket for live events with exponential backoff reconnection
  const connectWebSocket = useCallback(() => {
    // Append the API token as a query param — required by the server's WS auth check.
    // Read from env var; falls back to empty string (server will reject with 1008).
    const apiToken = process.env.NEXT_PUBLIC_API_TOKEN ?? ""
    const wsBase = API_BASE.replace(/^http/, "ws").replace("/api/v1", "")
    const wsUrl = `${wsBase}/api/v1/hooks/stream?token=${encodeURIComponent(apiToken)}`
    let reconnectDelay = 1000
    let ws: WebSocket

    try {
      ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        reconnectDelay = 1000
      }
      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data)
          if (data.type === "ping") return
          setLiveEvents((prev) => [data, ...prev].slice(0, 50))
        } catch { /* ignore parse errors */ }
      }
      ws.onerror = (e) => console.warn("WS error", e)
      ws.onclose = () => {
        setTimeout(() => connectWebSocket(), Math.min(reconnectDelay, 30000))
        reconnectDelay *= 2
      }
    } catch { /* WebSocket not available */ }

    return ws!
  }, [])

  useEffect(() => {
    const ws = connectWebSocket()
    return () => {
      if (ws) ws.close()
    }
  }, [connectWebSocket])

  const totalEvents = stats?.total_events ?? 0
  const totalAlerts = stats?.total_alerts ?? 0
  const topTool = stats?.events_by_tool
    ? Object.entries(stats.events_by_tool).sort(([,a], [,b]) => b - a)[0]?.[0] ?? "—"
    : "—"
  const alertRate = totalEvents > 0 ? ((totalAlerts / totalEvents) * 100).toFixed(1) : "0.0"

  const allSkills = Array.from(new Set(
    (events ?? []).map(e => e.skill_name).filter(Boolean) as string[]
  ))

  const displayEvents = events ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield className="text-primary" size={24} />
        <h1 className="text-2xl font-bold">Runtime Events</h1>
        {liveEvents.length > 0 && (
          <span className="flex items-center gap-1 text-xs text-green-400 animate-pulse">
            <span className="w-2 h-2 rounded-full bg-green-400" />
            Live
          </span>
        )}
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Events" value={totalEvents} icon={Activity} accent="text-blue-400" />
        <StatCard label="Alerts Triggered" value={totalAlerts} icon={AlertTriangle} accent="text-red-400" />
        <StatCard label="Top Tool" value={topTool} icon={Zap} accent="text-yellow-400" />
        <StatCard label="Alert Rate" value={`${alertRate}%`} icon={Shield} accent="text-orange-400" />
      </div>

      {/* Live feed */}
      {liveEvents.length > 0 && (
        <div className="border border-green-900/50 rounded-lg p-4 bg-green-950/20">
          <h3 className="text-sm font-medium text-green-400 mb-2 flex items-center gap-2">
            <Activity size={14} />
            Live Event Stream
          </h3>
          <div className="space-y-1 max-h-32 overflow-y-auto font-mono text-xs">
            {liveEvents.slice(0, 10).map((e, i) => (
              <div key={`live-${i}`} className="flex items-center gap-2 text-muted-foreground">
                <span className="text-green-600">{e.timestamp?.slice(11, 19) ?? ""}</span>
                <span className="text-foreground">{e.tool_name}</span>
                {e.skill_name && <span className="text-blue-400">[{e.skill_name}]</span>}
                {e.alert_triggered && <span className="text-red-400 font-bold">ALERT</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-3">
        <Filter size={14} className="text-muted-foreground" />
        <select
          className="bg-card border border-border rounded px-2 py-1 text-sm"
          value={skillFilter}
          onChange={(e) => setSkillFilter(e.target.value)}
        >
          <option value="">All Skills</option>
          {allSkills.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input
            type="checkbox"
            checked={alertsOnly}
            onChange={(e) => setAlertsOnly(e.target.checked)}
            className="rounded"
          />
          Alerts only
        </label>
      </div>

      {/* Events table */}
      <div className="border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted/50 border-b border-border">
            <tr>
              <th className="text-left px-4 py-2 font-medium">Timestamp</th>
              <th className="text-left px-4 py-2 font-medium">Session</th>
              <th className="text-left px-4 py-2 font-medium">Skill</th>
              <th className="text-left px-4 py-2 font-medium">Tool</th>
              <th className="text-left px-4 py-2 font-medium">Outcome</th>
              <th className="text-left px-4 py-2 font-medium">Alert</th>
            </tr>
          </thead>
          <tbody>
            {displayEvents.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-muted-foreground">
                  No events recorded yet. Use <code className="text-xs">sentinel hooks simulate</code> to fire a test event.
                </td>
              </tr>
            ) : (
              displayEvents.map((e) => (
                <tr
                  key={e.id}
                  className="border-b border-border hover:bg-muted/30 cursor-pointer transition-colors"
                  onClick={() => setSelectedEvent(selectedEvent?.id === e.id ? null : e)}
                >
                  <td className="px-4 py-2 font-mono text-xs">{e.timestamp?.slice(0, 19) ?? ""}</td>
                  <td className="px-4 py-2 font-mono text-xs">{e.session_id?.slice(0, 12)}</td>
                  <td className="px-4 py-2">{e.skill_name ?? <span className="text-muted-foreground">—</span>}</td>
                  <td className="px-4 py-2 font-mono">{e.tool_name}</td>
                  <td className="px-4 py-2">
                    <span className={
                      e.outcome === "success" ? "text-green-400" :
                      e.outcome === "error" ? "text-red-400" : "text-yellow-400"
                    }>
                      {e.outcome}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    {e.alert_triggered ? (
                      <span className="text-xs px-2 py-0.5 rounded bg-red-400/10 text-red-400 border border-red-400/30">
                        ALERT
                      </span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Alert detail panel */}
      {selectedEvent && selectedEvent.alert_triggered && (
        <div className="border border-red-900/50 rounded-lg p-4 bg-red-950/20">
          <h3 className="text-sm font-medium text-red-400 mb-3 flex items-center gap-2">
            <AlertTriangle size={14} />
            Alert Detail — {selectedEvent.id.slice(0, 8)}
          </h3>
          <div className="space-y-2 text-sm">
            <div><span className="text-muted-foreground">Tool:</span> <span className="font-mono">{selectedEvent.tool_name}</span></div>
            <div><span className="text-muted-foreground">Params:</span> <span className="font-mono text-xs">{selectedEvent.params_summary}</span></div>
            <div className="mt-2">
              <span className="text-muted-foreground">Alert reasons:</span>
              <ul className="mt-1 space-y-1">
                {selectedEvent.alert_reasons.map((r, i) => (
                  <li key={i} className="text-red-300 text-xs flex items-center gap-1">
                    <AlertTriangle size={10} /> {r}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
