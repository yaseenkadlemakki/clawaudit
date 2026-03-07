"use client"
import { useState, useRef, useEffect, useCallback } from "react"
import { useQuery, useMutation } from "@tanstack/react-query"
import { startScan, stopScan, getScan, type ScanRun } from "@/lib/api"
import { Play, Square, RefreshCw } from "lucide-react"
import { cn, formatDate } from "@/lib/utils"

const WS_BASE = "ws://localhost:18790/ws/scans"

function statusBadge(s: string) {
  const map: Record<string, string> = {
    running:  "bg-blue-500/20 text-blue-400 border-blue-500/30",
    complete: "bg-green-500/20 text-green-400 border-green-500/30",
    failed:   "bg-red-500/20 text-red-400 border-red-500/30",
    stopped:  "bg-slate-500/20 text-slate-400 border-slate-500/30",
    pending:  "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  }
  return (
    <span className={cn("px-2 py-0.5 rounded text-xs border", map[s] ?? map.pending)}>
      {s.toUpperCase()}
    </span>
  )
}

export default function AuditPage() {
  const [activeScan, setActiveScan] = useState<ScanRun | null>(null)
  const [logs, setLogs]             = useState<string[]>([])
  const [wsStatus, setWsStatus]     = useState<"idle" | "connecting" | "live" | "closed">("idle")
  const wsRef     = useRef<WebSocket | null>(null)
  const logEndRef = useRef<HTMLDivElement>(null)

  const { data: scanData } = useQuery({
    queryKey: ["scan", activeScan?.id],
    queryFn:  () => getScan(activeScan!.id),
    enabled:  !!activeScan?.id,
    refetchInterval: (q) => q.state.data?.status === "running" ? 3000 : false,
  })

  useEffect(() => { if (scanData) setActiveScan(scanData) }, [scanData])
  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: "smooth" }) }, [logs])

  const connectWs = useCallback((scanId: string) => {
    wsRef.current?.close()
    setLogs([])
    setWsStatus("connecting")
    const ws = new WebSocket(`${WS_BASE}/${scanId}/stream`)
    wsRef.current = ws
    ws.onopen    = () => { setWsStatus("live"); setLogs(p => [...p, `[connected] streaming scan ${scanId}`]) }
    ws.onmessage = (e) => { setLogs(p => [...p, typeof e.data === "string" ? e.data : JSON.stringify(e.data)]) }
    ws.onerror   = ()  => { setLogs(p => [...p, "[ws error]"]) }
    ws.onclose   = ()  => { setWsStatus("closed"); setLogs(p => [...p, "[stream closed]"]) }
  }, [])

  const startMut = useMutation({
    mutationFn: startScan,
    onSuccess:  (scan) => { setActiveScan(scan); connectWs(scan.id) },
  })
  const stopMut = useMutation({
    mutationFn: () => stopScan(activeScan!.id),
    onSuccess:  () => { wsRef.current?.close(); setActiveScan(s => s ? { ...s, status: "stopped" } : s) },
  })

  const isRunning = activeScan?.status === "running"

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Full Audit</h1>
        <div className="flex gap-3">
          <button
            onClick={() => startMut.mutate()}
            disabled={isRunning || startMut.isPending}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
              isRunning || startMut.isPending
                ? "bg-secondary text-muted-foreground cursor-not-allowed"
                : "bg-primary text-white hover:bg-primary/80"
            )}
          >
            {startMut.isPending ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
            Start Scan
          </button>
          <button
            onClick={() => stopMut.mutate()}
            disabled={!isRunning || stopMut.isPending}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
              !isRunning || stopMut.isPending
                ? "bg-secondary text-muted-foreground cursor-not-allowed"
                : "bg-red-600 text-white hover:bg-red-500"
            )}
          >
            <Square size={14} /> Stop Scan
          </button>
        </div>
      </div>

      {activeScan && (
        <div className="bg-card border border-border rounded-lg p-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Scan ID</p>
            <p className="font-mono text-xs">{activeScan.id.slice(0, 12)}…</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Status</p>
            {statusBadge(activeScan.status)}
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Started</p>
            <p className="text-xs">{formatDate(activeScan.started_at)}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">Findings</p>
            <p className="font-bold">{activeScan.findings_count}</p>
          </div>
        </div>
      )}

      <div className="bg-card border border-border rounded-lg">
        <div className="flex items-center justify-between px-4 py-2 border-b border-border">
          <span className="text-xs text-muted-foreground">Live Log Stream</span>
          <span className={cn(
            "text-xs px-2 py-0.5 rounded border",
            wsStatus === "live"        ? "bg-green-500/10 text-green-400 border-green-500/30"
            : wsStatus === "connecting" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
            : wsStatus === "closed"     ? "bg-slate-500/10 text-slate-400 border-slate-500/30"
            :                             "bg-slate-500/10 text-slate-500 border-slate-700"
          )}>
            {wsStatus === "live" ? "● LIVE" : wsStatus.toUpperCase()}
          </span>
        </div>
        <div className="h-96 overflow-y-auto p-4 log-stream bg-black/20">
          {logs.length === 0 && (
            <p className="text-muted-foreground text-xs">Start a scan to stream logs here.</p>
          )}
          {logs.map((line, i) => (
            <div key={i} className={cn(
              "text-xs leading-relaxed",
              line.includes("[error]") || line.includes("FAIL") ? "text-red-400"
              : line.includes("[warn]") || line.includes("WARNING")  ? "text-yellow-400"
              : line.includes("[ok]")  || line.includes("PASS")      ? "text-green-400"
              : "text-slate-300"
            )}>
              {line}
            </div>
          ))}
          <div ref={logEndRef} />
        </div>
      </div>

      {(startMut.error || stopMut.error) && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-4 text-sm">
          {(startMut.error as Error)?.message ?? (stopMut.error as Error)?.message}
        </div>
      )}
    </div>
  )
}
