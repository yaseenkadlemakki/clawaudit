"use client"
import { useState, useRef, useEffect, useCallback } from "react"
import { useQuery, useMutation } from "@tanstack/react-query"
import { startScan, stopScan, getScan, getScans, type ScanRun } from "@/lib/api"
import { Play, Square, RefreshCw } from "lucide-react"
import { cn, formatDate } from "@/lib/utils"
import Link from "next/link"

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:18790/ws/scans"

function StatusBadge({ status }: { status: ScanRun["status"] }) {
  const styles: Record<string, string> = {
    completed: "bg-green-900/50 text-green-400 border-green-700",
    running:   "bg-yellow-900/50 text-yellow-400 border-yellow-700",
    failed:    "bg-red-900/50 text-red-400 border-red-700",
    stopping:  "bg-slate-900/50 text-slate-400 border-slate-700",
    idle:      "bg-slate-900/50 text-slate-400 border-slate-700",
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs border ${styles[status] ?? styles.idle}`}>
      {status}
    </span>
  )
}

function formatDuration(started: string, completed?: string | null): string {
  if (!completed) return "—"
  const ms = new Date(completed).getTime() - new Date(started).getTime()
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${s % 60}s`
}

function statusBadge(s: string) {
  const map: Record<string, string> = {
    running:   "bg-blue-500/20 text-blue-400 border-blue-500/30",
    completed: "bg-green-500/20 text-green-400 border-green-500/30",
    failed:    "bg-red-500/20 text-red-400 border-red-500/30",
    stopping:  "bg-slate-500/20 text-slate-400 border-slate-500/30",
    idle:      "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  }
  return (
    <span className={cn("px-2 py-0.5 rounded text-xs border", map[s] ?? map.idle)}>
      {s.toUpperCase()}
    </span>
  )
}

interface LogEntry { id: number; text: string }

const MAX_WS_RETRIES = 3

export default function AuditPage() {
  const [activeScan, setActiveScan] = useState<ScanRun | null>(null)
  const [logs, setLogs]             = useState<LogEntry[]>([])
  const [wsStatus, setWsStatus]     = useState<"idle" | "connecting" | "live" | "closed">("idle")
  const wsRef       = useRef<WebSocket | null>(null)
  const logEndRef   = useRef<HTMLDivElement>(null)
  const logIdRef    = useRef(0)
  const retryRef    = useRef(0)
  const retryTimer  = useRef<ReturnType<typeof setTimeout> | null>(null)

  const pushLog = useCallback((text: string) => {
    setLogs(p => [...p, { id: ++logIdRef.current, text }])
  }, [])

  const { data: scans, isLoading: scansLoading, error: scansError } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    refetchInterval: 10_000,
  })

  const { data: scanData } = useQuery({
    queryKey: ["scan", activeScan?.id],
    queryFn:  () => getScan(activeScan!.id),
    enabled:  !!activeScan?.id,
    refetchInterval: (q) => q.state.data?.status === "running" ? 3000 : false,
  })

  useEffect(() => { if (scanData) setActiveScan(scanData) }, [scanData])
  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: "smooth" }) }, [logs])

  const connectWs = useCallback((scanId: string, retry = false) => {
    wsRef.current?.close()
    if (!retry) {
      setLogs([])
      logIdRef.current = 0
      retryRef.current = 0
    }
    setWsStatus("connecting")
    const ws = new WebSocket(`${WS_BASE}/${scanId}/stream`)
    wsRef.current = ws
    ws.onopen = () => {
      setWsStatus("live")
      retryRef.current = 0
      pushLog(`[connected] streaming scan ${scanId}`)
    }
    ws.onmessage = (e) => {
      pushLog(typeof e.data === "string" ? e.data : JSON.stringify(e.data))
    }
    ws.onerror = () => { pushLog("[ws error]") }
    ws.onclose = () => {
      setWsStatus("closed")
      pushLog("[stream closed]")
      if (retryRef.current < MAX_WS_RETRIES) {
        const delay = Math.min(1000 * 2 ** retryRef.current, 8000)
        retryRef.current++
        pushLog(`[reconnecting in ${delay / 1000}s… attempt ${retryRef.current}/${MAX_WS_RETRIES}]`)
        retryTimer.current = setTimeout(() => connectWs(scanId, true), delay)
      }
    }
  }, [pushLog])

  useEffect(() => {
    return () => { if (retryTimer.current) clearTimeout(retryTimer.current) }
  }, [])

  const handleReconnect = useCallback(() => {
    if (activeScan) {
      retryRef.current = 0
      connectWs(activeScan.id, true)
    }
  }, [activeScan, connectWs])

  const startMut = useMutation({
    mutationFn: startScan,
    onSuccess:  (scan) => { setActiveScan(scan); connectWs(scan.id) },
  })
  const stopMut = useMutation({
    mutationFn: () => { if (!activeScan) return Promise.resolve(null as unknown as ScanRun); return stopScan(activeScan.id) },
    onSuccess:  (scan) => { wsRef.current?.close(); setActiveScan(s => scan ?? (s ? { ...s, status: "stopping" } : s)) },
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
            <p className="font-bold">{activeScan.total_findings ?? 0}</p>
          </div>
        </div>
      )}

      {/* ── Previous Scans ─────────────────────────────────── */}
      <div className="bg-card border border-border rounded-lg">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-sm font-semibold">Previous Scans</h2>
        </div>
        <div className="p-4">
          {scansLoading && (
            <div className="space-y-2">
              {[1, 2, 3].map(i => (
                <div key={i} className="h-8 bg-muted/50 rounded animate-pulse" />
              ))}
            </div>
          )}
          {!scansLoading && scansError && (
            <div className="bg-red-950/30 border border-red-500 text-red-400 rounded p-4 text-sm">
              Failed to load scan history.
            </div>
          )}
          {!scansLoading && !scansError && scans?.length === 0 && (
            <p className="text-sm text-muted-foreground">No scans yet. Run your first audit above.</p>
          )}
          {!scansLoading && !scansError && scans && scans.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-muted-foreground border-b border-border">
                    <th className="pb-2 pr-4">Status</th>
                    <th className="pb-2 pr-4">Started</th>
                    <th className="pb-2 pr-4">Duration</th>
                    <th className="pb-2 pr-4">Findings</th>
                    <th className="pb-2">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map(scan => (
                    <tr key={scan.id} className="border-b border-border/50 last:border-0">
                      <td className="py-2 pr-4"><StatusBadge status={scan.status} /></td>
                      <td className="py-2 pr-4 text-xs">{formatDate(scan.started_at)}</td>
                      <td className="py-2 pr-4 text-xs">{formatDuration(scan.started_at, scan.completed_at)}</td>
                      <td className="py-2 pr-4 text-xs">{scan.total_findings}</td>
                      <td className="py-2">
                        <Link
                          href={`/findings?scan_id=${scan.id}`}
                          className="text-xs text-primary hover:underline"
                        >
                          View Findings
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg">
        <div className="flex items-center justify-between px-4 py-2 border-b border-border">
          <span className="text-xs text-muted-foreground">Live Log Stream</span>
          <div className="flex items-center gap-2">
            {wsStatus === "closed" && activeScan && (
              <button
                onClick={handleReconnect}
                className="text-xs px-2 py-0.5 rounded border bg-blue-500/10 text-blue-400 border-blue-500/30 hover:bg-blue-500/20 transition-colors"
              >
                Reconnect
              </button>
            )}
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
        </div>
        <div className="h-96 overflow-y-auto p-4 log-stream bg-black/20">
          {logs.length === 0 && (
            <p className="text-muted-foreground text-xs">Start a scan to stream logs here.</p>
          )}
          {logs.map((entry) => (
            <div key={entry.id} className={cn(
              "text-xs leading-relaxed",
              entry.text.includes("[error]") || entry.text.includes("FAIL") ? "text-red-400"
              : entry.text.includes("[warn]") || entry.text.includes("WARNING")  ? "text-yellow-400"
              : entry.text.includes("[ok]")  || entry.text.includes("PASS")      ? "text-green-400"
              : "text-slate-300"
            )}>
              {entry.text}
            </div>
          ))}
          <div ref={logEndRef} />
        </div>
      </div>

      {(startMut.error || stopMut.error) && (
        <div className="bg-red-950/30 border border-red-500 text-red-400 rounded p-4 text-sm">
          {(startMut.error as Error)?.message ?? (stopMut.error as Error)?.message}
        </div>
      )}
    </div>
  )
}
