"use client"
import { useQuery } from "@tanstack/react-query"
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts"
import { getDashboard } from "@/lib/api"
import { ScoreGauge } from "@/components/ScoreGauge"
import { formatDate } from "@/lib/utils"
import { AlertTriangle, CheckCircle2, ShieldAlert, Info } from "lucide-react"

const SEV_COLORS: Record<string, string> = {
  Critical: "#f87171",
  High:     "#fb923c",
  Medium:   "#fbbf24",
  Low:      "#60a5fa",
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  completed: <CheckCircle2 size={14} className="text-green-400" />,
  running:   <span className="animate-pulse text-blue-400 text-xs">●</span>,
  failed:    <AlertTriangle size={14} className="text-red-400" />,
  stopping:  <span className="text-yellow-400 text-xs">◌</span>,
}

export default function DashboardPage() {
  const { data: d, error, isLoading } = useQuery({
    queryKey: ["dashboard"],
    queryFn: getDashboard,
    refetchInterval: 15_000,
  })

  const riskData = d
    ? [
        { name: "Critical", value: d.risk_distribution.Critical },
        { name: "High",     value: d.risk_distribution.High     },
        { name: "Medium",   value: d.risk_distribution.Medium   },
        { name: "Low",      value: d.risk_distribution.Low      },
      ]
    : []

  const totalFindings = d
    ? Object.values(d.risk_distribution).reduce((a, b) => a + b, 0)
    : 0

  const lastScan = d?.recent_scans?.[0]

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-xl font-bold tracking-wide text-foreground">Security Dashboard</h1>

      {error && (
        <div className="bg-red-950/30 border border-red-500 text-red-400 rounded p-4 text-sm">
          Failed to load dashboard: {(error as Error)?.message ?? "Unknown error"}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: isLoading ? "…" : error ? "—" : totalFindings,              icon: <ShieldAlert size={16} className="text-orange-400" /> },
          { label: "Critical",       value: isLoading ? "…" : error ? "—" : d?.risk_distribution.Critical ?? 0, icon: <AlertTriangle size={16} className="text-red-400" /> },
          { label: "High",           value: isLoading ? "…" : error ? "—" : d?.risk_distribution.High    ?? 0, icon: <AlertTriangle size={16} className="text-orange-400" /> },
          { label: "Scans Run",      value: isLoading ? "…" : error ? "—" : d?.recent_scans?.length      ?? 0, icon: <Info size={16} className="text-blue-400" /> },
        ].map(({ label, value, icon }) => (
          <div key={label} className={`bg-card border rounded-lg p-4 ${error ? "border-red-500/30 opacity-60" : "border-border"}`}>
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">{icon} {label}</div>
            <p className="text-2xl font-bold text-foreground">{value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-card border border-border rounded-lg p-6 flex flex-col items-center gap-2">
          <h2 className="text-sm text-muted-foreground self-start">Overall Risk Score</h2>
          {error ? (
            <div className="flex items-center justify-center w-[180px] h-[180px]">
              <span className="text-muted-foreground text-sm">Unavailable</span>
            </div>
          ) : (
            <ScoreGauge score={d?.overall_score ?? 0} />
          )}
          <p className="text-xs text-muted-foreground">
            {lastScan ? `Last scan ${formatDate(lastScan.started_at)}` : "No scans yet"}
          </p>
        </div>

        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-sm text-muted-foreground mb-4">Risk Distribution</h2>
          {riskData.some(r => r.value > 0) ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={riskData} barSize={36}>
                <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 11 }} />
                <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 6 }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-muted-foreground text-sm">No data yet — run a scan first.</p>
          )}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6">
        <h2 className="text-sm text-muted-foreground mb-4">Scan History</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-muted-foreground text-xs">
                {["ID", "Status", "Started", "Finished", "Skills", "Findings"].map(h => (
                  <th key={h} className="text-left py-2 pr-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(d?.recent_scans ?? []).map((s) => (
                <tr key={s.id} className="border-b border-border/40 hover:bg-secondary/30">
                  <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">{s.id.slice(0, 8)}…</td>
                  <td className="py-2 pr-4">
                    <span className="flex items-center gap-1">
                      {STATUS_ICON[s.status] ?? <Info size={14} className="text-slate-400" />}
                      <span className="text-xs capitalize">{s.status}</span>
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-xs">{formatDate(s.started_at)}</td>
                  <td className="py-2 pr-4 text-xs">{s.completed_at ? formatDate(s.completed_at) : "—"}</td>
                  <td className="py-2 pr-4 text-xs">{s.skills_scanned ?? "—"}</td>
                  <td className="py-2 text-xs">{s.total_findings ?? "—"}</td>
                </tr>
              ))}
              {!d?.recent_scans?.length && !isLoading && (
                <tr>
                  <td colSpan={6} className="py-6 text-center text-muted-foreground text-xs">
                    No scans yet. Run a Full Audit to populate this table.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
