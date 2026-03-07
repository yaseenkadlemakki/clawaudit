"use client"
import { useQuery } from "@tanstack/react-query"
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts"
import { getDashboard, getScans } from "@/lib/api"
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
  complete: <CheckCircle2 size={14} className="text-green-400" />,
  running:  <span className="animate-pulse text-blue-400 text-xs">●</span>,
  failed:   <AlertTriangle size={14} className="text-red-400" />,
  stopped:  <Info size={14} className="text-slate-400" />,
}

export default function DashboardPage() {
  const stats = useQuery({ queryKey: ["dashboard"], queryFn: getDashboard, refetchInterval: 15_000 })
  const scans = useQuery({ queryKey: ["scans"],     queryFn: getScans,     refetchInterval: 15_000 })
  const d = stats.data

  const riskData = d
    ? [
        { name: "Critical", value: d.critical },
        { name: "High",     value: d.high     },
        { name: "Medium",   value: d.medium   },
        { name: "Low",      value: d.low      },
      ]
    : []

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-xl font-bold tracking-wide text-foreground">Security Dashboard</h1>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: d?.total_findings ?? "—", icon: <ShieldAlert size={16} className="text-orange-400" /> },
          { label: "Critical",       value: d?.critical       ?? "—", icon: <AlertTriangle size={16} className="text-red-400" /> },
          { label: "High",           value: d?.high           ?? "—", icon: <AlertTriangle size={16} className="text-orange-400" /> },
          { label: "Scans Run",      value: d?.total_scans    ?? "—", icon: <Info size={16} className="text-blue-400" /> },
        ].map(({ label, value, icon }) => (
          <div key={label} className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-2">{icon} {label}</div>
            <p className="text-2xl font-bold text-foreground">{value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-card border border-border rounded-lg p-6 flex flex-col items-center gap-2">
          <h2 className="text-sm text-muted-foreground self-start">Overall Risk Score</h2>
          <ScoreGauge score={d?.security_score ?? 0} />
          <p className="text-xs text-muted-foreground">
            {d?.last_scan_at ? `Last scan ${formatDate(d.last_scan_at)}` : "No scans yet"}
          </p>
        </div>

        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-sm text-muted-foreground mb-4">Risk Distribution</h2>
          {riskData.length > 0 ? (
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
            <p className="text-muted-foreground text-sm">No data yet.</p>
          )}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-6">
        <h2 className="text-sm text-muted-foreground mb-4">Scan History</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-muted-foreground text-xs">
                {["ID", "Status", "Started", "Finished", "Findings", "Score"].map(h => (
                  <th key={h} className="text-left py-2 pr-4">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(scans.data ?? []).map((s) => (
                <tr key={s.id} className="border-b border-border/40 hover:bg-secondary/30">
                  <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">{s.id.slice(0, 8)}…</td>
                  <td className="py-2 pr-4">
                    <span className="flex items-center gap-1">
                      {STATUS_ICON[s.status]}
                      <span className="text-xs capitalize">{s.status}</span>
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-xs">{formatDate(s.started_at)}</td>
                  <td className="py-2 pr-4 text-xs">{s.finished_at ? formatDate(s.finished_at) : "—"}</td>
                  <td className="py-2 pr-4">{s.findings_count}</td>
                  <td className="py-2 font-mono">{s.score ?? "—"}</td>
                </tr>
              ))}
              {!scans.data?.length && (
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
