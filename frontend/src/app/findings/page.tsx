"use client"
import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { getFindings, getSkills, type Finding } from "@/lib/api"
import { RiskBadge } from "@/components/RiskBadge"
import { formatDate } from "@/lib/utils"
import { Search, ChevronDown, ChevronUp } from "lucide-react"

const SEVERITIES = ["critical", "high", "medium", "low", "info"]

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr
        className="border-b border-border/40 hover:bg-secondary/20 cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-3 pl-4"><RiskBadge severity={finding.severity} /></td>
        <td className="py-3 px-4 font-medium text-sm">{finding.title}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{finding.policy}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{finding.skill_name ?? "—"}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{formatDate(finding.created_at)}</td>
        <td className="py-3 pr-4">
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </td>
      </tr>
      {open && (
        <tr className="bg-secondary/10 border-b border-border/40">
          <td colSpan={6} className="px-4 py-3 space-y-2">
            <p className="text-sm text-muted-foreground">{finding.description}</p>
            {finding.remediation && (
              <div className="bg-card border border-border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Remediation</p>
                <p className="text-xs">{finding.remediation}</p>
              </div>
            )}
            <p className="text-xs text-muted-foreground font-mono">
              scan: {finding.scan_id.slice(0, 12)}…
            </p>
          </td>
        </tr>
      )}
    </>
  )
}

export default function FindingsPage() {
  const [q, setQ]           = useState("")
  const [sev, setSev]       = useState("")
  const [policy, setPolicy] = useState("")
  const [skill, setSkill]   = useState("")

  const { data: skills } = useQuery({ queryKey: ["skills"], queryFn: getSkills })
  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings", { q, sev, policy, skill }],
    queryFn:  () => getFindings({
      q:        q      || undefined,
      severity: sev    || undefined,
      policy:   policy || undefined,
      skill:    skill  || undefined,
      limit: 100,
    }),
  })

  const policies = Array.from(new Set((findings ?? []).map(f => f.policy).filter(Boolean)))

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Findings Explorer</h1>
        <span className="text-xs text-muted-foreground">
          {findings?.length ?? 0} result{findings?.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            className="w-full bg-card border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
            placeholder="Search findings…"
            value={q}
            onChange={e => setQ(e.target.value)}
          />
        </div>
        <select
          className="bg-card border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          value={sev}
          onChange={e => setSev(e.target.value)}
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>
        <select
          className="bg-card border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          value={policy}
          onChange={e => setPolicy(e.target.value)}
        >
          <option value="">All Policies</option>
          {policies.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select
          className="bg-card border border-border rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          value={skill}
          onChange={e => setSkill(e.target.value)}
        >
          <option value="">All Skills</option>
          {(skills ?? []).map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-muted-foreground text-xs">
              {["Severity", "Title", "Policy", "Skill", "Detected", ""].map((h, i) => (
                <th key={i} className="text-left px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-muted-foreground text-xs">
                  Loading findings…
                </td>
              </tr>
            ) : findings?.length ? (
              findings.map(f => <FindingRow key={f.id} finding={f} />)
            ) : (
              <tr>
                <td colSpan={6} className="py-8 text-center text-muted-foreground text-xs">
                  No findings match your filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
