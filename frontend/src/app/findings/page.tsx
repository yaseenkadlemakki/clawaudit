"use client"
import { useState } from "react"
import { useSearchParams } from "next/navigation"
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
        aria-expanded={open}
        role="button"
      >
        <td className="py-3 pl-4"><RiskBadge severity={finding.severity} /></td>
        <td className="py-3 px-4 font-medium text-sm">{finding.title}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground font-mono">{finding.check_id}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{finding.domain}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{finding.skill_name ?? "—"}</td>
        <td className="py-3 px-4 text-xs text-muted-foreground">{finding.detected_at ? formatDate(finding.detected_at) : "—"}</td>
        <td className="py-3 pr-4">
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </td>
      </tr>
      {open && (
        <tr className="bg-secondary/10 border-b border-border/40">
          <td colSpan={7} className="px-4 py-3 space-y-2">
            <p className="text-sm text-muted-foreground">{finding.description}</p>
            {finding.evidence && (
              <div className="bg-card border border-border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Evidence</p>
                <p className="text-xs font-mono">{finding.evidence}</p>
              </div>
            )}
            {finding.remediation && (
              <div className="bg-card border border-border rounded p-3">
                <p className="text-xs text-muted-foreground mb-1">Remediation</p>
                <p className="text-xs">{finding.remediation}</p>
              </div>
            )}
            <p className="text-xs text-muted-foreground font-mono">
              scan: {finding.scan_id.slice(0, 12)}… · location: {finding.location}
            </p>
          </td>
        </tr>
      )}
    </>
  )
}

export default function FindingsPage() {
  const searchParams = useSearchParams()
  const scanIdParam = searchParams.get("scan_id") ?? undefined

  const [q, setQ]             = useState("")
  const [sev, setSev]         = useState("")
  const [domain, setDomain]   = useState("")

  const { data: allFindings, error: allError } = useQuery({
    queryKey: ["findings-all", scanIdParam],
    queryFn:  () => getFindings({ limit: 500, scan_id: scanIdParam }),
    staleTime: 30_000,
  })
  const { data: findings, isLoading, error: findingsError } = useQuery({
    queryKey: ["findings", { sev, domain, scanIdParam }],
    queryFn:  () => getFindings({
      severity: sev    || undefined,
      domain:   domain || undefined,
      scan_id:  scanIdParam,
      limit: 100,
    }),
  })

  const domains = Array.from(new Set((allFindings ?? []).map(f => f.domain).filter(Boolean)))

  // Client-side text search on title/description/check_id
  const filtered = q
    ? (findings ?? []).filter(f =>
        f.title.toLowerCase().includes(q.toLowerCase()) ||
        f.check_id.toLowerCase().includes(q.toLowerCase()) ||
        f.description.toLowerCase().includes(q.toLowerCase())
      )
    : (findings ?? [])

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Findings Explorer</h1>
        <span className="text-xs text-muted-foreground">
          {filtered.length} result{filtered.length !== 1 ? "s" : ""}
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
          value={domain}
          onChange={e => setDomain(e.target.value)}
        >
          <option value="">All Domains</option>
          {domains.map(d => <option key={d} value={d}>{d}</option>)}
        </select>
      </div>

      {(findingsError || allError) && (
        <div className="rounded border border-red-500 bg-red-950/30 p-4 text-red-400 text-sm">
          Failed to load findings: {String(findingsError ?? allError)}
        </div>
      )}

      <div className="bg-card border border-border rounded-lg overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-muted-foreground text-xs">
              {["Severity", "Title", "Check ID", "Domain", "Skill", "Detected", ""].map((h, i) => (
                <th key={i} className="text-left px-4 py-3">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-muted-foreground text-xs">
                  Loading findings…
                </td>
              </tr>
            ) : filtered.length ? (
              filtered.map(f => <FindingRow key={f.id} finding={f} />)
            ) : !findingsError && !allError ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-muted-foreground text-xs">
                  No findings match your filters.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  )
}
