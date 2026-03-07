"use client"
import { useState, useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import Link from "next/link"
import { getSkills } from "@/lib/api"
import { riskColor, cn } from "@/lib/utils"
import { ChevronRight, Search, Puzzle, Shell, Globe, AlertTriangle } from "lucide-react"

export default function SkillsPage() {
  const { data: skills, isLoading, error } = useQuery({ queryKey: ["skills"], queryFn: getSkills })
  const [q, setQ] = useState("")

  const filtered = useMemo(() => (skills ?? []).filter(s =>
    s.name.toLowerCase().includes(q.toLowerCase()) ||
    s.path.toLowerCase().includes(q.toLowerCase())
  ), [skills, q])

  if (error) return (
    <div className="p-8">
      <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-4 text-sm">
        Failed to load skills: {(error as Error).message}
      </div>
    </div>
  )

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Skill Explorer</h1>
        <span className="text-xs text-muted-foreground">
          {filtered.length} skill{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <input
          className="w-full bg-card border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
          placeholder="Search skills…"
          value={q}
          onChange={e => setQ(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="text-muted-foreground text-sm">Loading skills…</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(skill => (
            <Link
              key={skill.id}
              href={`/skills/${skill.id}`}
              className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group"
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Puzzle size={14} className="text-primary shrink-0 mt-0.5" />
                  <span className="font-medium text-sm">{skill.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className={cn("text-xs font-bold", riskColor(skill.risk_score))}>
                    {skill.risk_level}
                  </span>
                  <ChevronRight size={14} className="text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                </div>
              </div>

              <p className="text-xs text-muted-foreground line-clamp-1 mb-3 font-mono">
                {skill.path.replace(/.*\/skills\//, "…/skills/")}
              </p>

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Risk</span>
                  <span className={cn("text-sm font-bold", riskColor(skill.risk_score))}>{skill.risk_score}</span>
                </div>
                <div className="flex gap-1 flex-wrap justify-end">
                  {skill.shell_access && (
                    <span className="flex items-center gap-1 text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded">
                      <Shell size={10} /> shell
                    </span>
                  )}
                  {skill.outbound_domains.length > 0 && (
                    <span className="flex items-center gap-1 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded">
                      <Globe size={10} /> network
                    </span>
                  )}
                  {(skill.injection_risk === "HIGH" || skill.injection_risk === "CRITICAL") && (
                    <span className="flex items-center gap-1 text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded">
                      <AlertTriangle size={10} /> injection
                    </span>
                  )}
                </div>
              </div>

              {skill.trust_score === "QUARANTINE" || skill.trust_score === "UNTRUSTED" ? (
                <div className="mt-2 text-xs text-red-400">
                  ⚠ Trust: {skill.trust_score}
                </div>
              ) : null}
            </Link>
          ))}
          {filtered.length === 0 && (
            <p className="col-span-3 text-muted-foreground text-sm py-8 text-center">
              {skills?.length === 0 ? "No skills found — run a scan first." : "No skills match your search."}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
