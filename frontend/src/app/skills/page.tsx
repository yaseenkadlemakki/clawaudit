"use client"
import { useState, useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import Link from "next/link"
import { getSkills } from "@/lib/api"
import { riskColor, cn } from "@/lib/utils"
import { ChevronRight, Search, Puzzle } from "lucide-react"

export default function SkillsPage() {
  const { data: skills, isLoading } = useQuery({ queryKey: ["skills"], queryFn: getSkills })
  const [q, setQ] = useState("")

  const filtered = useMemo(() => (skills ?? []).filter(s =>
    s.name.toLowerCase().includes(q.toLowerCase()) ||
    s.description.toLowerCase().includes(q.toLowerCase())
  ), [skills, q])

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
                <ChevronRight size={14} className="text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
              </div>
              <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{skill.description}</p>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Risk</span>
                  <span className={cn("text-sm font-bold", riskColor(skill.risk_score))}>{skill.risk_score}</span>
                </div>
                <div className="flex gap-1 flex-wrap justify-end">
                  {skill.capabilities.slice(0, 3).map(cap => (
                    <span key={cap} className="text-xs bg-secondary px-1.5 py-0.5 rounded text-muted-foreground">{cap}</span>
                  ))}
                  {skill.capabilities.length > 3 && (
                    <span className="text-xs text-muted-foreground">+{skill.capabilities.length - 3}</span>
                  )}
                </div>
              </div>
              {skill.policy_violations > 0 && (
                <div className="mt-2 text-xs text-red-400">
                  ⚠ {skill.policy_violations} policy violation{skill.policy_violations !== 1 ? "s" : ""}
                </div>
              )}
            </Link>
          ))}
          {filtered.length === 0 && (
            <p className="col-span-3 text-muted-foreground text-sm py-8 text-center">
              No skills match your search.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
