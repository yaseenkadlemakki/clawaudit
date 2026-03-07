"use client"
import { useQuery } from "@tanstack/react-query"
import { useParams } from "next/navigation"
import Link from "next/link"
import { getSkill, getFindings } from "@/lib/api"
import { ArrowLeft, ShieldAlert, Puzzle } from "lucide-react"
import { RiskBadge } from "@/components/RiskBadge"
import { ScoreGauge } from "@/components/ScoreGauge"

export default function SkillDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: skill, isLoading } = useQuery({
    queryKey: ["skill", id],
    queryFn:  () => getSkill(id),
  })
  const { data: findings } = useQuery({
    queryKey: ["findings", { skill: id }],
    queryFn:  () => getFindings({ skill: id, limit: 20 }),
    enabled: !!id,
  })

  if (isLoading) return <div className="p-8 text-muted-foreground">Loading…</div>
  if (!skill)   return <div className="p-8 text-red-400">Skill not found.</div>

  return (
    <div className="p-8 space-y-6 max-w-4xl">
      <Link href="/skills" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
        <ArrowLeft size={12} /> Back to Skills
      </Link>

      <div className="flex items-start gap-6">
        <ScoreGauge score={skill.risk_score} />
        <div className="flex-1 space-y-2">
          <div className="flex items-center gap-2">
            <Puzzle size={16} className="text-primary" />
            <h1 className="text-xl font-bold">{skill.name}</h1>
          </div>
          <p className="text-sm text-muted-foreground">{skill.description}</p>
          <p className="text-xs text-muted-foreground font-mono">{skill.location}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <h2 className="text-xs text-muted-foreground mb-3 uppercase tracking-wider">Permissions</h2>
          {skill.permissions.length === 0 ? (
            <p className="text-xs text-muted-foreground">None declared</p>
          ) : (
            <ul className="space-y-1">
              {skill.permissions.map(p => (
                <li key={p} className="flex items-center gap-2 text-xs">
                  <ShieldAlert size={10} className="text-orange-400" />
                  {p}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="bg-card border border-border rounded-lg p-4">
          <h2 className="text-xs text-muted-foreground mb-3 uppercase tracking-wider">Capabilities</h2>
          <div className="flex flex-wrap gap-2">
            {skill.capabilities.map(c => (
              <span key={c} className="bg-secondary px-2 py-1 rounded text-xs">{c}</span>
            ))}
            {skill.capabilities.length === 0 && (
              <p className="text-xs text-muted-foreground">None declared</p>
            )}
          </div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4">
        <h2 className="text-xs text-muted-foreground mb-3 uppercase tracking-wider">
          Related Findings ({findings?.length ?? 0})
        </h2>
        {findings?.length ? (
          <div className="space-y-2">
            {findings.map(f => (
              <div key={f.id} className="flex items-start gap-3 text-sm border-b border-border/40 pb-2 last:border-0">
                <RiskBadge severity={f.severity} className="mt-0.5 shrink-0" />
                <div>
                  <p className="font-medium text-sm">{f.title}</p>
                  <p className="text-xs text-muted-foreground">{f.policy}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">No findings for this skill.</p>
        )}
      </div>
    </div>
  )
}
