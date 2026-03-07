"use client"
import { useQuery } from "@tanstack/react-query"
import { useParams } from "next/navigation"
import Link from "next/link"
import { getSkill } from "@/lib/api"
import { ArrowLeft, Puzzle, Shell, Globe, AlertTriangle, ShieldCheck, ShieldX } from "lucide-react"
import { ScoreGauge } from "@/components/ScoreGauge"
import { cn } from "@/lib/utils"

function TrustBadge({ score }: { score: string }) {
  const map: Record<string, string> = {
    TRUSTED:   "bg-green-500/10 text-green-400 border-green-500/20",
    CAUTION:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    UNTRUSTED: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    QUARANTINE:"bg-red-500/10 text-red-400 border-red-500/20",
  }
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded border font-medium", map[score] ?? map.CAUTION)}>
      {score}
    </span>
  )
}

function InjectionBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    LOW:      "bg-green-500/10 text-green-400 border-green-500/20",
    MEDIUM:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    HIGH:     "bg-orange-500/10 text-orange-400 border-orange-500/20",
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/20",
  }
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded border font-medium", map[risk] ?? map.MEDIUM)}>
      {risk}
    </span>
  )
}

export default function SkillDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { data: skill, isLoading, error } = useQuery({
    queryKey: ["skill", id],
    queryFn:  () => getSkill(id),
  })

  if (isLoading) return <div className="p-8 text-muted-foreground text-sm">Loading…</div>
  if (error || !skill) return (
    <div className="p-8">
      <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-4 text-sm">
        Skill not found or failed to load.
      </div>
    </div>
  )

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
          <div className="flex items-center gap-2 flex-wrap">
            <TrustBadge score={skill.trust_score} />
            <span className="text-xs text-muted-foreground">Risk Level:</span>
            <span className="text-xs font-medium">{skill.risk_level}</span>
          </div>
          <p className="text-xs text-muted-foreground font-mono break-all">{skill.path}</p>
          {skill.source && (
            <p className="text-xs text-muted-foreground">Source: {skill.source}</p>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-card border border-border rounded-lg p-4 space-y-3">
          <h2 className="text-xs text-muted-foreground uppercase tracking-wider">Capabilities</h2>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2 text-xs">
                <Shell size={12} className={skill.shell_access ? "text-orange-400" : "text-muted-foreground"} />
                Shell Execution
              </div>
              {skill.shell_access
                ? <span className="flex items-center gap-1 text-xs text-orange-400"><ShieldX size={10} /> Enabled</span>
                : <span className="flex items-center gap-1 text-xs text-green-400"><ShieldCheck size={10} /> Disabled</span>
              }
            </div>
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2 text-xs">
                <AlertTriangle size={12} className="text-muted-foreground" />
                Injection Risk
              </div>
              <InjectionBadge risk={skill.injection_risk} />
            </div>
          </div>
        </div>

        <div className="bg-card border border-border rounded-lg p-4 space-y-3">
          <h2 className="text-xs text-muted-foreground uppercase tracking-wider">
            Network Access ({skill.outbound_domains.length})
          </h2>
          {skill.outbound_domains.length > 0 ? (
            <ul className="space-y-1">
              {skill.outbound_domains.map(d => (
                <li key={d} className="flex items-center gap-2 text-xs">
                  <Globe size={10} className="text-blue-400 shrink-0" />
                  <span className="font-mono">{d}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">No outbound domains declared</p>
          )}
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg p-4 space-y-2">
        <h2 className="text-xs text-muted-foreground uppercase tracking-wider mb-3">Metadata</h2>
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div>
            <p className="text-muted-foreground">Scan ID</p>
            <p className="font-mono">{skill.scan_id.slice(0, 12)}…</p>
          </div>
          <div>
            <p className="text-muted-foreground">Detected</p>
            <p>{new Date(skill.detected_at).toLocaleString()}</p>
          </div>
        </div>
      </div>
    </div>
  )
}
