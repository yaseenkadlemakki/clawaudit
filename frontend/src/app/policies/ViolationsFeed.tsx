"use client"
import { useQuery } from "@tanstack/react-query"
import Link from "next/link"
import { ExternalLink } from "lucide-react"
import { getViolations } from "@/lib/api"
import { formatDate } from "@/lib/utils"

const ACTION_COLORS: Record<string, string> = {
  BLOCK:      "text-red-400 bg-red-950/60 border-red-700/50",
  ALERT:      "text-orange-400 bg-orange-950/60 border-orange-700/50",
  QUARANTINE: "text-purple-400 bg-purple-950/60 border-purple-700/50",
}

function extractAction(title: string): string {
  if (title.includes("BLOCK")) return "BLOCK"
  if (title.includes("QUARANTINE")) return "QUARANTINE"
  return "ALERT"
}

export function ViolationsFeed() {
  const { data: violations, isLoading, error } = useQuery({
    queryKey: ["violations"],
    queryFn: getViolations,
    refetchInterval: 10_000,
  })

  if (isLoading) {
    return (
      <div className="py-12 text-center text-muted-foreground text-sm">Loading violations…</div>
    )
  }

  if (error) {
    return (
      <div className="bg-red-950/30 border border-red-700/50 text-red-400 rounded p-4 text-sm">
        Failed to load violations: {(error as Error)?.message ?? "Unknown error"}
      </div>
    )
  }

  if (!violations?.length) {
    return (
      <div className="py-12 text-center text-muted-foreground text-sm">
        No policy violations yet. Violations appear here when policies fire ALERT, BLOCK, or QUARANTINE.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-muted-foreground text-xs">
            {["Time", "Tool / Policy", "Action", "Skill", "Evidence", ""].map((h) => (
              <th key={h} className="text-left py-2 pr-4 font-medium">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {violations.map((v) => {
            const action = extractAction(v.title)
            return (
              <tr
                key={v.id}
                className="border-b border-border/40 hover:bg-secondary/30 transition-colors"
              >
                <td className="py-3 pr-4 text-xs text-muted-foreground whitespace-nowrap">
                  {v.detected_at ? formatDate(v.detected_at) : "—"}
                </td>
                <td className="py-3 pr-4">
                  <p className="text-foreground text-xs font-medium line-clamp-1">{v.title}</p>
                  <p className="text-muted-foreground text-xs mt-0.5">{v.check_id}</p>
                </td>
                <td className="py-3 pr-4">
                  <span
                    className={`inline-block px-2 py-0.5 rounded text-xs border font-semibold ${ACTION_COLORS[action] ?? "text-orange-400 bg-orange-950/60 border-orange-700/50"}`}
                  >
                    {action}
                  </span>
                </td>
                <td className="py-3 pr-4 text-xs text-muted-foreground">
                  {v.skill_name ?? "—"}
                </td>
                <td className="py-3 pr-4 text-xs text-muted-foreground max-w-[200px]">
                  <span className="line-clamp-1 font-mono">{v.evidence}</span>
                </td>
                <td className="py-3">
                  <Link
                    href={`/findings?domain=policy`}
                    className="text-muted-foreground hover:text-primary transition-colors"
                    title="View finding"
                  >
                    <ExternalLink size={13} />
                  </Link>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
