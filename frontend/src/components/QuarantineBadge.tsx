"use client"
import { ShieldAlert } from "lucide-react"
import { formatDate } from "@/lib/utils"

interface QuarantineBadgeProps {
  quarantinedAt?: string | null
  reason?: string | null
}

export function QuarantineBadge({ quarantinedAt, reason }: QuarantineBadgeProps) {
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold bg-red-950/60 text-red-400 border border-red-700/50"
      title={[
        reason ? `Reason: ${reason}` : null,
        quarantinedAt ? `Since: ${formatDate(quarantinedAt)}` : null,
      ]
        .filter(Boolean)
        .join(" | ")}
    >
      <ShieldAlert size={12} />
      QUARANTINED
    </span>
  )
}
