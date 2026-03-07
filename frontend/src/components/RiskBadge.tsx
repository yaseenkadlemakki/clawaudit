import { cn, severityColor } from "@/lib/utils"

interface Props { severity: string; className?: string }

export function RiskBadge({ severity, className }: Props) {
  return (
    <span className={cn(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
      severityColor(severity),
      className
    )}>
      {severity.toUpperCase()}
    </span>
  )
}
