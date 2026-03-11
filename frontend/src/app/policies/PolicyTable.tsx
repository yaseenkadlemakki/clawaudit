"use client"
import { Pencil, Trash2, Lock } from "lucide-react"
import type { Policy } from "@/lib/api"

const ACTION_COLORS: Record<string, string> = {
  BLOCK:      "bg-red-950/60 text-red-400 border-red-700/50",
  ALERT:      "bg-orange-950/60 text-orange-400 border-orange-700/50",
  WARN:       "bg-yellow-950/60 text-yellow-400 border-yellow-700/50",
  QUARANTINE: "bg-purple-950/60 text-purple-400 border-purple-700/50",
  ALLOW:      "bg-green-950/60 text-green-400 border-green-700/50",
}

const DOMAIN_COLORS: Record<string, string> = {
  tool_call:  "bg-blue-950/60 text-blue-400",
  config:     "bg-slate-800 text-slate-400",
  runtime:    "bg-indigo-950/60 text-indigo-400",
  capability: "bg-teal-950/60 text-teal-400",
  "*":        "bg-slate-800 text-slate-400",
}

interface PolicyTableProps {
  policies: Policy[]
  onEdit: (policy: Policy) => void
  onDelete: (policy: Policy) => void
  onToggle: (policy: Policy, enabled: boolean) => void
}

export function PolicyTable({ policies, onEdit, onDelete, onToggle }: PolicyTableProps) {
  if (policies.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground text-sm">
        No policies found.
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-muted-foreground text-xs">
            {["Name", "Domain", "Condition", "Action", "Violations", "Enabled", ""].map((h) => (
              <th key={h} className="text-left py-2 pr-4 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr
              key={p.id}
              className="border-b border-border/40 hover:bg-secondary/30 transition-colors"
            >
              <td className="py-3 pr-4">
                <span className="font-medium text-foreground">{p.name}</span>
                {p.builtin && (
                  <span title="Built-in policy"><Lock size={11} className="inline ml-1.5 text-muted-foreground" /></span>
                )}
                {p.description && (
                  <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{p.description}</p>
                )}
              </td>
              <td className="py-3 pr-4">
                <span
                  className={`inline-block px-2 py-0.5 rounded text-xs ${DOMAIN_COLORS[p.domain] ?? "bg-slate-800 text-slate-400"}`}
                >
                  {p.domain}
                </span>
              </td>
              <td className="py-3 pr-4 font-mono text-xs text-muted-foreground">
                {p.check} <span className="text-slate-500">{p.condition}</span>{" "}
                <span className="text-foreground">{p.value || "—"}</span>
              </td>
              <td className="py-3 pr-4">
                <span
                  className={`inline-block px-2 py-0.5 rounded text-xs border font-semibold ${ACTION_COLORS[p.action] ?? "bg-slate-800 text-slate-400 border-slate-700"}`}
                >
                  {p.action}
                </span>
              </td>
              <td className="py-3 pr-4 text-xs">
                {p.violation_count > 0 ? (
                  <span className="text-orange-400 font-medium">{p.violation_count}</span>
                ) : (
                  <span className="text-muted-foreground">0</span>
                )}
              </td>
              <td className="py-3 pr-4">
                <button
                  onClick={() => onToggle(p, !p.enabled)}
                  aria-label={p.enabled ? "Disable policy" : "Enable policy"}
                  disabled={p.builtin}
                  title={p.builtin ? "Built-in policies cannot be toggled" : undefined}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    p.enabled ? "bg-primary" : "bg-slate-700"
                  } ${p.builtin ? "opacity-60 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  <span
                    className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${
                      p.enabled ? "translate-x-4" : "translate-x-0.5"
                    }`}
                  />
                </button>
              </td>
              <td className="py-3 text-right">
                <div className="flex items-center justify-end gap-1">
                  {!p.builtin && (
                    <button
                      onClick={() => onEdit(p)}
                      aria-label="Edit policy"
                      className="p-1.5 rounded hover:bg-secondary text-muted-foreground hover:text-foreground transition-colors"
                    >
                      <Pencil size={13} />
                    </button>
                  )}
                  <button
                    onClick={() => onDelete(p)}
                    aria-label="Delete policy"
                    disabled={p.builtin}
                    title={p.builtin ? "Cannot delete built-in policies" : undefined}
                    className={`p-1.5 rounded transition-colors ${
                      p.builtin
                        ? "text-muted-foreground/30 cursor-not-allowed"
                        : "hover:bg-red-950/40 text-muted-foreground hover:text-red-400"
                    }`}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
