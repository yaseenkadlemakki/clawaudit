"use client"
import { useState, useEffect } from "react"
import { X } from "lucide-react"
import type { Policy, PolicyCreate } from "@/lib/api"

const DOMAINS = ["tool_call", "config", "runtime", "capability", "*"]
const CONDITIONS = ["equals", "not_equals", "contains", "not_contains", "matches", "glob", "starts_with", "ends_with", "gt", "gte", "in", "not_in", "exists", "not_exists"]
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
const ACTIONS = ["ALLOW", "WARN", "ALERT", "BLOCK", "QUARANTINE"]
const KNOWN_CHECKS = [
  "tool", "params.pty", "params.elevated", "params.path", "params.command",
  "params.url", "params.action", "skill.name", "skill.signed", "skill.publisher", "skill.path",
]

interface PolicyFormModalProps {
  policy?: Policy | null
  onSave: (data: PolicyCreate) => Promise<void>
  onClose: () => void
}

const EMPTY: PolicyCreate = {
  name: "",
  domain: "tool_call",
  check: "",
  condition: "equals",
  value: "",
  severity: "HIGH",
  action: "ALERT",
  enabled: true,
  description: "",
  priority: 0,
}

export function PolicyFormModal({ policy, onSave, onClose }: PolicyFormModalProps) {
  const [form, setForm] = useState<PolicyCreate>(
    policy
      ? {
          name: policy.name,
          domain: policy.domain,
          check: policy.check,
          condition: policy.condition,
          value: policy.value,
          severity: policy.severity,
          action: policy.action,
          enabled: policy.enabled,
          description: policy.description ?? "",
          priority: policy.priority,
        }
      : EMPTY
  )
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function update(field: keyof PolicyCreate, value: unknown) {
    setForm((prev) => ({ ...prev, [field]: value }))
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name.trim()) { setError("Name is required"); return }
    if (!form.check.trim()) { setError("Check field is required"); return }
    setSaving(true)
    setError(null)
    try {
      await onSave(form)
      onClose()
    } catch (err) {
      setError((err as Error)?.message ?? "Failed to save policy")
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-card border border-border rounded-lg w-full max-w-lg shadow-xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <h2 className="font-semibold text-foreground">
            {policy ? "Edit Policy" : "New Policy"}
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="px-6 py-5 space-y-4">
          {error && (
            <div className="bg-red-950/30 border border-red-700/50 text-red-400 rounded p-3 text-sm">
              {error}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className="block text-xs text-muted-foreground mb-1">Name *</label>
              <input
                value={form.name}
                onChange={(e) => update("name", e.target.value)}
                placeholder="my-policy-name"
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Domain</label>
              <select
                value={form.domain}
                onChange={(e) => update("domain", e.target.value)}
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {DOMAINS.map((d) => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Check Field *</label>
              <input
                list="check-options"
                value={form.check}
                onChange={(e) => update("check", e.target.value)}
                placeholder="params.pty"
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
              />
              <datalist id="check-options">
                {KNOWN_CHECKS.map((c) => <option key={c} value={c} />)}
              </datalist>
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Condition</label>
              <select
                value={form.condition}
                onChange={(e) => update("condition", e.target.value)}
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {CONDITIONS.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Value</label>
              <input
                value={form.value}
                onChange={(e) => update("value", e.target.value)}
                placeholder="true"
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Severity</label>
              <select
                value={form.severity}
                onChange={(e) => update("severity", e.target.value)}
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>

            <div>
              <label className="block text-xs text-muted-foreground mb-1">Action</label>
              <select
                value={form.action}
                onChange={(e) => update("action", e.target.value)}
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              >
                {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>

            <div className="col-span-2">
              <label className="block text-xs text-muted-foreground mb-1">Priority</label>
              <input
                type="number"
                value={form.priority}
                onChange={(e) => update("priority", parseInt(e.target.value, 10) || 0)}
                min={0}
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>

            <div className="col-span-2">
              <label className="block text-xs text-muted-foreground mb-1">Description</label>
              <textarea
                value={form.description ?? ""}
                onChange={(e) => update("description", e.target.value)}
                rows={2}
                placeholder="Describe what this policy enforces..."
                className="w-full bg-secondary border border-border rounded px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary resize-none"
              />
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm rounded border border-border text-muted-foreground hover:text-foreground transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="px-4 py-2 text-sm rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-60"
            >
              {saving ? "Saving…" : "Save Policy"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
