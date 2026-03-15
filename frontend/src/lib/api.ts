const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:18790/api/v1"
export const API_BASE = BASE

// Intentionally client-side — ClawAudit runs on localhost only.
// NEXT_PUBLIC_* vars are inlined into the client JS bundle at build time.
// If this tool is ever deployed remotely, move auth to a server-side proxy / API route.
export const API_TOKEN = process.env.NEXT_PUBLIC_API_TOKEN ?? ""

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  }
  if (API_TOKEN) {
    headers["Authorization"] = `Bearer ${API_TOKEN}`
  }
  const res = await fetch(`${BASE}${path}`, {
    ...opts,
    // Built-in headers (including Authorization) spread last so callers cannot override auth.
    headers: { ...((opts?.headers as Record<string, string>) ?? {}), ...headers },
  })
  if (!res.ok) {
    let message: string
    try {
      const body = await res.json()
      message = body.detail ?? body.message ?? `${res.status} ${res.statusText}`
    } catch {
      message = `API ${res.status}: ${await res.text().catch(() => res.statusText)}`
    }
    throw new Error(message)
  }
  return res.json()
}

// ── Dashboard ──────────────────────────────────────────────
export interface DashboardStats {
  overall_score: number
  total_skills: number
  critical_findings: number
  risk_distribution: {
    Critical: number
    High: number
    Medium: number
    Low: number
  }
  recent_scans: ScanRun[]
}

export interface ScanRun {
  id: string
  status: "idle" | "running" | "stopping" | "completed" | "failed"
  started_at: string
  completed_at: string | null
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  skills_scanned: number
  triggered_by: string
  error_message: string | null
}

export interface Skill {
  id: string
  scan_id: string
  name: string
  source: string
  path: string
  shell_access: boolean
  outbound_domains: string[]
  injection_risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  trust_score: "TRUSTED" | "CAUTION" | "UNTRUSTED" | "QUARANTINE"
  risk_score: number
  risk_level: string
  detected_at: string
  quarantined?: boolean
  quarantined_at?: string | null
  quarantine_reason?: string | null
}

export interface Finding {
  id: string
  scan_id: string
  check_id: string
  domain: string
  title: string
  description: string
  severity: string
  result: string
  evidence: string
  location: string
  remediation: string
  detected_at: string | null
  skill_name: string | null
}

export interface FindingsParams {
  severity?: string
  domain?: string
  scan_id?: string
  limit?: number
  offset?: number
}

export const getDashboard = () => req<DashboardStats>("/dashboard")
export const getScans     = () => req<ScanRun[]>("/scans")
export const startScan    = () => req<ScanRun>("/scans", { method: "POST", body: JSON.stringify({}) })
export const stopScan     = (id: string) => req<ScanRun>(`/scans/${id}/stop`, { method: "DELETE" })
export const getScan      = (id: string) => req<ScanRun>(`/scans/${id}`)
export const getSkills    = () => req<Skill[]>("/skills")
export const getSkill     = (name: string) => req<Skill>(`/skills/${name}`)
export const getFindings  = (params: FindingsParams = {}) => {
  const qs = new URLSearchParams(
    Object.entries(params)
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => [k, String(v)])
  ).toString()
  return req<Finding[]>(`/findings${qs ? "?" + qs : ""}`)
}

// ── Lifecycle ─────────────────────────────────────────────
export interface LifecycleSkill {
  name: string
  path: string
  source: string
  version: string
  enabled: boolean
  installed_at: string
  risk_level: string
}

export interface SkillHealth {
  name: string
  findings: Array<{ check_id: string; title: string; severity: string; result: string; location: string }>
  risk_level: string
}

export const getLifecycleSkills = () => req<LifecycleSkill[]>("/lifecycle")
export const installSkill         = (source: string, path?: string, url?: string) =>
  req<LifecycleSkill>("/lifecycle/install", { method: "POST", body: JSON.stringify({ source, path, url }) })
export const installSkillFromUrl  = (url: string) => installSkill("url", undefined, url)
export const installSkillFromFile = (path: string) => installSkill("file", path)
export const enableSkill          = (name: string) => req<{ name: string; enabled: boolean }>(`/lifecycle/${name}/enable`, { method: "POST" })
export const disableSkill         = (name: string) => req<{ name: string; enabled: boolean }>(`/lifecycle/${name}/disable`, { method: "POST" })
export const uninstallSkill       = (name: string) => req<{ name: string; trash_path: string }>(`/lifecycle/${name}`, { method: "DELETE" })
export const getSkillHealth       = (name: string) => req<SkillHealth>(`/lifecycle/${name}/health`)

// ── Hooks ────────────────────────────────────────────────
export interface ToolEvent {
  id: string
  session_id: string
  skill_name: string | null
  tool_name: string
  params_summary: string
  timestamp: string
  duration_ms: number | null
  outcome: string
  alert_triggered: boolean
  alert_reasons: string[]
}

export interface HookStats {
  total_events: number
  total_alerts: number
  events_by_tool: Record<string, number>
  events_by_skill: Record<string, number>
}

export const getHookEvents = (params: {
  limit?: number
  alerts_only?: boolean
  session_id?: string
  skill_name?: string
} = {}) => {
  const qs = new URLSearchParams()
  if (params.limit) qs.set("limit", String(params.limit))
  if (params.alerts_only) qs.set("alerts_only", "true")
  if (params.session_id) qs.set("session_id", params.session_id)
  if (params.skill_name) qs.set("skill_name", params.skill_name)
  const q = qs.toString()
  return req<ToolEvent[]>(`/hooks/events${q ? "?" + q : ""}`)
}

export const getHookStats = () => req<HookStats>("/hooks/stats")

// ── Remediation ──────────────────────────────────────────
export interface Proposal {
  proposal_id: string
  finding_id: string
  check_id: string
  skill_name: string
  skill_path: string
  description: string
  action_type: string
  diff_preview: string
  impact: string[]
  reversible: boolean
  status: string
  severity: string
}

export interface HistoryItem {
  id: string
  proposal_id: string
  skill_name: string
  check_id: string
  action_type: string
  status: string
  description: string
  snapshot_path: string | null
  applied_at: string
  error: string | null
}

export const getRemediationProposals = () => req<Proposal[]>("/remediation/proposals")
export const getRemediationHistory   = () => req<HistoryItem[]>("/remediation/history")
export const applyRemediation        = (proposal: Proposal) =>
  req<unknown>("/remediation/apply", { method: "POST", body: JSON.stringify(proposal) })

// ── Policies ─────────────────────────────────────────────
export interface Policy {
  id: string
  name: string
  domain: string
  check: string
  condition: string
  value: string
  severity: string
  action: string
  enabled: boolean
  builtin: boolean
  description: string | null
  priority: number
  tags: string | null
  violation_count: number
  last_triggered_at: string | null
  created_at: string | null
  updated_at: string | null
}

export interface PolicyCreate {
  name: string
  domain: string
  check: string
  condition: string
  value: string
  severity: string
  action: string
  enabled?: boolean
  description?: string | null
  priority?: number
  tags?: string[]
  builtin?: boolean
}

export interface PolicyStats {
  active_count: number
  violations_today: number
  blocked_today: number
  alerted_today: number
  quarantined_skills: number
}

export const getPolicies       = () => req<Policy[]>("/policies")
export const createPolicy      = (body: PolicyCreate) =>
  req<Policy>("/policies", { method: "POST", body: JSON.stringify(body) })
export const updatePolicy      = (id: string, body: Partial<PolicyCreate>) =>
  req<Policy>(`/policies/${id}`, { method: "PUT", body: JSON.stringify(body) })
export const deletePolicy      = (id: string) => req<void>(`/policies/${id}`, { method: "DELETE" })
export const togglePolicy      = (id: string, enabled: boolean) => updatePolicy(id, { enabled })
export const getPolicyStats    = () => req<PolicyStats>("/policies/stats")
export const getViolations     = () => req<Finding[]>("/findings?domain=policy&limit=50")
export const unquarantineSkill = (skillId: string) =>
  req<unknown>(`/skills/${skillId}/unquarantine`, { method: "POST" })
