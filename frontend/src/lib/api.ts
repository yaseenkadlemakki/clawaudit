const BASE = "http://localhost:18790/api/v1"

async function req<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  })
  if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
  return res.json()
}

// ── Dashboard ──────────────────────────────────────────────
export interface DashboardStats {
  security_score: number
  total_findings: number
  critical: number
  high: number
  medium: number
  low: number
  total_scans: number
  last_scan_at: string | null
}

export interface ScanRun {
  id: string
  status: "pending" | "running" | "complete" | "failed" | "stopped"
  started_at: string
  finished_at: string | null
  findings_count: number
  score: number | null
}

export interface Skill {
  id: string
  name: string
  description: string
  risk_score: number
  permissions: string[]
  capabilities: string[]
  policy_violations: number
  location: string
}

export interface Finding {
  id: string
  title: string
  description: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  policy: string
  skill_id: string | null
  skill_name: string | null
  scan_id: string
  created_at: string
  remediation: string | null
}

export interface FindingsParams {
  severity?: string
  policy?: string
  skill?: string
  scan_id?: string
  q?: string
  limit?: number
  offset?: number
}

export const getDashboard = () => req<DashboardStats>("/dashboard")
export const getScans     = () => req<ScanRun[]>("/scans")
export const startScan    = () => req<ScanRun>("/scans", { method: "POST", body: JSON.stringify({}) })
export const stopScan     = (id: string) => req<void>(`/scans/${id}`, { method: "DELETE" })
export const getScan      = (id: string) => req<ScanRun>(`/scans/${id}`)
export const getSkills    = () => req<Skill[]>("/skills")
export const getSkill     = (id: string) => req<Skill>(`/skills/${id}`)
export const getFindings  = (params: FindingsParams = {}) => {
  const qs = new URLSearchParams(
    Object.entries(params)
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => [k, String(v)])
  ).toString()
  return req<Finding[]>(`/findings${qs ? "?" + qs : ""}`)
}
