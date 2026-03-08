const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:18790/api/v1"
export const API_BASE = BASE

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
  status: "pending" | "running" | "complete" | "failed" | "stopped"
  started_at: string
  finished_at: string | null
  findings_count?: number
  total_findings?: number
  skills_scanned?: number
  score: number | null
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
