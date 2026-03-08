"use client"
import { useState, useMemo, useCallback } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import Link from "next/link"
import { getSkills, getLifecycleSkills, enableSkill, disableSkill, uninstallSkill, installSkillFromUrl, installSkillFromFile, type LifecycleSkill } from "@/lib/api"
import { riskColor, cn } from "@/lib/utils"
import { ChevronRight, Search, Puzzle, Shell, Globe, AlertTriangle, Power, PowerOff, Trash2, Lock, Download, X, Upload, Link2 } from "lucide-react"

function StatusBadge({ enabled }: { enabled: boolean }) {
  return enabled
    ? <span className="text-xs bg-green-500/10 text-green-400 border border-green-500/20 px-1.5 py-0.5 rounded">enabled</span>
    : <span className="text-xs bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 px-1.5 py-0.5 rounded">disabled</span>
}

function InstallModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [tab, setTab] = useState<"url" | "file">("url")
  const [url, setUrl] = useState("")
  const [error, setError] = useState("")
  const qc = useQueryClient()

  const installUrl = useMutation({
    mutationFn: (u: string) => installSkillFromUrl(u),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["lifecycle-skills"] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  const installFile = useMutation({
    mutationFn: (path: string) => installSkillFromFile(path),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["lifecycle-skills"] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  if (!open) return null
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-bold">Install Skill</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X size={16} /></button>
        </div>
        <div className="flex gap-2 mb-4">
          <button onClick={() => { setTab("url"); setError("") }} className={cn("text-xs px-3 py-1.5 rounded border", tab === "url" ? "bg-primary/10 border-primary/30 text-primary" : "border-border text-muted-foreground")}>
            <Link2 size={12} className="inline mr-1" />From URL
          </button>
          <button onClick={() => { setTab("file"); setError("") }} className={cn("text-xs px-3 py-1.5 rounded border", tab === "file" ? "bg-primary/10 border-primary/30 text-primary" : "border-border text-muted-foreground")}>
            <Upload size={12} className="inline mr-1" />Upload .skill
          </button>
        </div>
        {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded p-2 text-xs mb-3">{error}</div>}
        {tab === "url" ? (
          <form onSubmit={e => { e.preventDefault(); installUrl.mutate(url) }} className="space-y-3">
            <input className="w-full bg-background border border-border rounded px-3 py-2 text-sm" placeholder="https://clawhub.dev/skills/example.skill" value={url} onChange={e => setUrl(e.target.value)} />
            <button type="submit" disabled={installUrl.isPending || !url} className="w-full bg-primary text-primary-foreground rounded px-3 py-2 text-sm disabled:opacity-50">
              {installUrl.isPending ? "Installing..." : "Install"}
            </button>
          </form>
        ) : (
          <form onSubmit={e => { e.preventDefault(); const input = (e.target as HTMLFormElement).elements.namedItem("filepath") as HTMLInputElement; installFile.mutate(input.value) }} className="space-y-3">
            <input name="filepath" className="w-full bg-background border border-border rounded px-3 py-2 text-sm" placeholder="/path/to/skill.skill" />
            <button type="submit" disabled={installFile.isPending} className="w-full bg-primary text-primary-foreground rounded px-3 py-2 text-sm disabled:opacity-50">
              {installFile.isPending ? "Installing..." : "Install from file"}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}

function UninstallModal({ name, open, onConfirm, onClose, isPending }: { name: string; open: boolean; onConfirm: () => void; onClose: () => void; isPending: boolean }) {
  if (!open) return null
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg p-6 w-full max-w-sm" onClick={e => e.stopPropagation()}>
        <h2 className="font-bold mb-2">Uninstall {name}?</h2>
        <p className="text-sm text-muted-foreground mb-4">This will move the skill to trash. You can recover it later.</p>
        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="px-3 py-1.5 text-sm border border-border rounded hover:bg-muted">Cancel</button>
          <button onClick={onConfirm} disabled={isPending} className="px-3 py-1.5 text-sm bg-red-500 text-white rounded hover:bg-red-600 disabled:opacity-50">
            {isPending ? "Removing..." : "Uninstall"}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function SkillsPage() {
  const { data: skills, isLoading: loadingScanned, error: scanError } = useQuery({ queryKey: ["skills"], queryFn: getSkills })
  const { data: lifecycleSkills, isLoading: loadingLifecycle } = useQuery({ queryKey: ["lifecycle-skills"], queryFn: getLifecycleSkills })
  const [q, setQ] = useState("")
  const [installOpen, setInstallOpen] = useState(false)
  const [uninstallTarget, setUninstallTarget] = useState<string | null>(null)
  const qc = useQueryClient()

  const toggleMut = useMutation({
    mutationFn: ({ name, enable }: { name: string; enable: boolean }) => enable ? enableSkill(name) : disableSkill(name),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["lifecycle-skills"] }),
  })

  const uninstallMut = useMutation({
    mutationFn: (name: string) => uninstallSkill(name),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["lifecycle-skills"] }); setUninstallTarget(null) },
  })

  // Merge scanned skills with lifecycle data
  const merged = useMemo(() => {
    const lcMap = new Map((lifecycleSkills ?? []).map(s => [s.name, s]))
    const scanned = (skills ?? []).map(s => ({ ...s, lc: lcMap.get(s.name) }))
    // Add lifecycle-only skills not in scanned set
    const scannedNames = new Set(scanned.map(s => s.name))
    const lcOnly = (lifecycleSkills ?? []).filter(s => !scannedNames.has(s.name)).map(s => ({
      id: s.name, scan_id: "", name: s.name, source: s.source, path: s.path,
      shell_access: false, outbound_domains: [] as string[], injection_risk: "LOW" as const,
      trust_score: "TRUSTED" as const, risk_score: 0, risk_level: s.risk_level,
      detected_at: s.installed_at, lc: s,
    }))
    return [...scanned, ...lcOnly]
  }, [skills, lifecycleSkills])

  const filtered = useMemo(() => merged.filter(s =>
    s.name.toLowerCase().includes(q.toLowerCase()) ||
    s.path.toLowerCase().includes(q.toLowerCase())
  ), [merged, q])

  const isLoading = loadingScanned || loadingLifecycle

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold tracking-wide">Skill Explorer</h1>
        <div className="flex items-center gap-3">
          <span className="text-xs text-muted-foreground">
            {filtered.length} skill{filtered.length !== 1 ? "s" : ""}
          </span>
          <button onClick={() => setInstallOpen(true)} className="flex items-center gap-1.5 text-xs bg-primary/10 text-primary border border-primary/30 px-3 py-1.5 rounded hover:bg-primary/20 transition-colors">
            <Download size={12} /> Install Skill
          </button>
        </div>
      </div>

      {scanError && (
        <div className="rounded border border-red-500 bg-red-950/30 p-4 text-red-400 text-sm">
          Failed to load skills: {(scanError as Error).message}
        </div>
      )}

      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
        <input
          className="w-full bg-card border border-border rounded-md pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
          placeholder="Search skills..."
          value={q}
          onChange={e => setQ(e.target.value)}
        />
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[1, 2, 3].map(i => (
            <div key={i} className="bg-card border border-border rounded-lg p-4 animate-pulse">
              <div className="h-4 bg-muted rounded w-1/2 mb-3" />
              <div className="h-3 bg-muted rounded w-3/4 mb-3" />
              <div className="h-3 bg-muted rounded w-1/3" />
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.map(skill => {
            const lc = skill.lc as LifecycleSkill | undefined
            const enabled = lc?.enabled ?? true
            const isProtected = lc ? lc.source === "system" : false
            return (
              <div key={skill.id ?? skill.name} className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors group relative">
                <Link href={`/skills/${skill.id}`} className="block">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Puzzle size={14} className="text-primary shrink-0 mt-0.5" />
                      <span className="font-medium text-sm">{skill.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {lc && <StatusBadge enabled={enabled} />}
                      <span className={cn("text-xs font-bold", riskColor(skill.risk_score))}>
                        {skill.risk_level}
                      </span>
                      <ChevronRight size={14} className="text-muted-foreground group-hover:text-primary transition-colors shrink-0" />
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground line-clamp-1 mb-3 font-mono">
                    {skill.path.replace(/.*\/skills\//, ".../skills/")}
                  </p>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">v{lc?.version ?? "?"}</span>
                      <span className="text-xs text-muted-foreground">{lc?.source ?? skill.source}</span>
                    </div>
                    <div className="flex gap-1 flex-wrap justify-end">
                      {skill.shell_access && (
                        <span className="flex items-center gap-1 text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded">
                          <Shell size={10} /> shell
                        </span>
                      )}
                      {skill.outbound_domains.length > 0 && (
                        <span className="flex items-center gap-1 text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded">
                          <Globe size={10} /> network
                        </span>
                      )}
                      {(skill.injection_risk === "HIGH" || skill.injection_risk === "CRITICAL") && (
                        <span className="flex items-center gap-1 text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded">
                          <AlertTriangle size={10} /> injection
                        </span>
                      )}
                    </div>
                  </div>
                </Link>

                {/* Lifecycle action buttons */}
                {lc && (
                  <div className="flex gap-1.5 mt-3 pt-3 border-t border-border">
                    {isProtected ? (
                      <span className="flex items-center gap-1 text-xs text-muted-foreground"><Lock size={10} /> Protected</span>
                    ) : (
                      <>
                        <button
                          onClick={e => { e.preventDefault(); toggleMut.mutate({ name: skill.name, enable: !enabled }) }}
                          disabled={toggleMut.isPending}
                          className={cn("flex items-center gap-1 text-xs px-2 py-1 rounded border transition-colors", enabled ? "border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10" : "border-green-500/30 text-green-400 hover:bg-green-500/10")}
                        >
                          {enabled ? <><PowerOff size={10} /> Disable</> : <><Power size={10} /> Enable</>}
                        </button>
                        <button
                          onClick={e => { e.preventDefault(); setUninstallTarget(skill.name) }}
                          className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <Trash2 size={10} /> Uninstall
                        </button>
                      </>
                    )}
                  </div>
                )}
              </div>
            )
          })}
          {filtered.length === 0 && (
            <p className="col-span-3 text-muted-foreground text-sm py-8 text-center">
              {merged.length === 0 ? "No skills found — run a scan first." : "No skills match your search."}
            </p>
          )}
        </div>
      )}

      <InstallModal open={installOpen} onClose={() => setInstallOpen(false)} />
      <UninstallModal
        name={uninstallTarget ?? ""}
        open={!!uninstallTarget}
        onConfirm={() => uninstallTarget && uninstallMut.mutate(uninstallTarget)}
        onClose={() => setUninstallTarget(null)}
        isPending={uninstallMut.isPending}
      />
    </div>
  )
}
