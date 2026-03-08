"use client"

import { useEffect, useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { Shield, AlertTriangle, CheckCircle, RotateCcw, Eye, Zap, Clock } from "lucide-react"
import { API_BASE, API_TOKEN } from "@/lib/api"

interface Proposal {
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
}

interface HistoryItem {
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

const SEVERITY_COLORS: Record<string, string> = {
  "ADV-001": "text-orange-400 bg-orange-400/10 border-orange-400/30",
  "ADV-005": "text-red-400 bg-red-400/10 border-red-400/30",
  "PERM-001": "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
}

function ProposalCard({
  proposal,
  onApply,
  applying,
}: {
  proposal: Proposal
  onApply: (p: Proposal) => void
  applying: boolean
}) {
  const [showDiff, setShowDiff] = useState(false)
  const colorClass = SEVERITY_COLORS[proposal.check_id] ?? "text-blue-400 bg-blue-400/10 border-blue-400/30"

  return (
    <div className="border border-border rounded-lg p-4 space-y-3 bg-card">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs font-mono px-2 py-0.5 rounded border ${colorClass}`}>
            {proposal.check_id}
          </span>
          <span className="text-sm font-medium">{proposal.skill_name}</span>
          {proposal.reversible && (
            <span className="text-xs text-muted-foreground flex items-center gap-1">
              <RotateCcw className="h-3 w-3" /> reversible
            </span>
          )}
        </div>
        <button
          onClick={() => onApply(proposal)}
          disabled={applying}
          className="shrink-0 px-3 py-1.5 text-xs rounded-md bg-primary text-primary-foreground hover:bg-primary/80 disabled:opacity-50 transition-colors flex items-center gap-1"
        >
          <Zap className="h-3 w-3" />
          {applying ? "Applying…" : "Apply Fix"}
        </button>
      </div>

      <p className="text-sm text-muted-foreground">{proposal.description}</p>

      {proposal.impact.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Impact</p>
          <ul className="space-y-1">
            {proposal.impact.map((item, i) => (
              <li key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                <AlertTriangle className="h-3 w-3 text-yellow-500 mt-0.5 shrink-0" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {proposal.diff_preview && (
        <button
          onClick={() => setShowDiff(!showDiff)}
          className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
        >
          <Eye className="h-3 w-3" />
          {showDiff ? "Hide diff" : "Show diff"}
        </button>
      )}

      {showDiff && proposal.diff_preview && (
        <pre className="text-xs bg-muted rounded p-3 overflow-x-auto max-h-48 font-mono leading-relaxed whitespace-pre">
          {proposal.diff_preview}
        </pre>
      )}
    </div>
  )
}

export default function RemediationPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<"proposals" | "history">("proposals")
  const [confirmProposal, setConfirmProposal] = useState<Proposal | null>(null)
  const [applyingId, setApplyingId] = useState<string | null>(null)

  const { data: proposals = [], isLoading: loadingProposals, error: proposalsError } = useQuery<Proposal[]>({
    queryKey: ["remediation-proposals"],
    queryFn: async () => {
      const headers: Record<string, string> = { "Content-Type": "application/json" }
      if (API_TOKEN) headers["Authorization"] = `Bearer ${API_TOKEN}`
      const r = await fetch(`${API_BASE}/remediation/proposals`, { headers })
      if (!r.ok) throw new Error(`Failed to load proposals (${r.status})`)
      return r.json()
    },
  })

  const { data: history = [], isLoading: loadingHistory, error: historyError } = useQuery<HistoryItem[]>({
    queryKey: ["remediation-history"],
    queryFn: async () => {
      const headers: Record<string, string> = { "Content-Type": "application/json" }
      if (API_TOKEN) headers["Authorization"] = `Bearer ${API_TOKEN}`
      const r = await fetch(`${API_BASE}/remediation/history`, { headers })
      if (!r.ok) throw new Error(`Failed to load history (${r.status})`)
      return r.json()
    },
    enabled: activeTab === "history",
  })

  // Dismiss confirmation modal on Escape key
  useEffect(() => {
    if (!confirmProposal) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setConfirmProposal(null)
    }
    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [confirmProposal])

  const applyMutation = useMutation({
    mutationFn: async (proposal: Proposal) => {
      const headers: Record<string, string> = { "Content-Type": "application/json" }
      if (API_TOKEN) headers["Authorization"] = `Bearer ${API_TOKEN}`
      const res = await fetch(`${API_BASE}/remediation/apply`, {
        method: "POST",
        headers,
        body: JSON.stringify(proposal),
      })
      if (!res.ok) throw new Error(await res.text())
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation-proposals"] })
      queryClient.invalidateQueries({ queryKey: ["remediation-history"] })
      setApplyingId(null)
      setConfirmProposal(null)
    },
    onError: () => setApplyingId(null),
  })

  const handleApply = (proposal: Proposal) => {
    setConfirmProposal(proposal)
  }

  const confirmApply = () => {
    if (!confirmProposal) return
    setApplyingId(confirmProposal.proposal_id)
    applyMutation.mutate(confirmProposal)
  }

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <Shield className="h-6 w-6 text-primary" />
        <div>
          <h1 className="text-xl font-semibold">Remediation</h1>
          <p className="text-sm text-muted-foreground">
            Review and apply automated fixes for security findings
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(["proposals", "history"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm capitalize transition-colors border-b-2 -mb-px ${
              activeTab === tab
                ? "border-primary text-foreground font-medium"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {tab}
            {tab === "proposals" && proposals.length > 0 && (
              <span className="ml-2 text-xs bg-primary/20 text-primary px-1.5 py-0.5 rounded-full">
                {proposals.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Proposals tab */}
      {activeTab === "proposals" && (
        <div className="space-y-4">
          {loadingProposals && (
            <p className="text-sm text-muted-foreground">Scanning for remediations…</p>
          )}
          {proposalsError && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-3 text-sm">
              Failed to load proposals. Is the backend running?
            </div>
          )}
          {!loadingProposals && !proposalsError && proposals.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
              <CheckCircle className="h-10 w-10 text-green-500" />
              <p className="text-sm font-medium">No remediations needed</p>
              <p className="text-xs text-muted-foreground">
                All scanned skills are within acceptable security bounds.
              </p>
            </div>
          )}
          {proposals.map((p) => (
            <ProposalCard
              key={p.proposal_id}
              proposal={p}
              onApply={handleApply}
              applying={applyingId === p.proposal_id}
            />
          ))}
        </div>
      )}

      {/* History tab */}
      {activeTab === "history" && (
        <div className="space-y-3">
          {loadingHistory && <p className="text-sm text-muted-foreground">Loading history…</p>}
          {historyError && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg p-3 text-sm">
              Failed to load history. Is the backend running?
            </div>
          )}
          {!loadingHistory && !historyError && history.length === 0 && (
            <p className="text-sm text-muted-foreground">No remediations applied yet.</p>
          )}
          {history.map((item) => (
            <div key={item.id} className="border border-border rounded-lg p-3 space-y-1">
              <div className="flex items-center gap-2">
                {item.status === "applied" ? (
                  <CheckCircle className="h-4 w-4 text-green-500" />
                ) : item.status === "rolled_back" ? (
                  <RotateCcw className="h-4 w-4 text-blue-500" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                )}
                <span className="text-sm font-medium">{item.skill_name}</span>
                <span className="text-xs text-muted-foreground font-mono">{item.check_id}</span>
              </div>
              <p className="text-xs text-muted-foreground pl-6">{item.description}</p>
              <div className="flex items-center gap-2 pl-6">
                <Clock className="h-3 w-3 text-muted-foreground" />
                <span className="text-xs text-muted-foreground">
                  {new Date(item.applied_at).toLocaleString()}
                </span>
                {item.snapshot_path && (
                  <span className="text-xs text-muted-foreground">
                    · snapshot: {item.snapshot_path.split("/").pop()}
                  </span>
                )}
              </div>
              {item.error && (
                <p className="text-xs text-red-400 pl-6">Error: {item.error}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Confirmation dialog */}
      {confirmProposal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
          <div className="bg-card border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h2 id="confirm-title" className="text-base font-semibold flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-yellow-500" />
              Confirm Remediation
            </h2>
            <p className="text-sm text-muted-foreground">{confirmProposal.description}</p>
            <div className="space-y-1">
              {confirmProposal.impact.map((item, i) => (
                <p key={i} className="text-xs text-muted-foreground">• {item}</p>
              ))}
            </div>
            {confirmProposal.reversible && (
              <p className="text-xs text-green-400 flex items-center gap-1">
                <RotateCcw className="h-3 w-3" /> A snapshot will be taken before applying.
              </p>
            )}
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setConfirmProposal(null)}
                className="px-3 py-1.5 text-sm rounded-md border border-border hover:bg-muted transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={confirmApply}
                disabled={applyMutation.isPending}
                className="px-3 py-1.5 text-sm rounded-md bg-primary text-primary-foreground hover:bg-primary/80 disabled:opacity-50 transition-colors"
              >
                {applyMutation.isPending ? "Applying…" : "Apply Fix"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
