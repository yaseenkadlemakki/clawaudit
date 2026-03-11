"use client"
import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { Plus, ShieldCheck, ShieldAlert, AlertTriangle, ShieldX, Activity } from "lucide-react"
import {
  getPolicies,
  getPolicyStats,
  createPolicy,
  updatePolicy,
  deletePolicy,
  togglePolicy,
  type Policy,
  type PolicyCreate,
} from "@/lib/api"
import { PolicyTable } from "./PolicyTable"
import { PolicyFormModal } from "./PolicyFormModal"
import { ViolationsFeed } from "./ViolationsFeed"

type Tab = "policies" | "violations"

export default function PoliciesPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>("policies")
  const [showModal, setShowModal] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const { data: policies = [], isLoading, error } = useQuery({
    queryKey: ["policies"],
    queryFn: getPolicies,
    refetchInterval: 30_000,
  })

  const { data: stats } = useQuery({
    queryKey: ["policy-stats"],
    queryFn: getPolicyStats,
    refetchInterval: 30_000,
  })

  const createMut = useMutation({
    mutationFn: createPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<PolicyCreate> }) =>
      updatePolicy(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }),
  })

  const deleteMut = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policies"] })
      setDeleteError(null)
    },
    onError: (err: Error) => {
      setDeleteError(err.message)
    },
  })

  async function handleSave(data: PolicyCreate) {
    if (editingPolicy) {
      await updateMut.mutateAsync({ id: editingPolicy.id, data })
    } else {
      await createMut.mutateAsync(data)
    }
  }

  function handleEdit(policy: Policy) {
    setEditingPolicy(policy)
    setShowModal(true)
  }

  function handleDelete(policy: Policy) {
    if (policy.builtin) {
      setDeleteError("Cannot delete a built-in policy")
      return
    }
    if (!confirm(`Delete policy "${policy.name}"?`)) return
    deleteMut.mutate(policy.id)
  }

  function handleToggle(policy: Policy, enabled: boolean) {
    updateMut.mutate({ id: policy.id, data: { enabled } })
  }

  const builtinPolicies = policies.filter((p) => p.builtin)
  const customPolicies = policies.filter((p) => !p.builtin)

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="text-primary" size={22} />
          <h1 className="text-xl font-bold tracking-wide text-foreground">Policy Engine</h1>
        </div>
        <button
          onClick={() => { setEditingPolicy(null); setShowModal(true) }}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Plus size={14} />
          New Policy
        </button>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[
          { label: "Active Policies",      value: stats?.active_count        ?? "…", icon: <ShieldCheck size={14} className="text-green-400" /> },
          { label: "Violations Today",     value: stats?.violations_today     ?? "…", icon: <Activity size={14} className="text-blue-400" /> },
          { label: "Blocked Today",        value: stats?.blocked_today        ?? "…", icon: <ShieldX size={14} className="text-red-400" /> },
          { label: "Alerted Today",        value: stats?.alerted_today        ?? "…", icon: <AlertTriangle size={14} className="text-orange-400" /> },
          { label: "Quarantined Skills",   value: stats?.quarantined_skills   ?? "…", icon: <ShieldAlert size={14} className="text-purple-400" /> },
        ].map(({ label, value, icon }) => (
          <div key={label} className="bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1.5">{icon} {label}</div>
            <p className="text-xl font-bold text-foreground">{value}</p>
          </div>
        ))}
      </div>

      {/* Error banners */}
      {(error || deleteError) && (
        <div className="bg-red-950/30 border border-red-700/50 text-red-400 rounded p-3 text-sm">
          {deleteError ?? (error as Error)?.message ?? "Error loading policies"}
          {deleteError && (
            <button onClick={() => setDeleteError(null)} className="ml-2 underline text-xs">dismiss</button>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-border">
        {(["policies", "violations"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 transition-colors ${
              tab === t
                ? "border-primary text-primary"
                : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "policies" ? "All Policies" : "Violations Feed"}
          </button>
        ))}
      </div>

      {tab === "policies" && (
        <>
          {isLoading ? (
            <div className="py-8 text-center text-muted-foreground text-sm">Loading policies…</div>
          ) : (
            <>
              {/* Built-in policies */}
              {builtinPolicies.length > 0 && (
                <div className="bg-card border border-border rounded-lg p-5">
                  <h2 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
                    <ShieldCheck size={14} className="text-primary" />
                    Built-in Policies
                    <span className="text-xs bg-secondary px-1.5 py-0.5 rounded">{builtinPolicies.length}</span>
                  </h2>
                  <PolicyTable
                    policies={builtinPolicies}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                    onToggle={handleToggle}
                  />
                </div>
              )}

              {/* Custom policies */}
              <div className="bg-card border border-border rounded-lg p-5">
                <h2 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
                  Custom Policies
                  <span className="text-xs bg-secondary px-1.5 py-0.5 rounded">{customPolicies.length}</span>
                </h2>
                <PolicyTable
                  policies={customPolicies}
                  onEdit={handleEdit}
                  onDelete={handleDelete}
                  onToggle={handleToggle}
                />
              </div>
            </>
          )}
        </>
      )}

      {tab === "violations" && (
        <div className="bg-card border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
            <AlertTriangle size={14} className="text-orange-400" />
            Recent Policy Violations
          </h2>
          <ViolationsFeed />
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <PolicyFormModal
          policy={editingPolicy}
          onSave={handleSave}
          onClose={() => { setShowModal(false); setEditingPolicy(null) }}
        />
      )}
    </div>
  )
}
