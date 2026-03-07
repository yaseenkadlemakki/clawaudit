import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

export function riskColor(score: number): string {
  if (score >= 80) return "text-red-400"
  if (score >= 60) return "text-orange-400"
  if (score >= 40) return "text-yellow-400"
  return "text-green-400"
}

export function severityColor(sev: string): string {
  const s = sev.toLowerCase()
  if (s === "critical") return "bg-red-500/20 text-red-400 border-red-500/30"
  if (s === "high")     return "bg-orange-500/20 text-orange-400 border-orange-500/30"
  if (s === "medium")   return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
  if (s === "low")      return "bg-blue-500/20 text-blue-400 border-blue-500/30"
  return "bg-slate-500/20 text-slate-400 border-slate-500/30"
}
