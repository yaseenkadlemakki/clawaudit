"use client"
import { InvestigationPanel } from "@/components/InvestigationPanel"

export default function ChatPage() {
  return (
    <div className="p-6">
      <InvestigationPanel defaultExpanded={true} />
    </div>
  )
}
