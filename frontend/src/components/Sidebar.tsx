"use client"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { LayoutDashboard, Play, Puzzle, Search, Shield } from "lucide-react"
import { cn } from "@/lib/utils"

const nav = [
  { href: "/dashboard", label: "Dashboard",        icon: LayoutDashboard },
  { href: "/audit",     label: "Full Audit",        icon: Play            },
  { href: "/skills",    label: "Skill Explorer",    icon: Puzzle          },
  { href: "/findings",  label: "Findings Explorer", icon: Search          },
]

export function Sidebar() {
  const path = usePathname()
  return (
    <aside className="w-56 shrink-0 border-r border-border bg-card flex flex-col h-screen sticky top-0">
      <div className="flex items-center gap-2 px-4 py-5 border-b border-border">
        <Shield className="text-primary" size={20} />
        <span className="font-bold text-sm tracking-widest text-foreground">CLAWAUDIT</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors",
              path.startsWith(href)
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-secondary hover:text-foreground"
            )}
          >
            <Icon size={15} />
            {label}
          </Link>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-border text-xs text-muted-foreground">
        Phase 2 UI · v0.1
      </div>
    </aside>
  )
}
