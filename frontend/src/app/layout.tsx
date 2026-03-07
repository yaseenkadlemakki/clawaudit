import type { Metadata } from "next"
import "./globals.css"
import { Sidebar } from "@/components/Sidebar"
import { Providers } from "./providers"

export const metadata: Metadata = {
  title: "ClawAudit",
  description: "Security audit for OpenClaw agents",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="flex min-h-screen bg-background">
        <Providers>
          <Sidebar />
          <main className="flex-1 overflow-auto">{children}</main>
        </Providers>
      </body>
    </html>
  )
}
