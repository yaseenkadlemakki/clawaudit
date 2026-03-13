import { defineConfig, devices } from "@playwright/test"
import { readFileSync } from "fs"
import { resolve } from "path"

// Load .env.local so NEXT_PUBLIC_* vars are available in Playwright worker process,
// matching what is baked into the Next.js bundle at build time.
try {
  const envFile = resolve(__dirname, ".env.local")
  const lines = readFileSync(envFile, "utf-8").split("\n")
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    const eqIdx = trimmed.indexOf("=")
    if (eqIdx === -1) continue
    const key = trimmed.slice(0, eqIdx).trim()
    const val = trimmed.slice(eqIdx + 1).trim()
    if (!(key in process.env)) process.env[key] = val
  }
} catch {
  // .env.local not present — no-op
}

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 1,
  use: {
    baseURL: "http://localhost:3002",
    screenshot: "only-on-failure",
    video: "off",
    extraHTTPHeaders: {},
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: undefined,
})
