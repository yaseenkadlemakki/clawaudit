import { test, expect, Page } from "@playwright/test"

// ─── Helpers ─────────────────────────────────────────────────────────

/** Collect console errors during a test */
function collectConsoleErrors(page: Page): string[] {
  const errors: string[] = []
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text())
  })
  page.on("pageerror", (err) => errors.push(err.message))
  return errors
}

/** Intercept all API calls and force 401 */
async function mockAllApi401(page: Page) {
  await page.route("**/api/v1/**", (route) =>
    route.fulfill({ status: 401, body: "Unauthorized" })
  )
}

/** Wait for at least one API response (or networkidle as fallback) */
async function waitForApi(page: Page) {
  await page.waitForLoadState("networkidle")
}

// ─── Navigation ──────────────────────────────────────────────────────

test.describe("Navigation", () => {
  test("sidebar links navigate to correct pages", async ({ page }) => {
    await page.goto("/dashboard")
    await page.waitForSelector("text=CLAWAUDIT")

    const links = [
      { label: "Dashboard", path: "/dashboard" },
      { label: "Full Audit", path: "/audit" },
      { label: "Skill Explorer", path: "/skills" },
      { label: "Findings Explorer", path: "/findings" },
      { label: "Remediation", path: "/remediation" },
      { label: "Runtime Events", path: "/hooks" },
    ]

    for (const { label, path } of links) {
      await page.getByRole("link", { name: label }).click()
      await page.waitForURL(`**${path}`)
      expect(page.url()).toContain(path)
    }
  })

  test("CLAWAUDIT branding visible in sidebar", async ({ page }) => {
    await page.goto("/dashboard")
    await expect(page.locator("text=CLAWAUDIT")).toBeVisible()
    await expect(page.locator("text=Phase 8")).toBeVisible()
  })

  test("active page is highlighted in sidebar", async ({ page }) => {
    await page.goto("/dashboard")
    await page.waitForSelector("text=CLAWAUDIT")
    const dashLink = page.getByRole("link", { name: "Dashboard" })
    await expect(dashLink).toHaveClass(/text-primary/)
  })

  test("root / redirects to /dashboard", async ({ page }) => {
    await page.goto("/")
    await page.waitForURL("**/dashboard")
    expect(page.url()).toContain("/dashboard")
  })
})

// ─── Dashboard ───────────────────────────────────────────────────────

test.describe("Dashboard", () => {
  test("page renders with heading and stat cards", async ({ page }) => {
    await page.goto("/dashboard")

    await expect(page.getByRole("heading", { name: /Security Dashboard/i })).toBeVisible()

    // 4 stat cards
    await expect(page.getByText("Total Findings")).toBeVisible()
    await expect(page.getByText("Critical").first()).toBeVisible()
    await expect(page.getByText("High").first()).toBeVisible()
    await expect(page.getByText("Scans Run")).toBeVisible()
  })

  test("Overall Risk Score section renders", async ({ page }) => {
    await page.goto("/dashboard")
    await expect(page.getByText("Overall Risk Score")).toBeVisible({ timeout: 10000 })
  })

  test("risk distribution section renders", async ({ page }) => {
    await page.goto("/dashboard")
    await expect(page.getByText("Risk Distribution")).toBeVisible({ timeout: 10000 })
  })

  test("scan history table renders with headers", async ({ page }) => {
    await page.goto("/dashboard")
    await expect(page.getByText("Scan History")).toBeVisible({ timeout: 5000 })
    const headers = ["ID", "Status", "Started", "Finished", "Skills", "Findings"]
    for (const h of headers) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("stat cards show dash (not zero) on API error", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/dashboard")
    await waitForApi(page)

    // Stat cards should show "—" not "0" when API fails
    const statValues = await page.locator(".text-2xl").allTextContents()
    const allZeros = statValues.every((v) => v.trim() === "0")
    expect(allZeros).toBe(false)
  })
})

// ─── Full Audit ──────────────────────────────────────────────────────

test.describe("Full Audit", () => {
  test("page renders with heading and controls", async ({ page }) => {
    await page.goto("/audit")

    await expect(page.getByRole("heading", { name: /Full Audit/i })).toBeVisible()
    await expect(page.getByRole("button", { name: /Start Scan/i })).toBeVisible()
  })

  test("Start Scan button is clickable and shows response", async ({ page }) => {
    await page.goto("/audit")

    const startBtn = page.getByRole("button", { name: /Start Scan/i })
    await expect(startBtn).toBeEnabled()
    await startBtn.click()

    // After clicking: either scan starts (status shown) or error appears
    await page.waitForLoadState("networkidle")
    const hasStatus = await page.getByText(/running|pending|complete/i).count() > 0
    const hasError = await page.locator('[role="alert"], [class*="error"], [class*="destructive"]').count() > 0
    const hasStopBtn = await page.getByRole("button", { name: /Stop Scan/i }).count() > 0

    expect(hasStatus || hasError || hasStopBtn).toBeTruthy()
  })

  test("Live Log Stream panel renders", async ({ page }) => {
    await page.goto("/audit")
    await expect(page.getByText("Live Log Stream")).toBeVisible({ timeout: 5000 })
  })

  test("Stop Scan button exists", async ({ page }) => {
    await page.goto("/audit")
    await expect(page.getByRole("button", { name: /Stop Scan/i })).toBeVisible()
  })

  test("WebSocket status indicator shows (IDLE/LIVE/CONNECTING/CLOSED)", async ({ page }) => {
    await page.goto("/audit")
    const statusIndicator = page.getByText(/IDLE|LIVE|CONNECTING|CLOSED/)
    await expect(statusIndicator).toBeVisible({ timeout: 5000 })
  })
})

// ─── Skill Explorer ──────────────────────────────────────────────────

test.describe("Skill Explorer", () => {
  test("page heading always visible even on error", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/skills")
    await waitForApi(page)

    // The heading must ALWAYS be visible, even when API fails
    await expect(page.getByRole("heading", { name: /Skill Explorer/i })).toBeVisible()
  })

  test("Install Skill button visible even on error", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/skills")
    await waitForApi(page)

    await expect(page.getByRole("button", { name: /Install Skill/i })).toBeVisible()
  })

  test("shows skills list or error (not blank page)", async ({ page }) => {
    await page.goto("/skills")
    await waitForApi(page)

    const hasSkills = await page.locator('[class*="card"]').count() > 0
    const hasEmpty = await page.getByText(/no skills/i).count() > 0
    const hasError = await page.locator('[role="alert"], [class*="error"], [class*="destructive"]').or(page.getByText(/error|failed/i)).count() > 0
    const hasLoading = await page.locator('[class*="skeleton"], [class*="animate-pulse"]').count() > 0

    expect(hasSkills || hasEmpty || hasError || hasLoading).toBeTruthy()
  })
})

// ─── Skill Detail ────────────────────────────────────────────────────

test.describe("Skill Detail", () => {
  test("navigating to /skills/test-id shows detail or error", async ({ page }) => {
    await page.goto("/skills/test-id")
    await waitForApi(page)

    const hasBackLink = await page.getByText("Back").or(page.locator('[href="/skills"]')).count() > 0
    const hasError = await page.locator('[role="alert"], [class*="error"], [class*="destructive"]').or(page.getByText(/error|failed/i)).count() > 0
    const hasContent = await page.getByText(/risk|trust/i).count() > 0

    expect(hasBackLink || hasError || hasContent).toBeTruthy()
  })
})

// ─── Findings Explorer ───────────────────────────────────────────────

test.describe("Findings Explorer", () => {
  test("page renders with heading and filters", async ({ page }) => {
    await page.goto("/findings")
    await expect(page.getByRole("heading", { name: /Findings Explorer/i })).toBeVisible()
  })

  test("search box renders and accepts input", async ({ page }) => {
    await page.goto("/findings")
    const searchInput = page.locator('input[placeholder*="earch"]').first()
    await expect(searchInput).toBeVisible()
    await searchInput.fill("test-query")
    await expect(searchInput).toHaveValue("test-query")
  })

  test("severity dropdown renders", async ({ page }) => {
    await page.goto("/findings")
    const severityFilter = page.locator("select").first()
    await expect(severityFilter).toBeVisible()
  })

  test("findings table headers render", async ({ page }) => {
    await page.goto("/findings")
    const expectedHeaders = ["Severity", "Title", "Check ID", "Domain"]
    for (const h of expectedHeaders) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("shows error banner on auth failure (not silent zero results)", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/findings")
    await waitForApi(page)

    // Error indicator must be visible
    const errorLocator = page.locator('[role="alert"], [class*="error"], [class*="destructive"]')
      .or(page.getByText(/error|failed|401/i))
    await expect(errorLocator.first()).toBeVisible({ timeout: 5000 })

    // "No findings match" empty state must NOT appear alongside the error
    await expect(page.getByText("No findings match your filters")).not.toBeVisible()
  })
})

// ─── Investigation / Chat ────────────────────────────────────────────

test.describe("Investigation Chat", () => {
  test("page renders with heading and input", async ({ page }) => {
    await page.goto("/chat")

    await expect(page.getByRole("heading", { name: /Security Investigation/i })).toBeVisible()

    const chatInput = page.locator("textarea").last()
    await expect(chatInput).toBeVisible()
  })

  test("suggestion chips visible when no messages", async ({ page }) => {
    await page.goto("/chat")
    await waitForApi(page)

    // Look for suggestion cards in the grid
    const suggestions = page.locator('[class*="grid"] button').or(page.locator('[class*="grid"] [class*="card"]'))
    const count = await suggestions.count()
    expect(count).toBeGreaterThanOrEqual(3)
  })

  test("OpenClaw/BYOLLM toggle visible", async ({ page }) => {
    await page.goto("/chat")
    await expect(page.getByText("OpenClaw").first()).toBeVisible()
    await expect(page.getByText("BYOLLM")).toBeVisible()
  })

  test("clicking suggestion chip populates input or sends message", async ({ page }) => {
    // Mock the chat endpoint so the test doesn't depend on a running backend
    await page.route("**/api/v1/chat", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ answer: "Mock answer." }),
      })
    )

    await page.goto("/chat")
    await waitForApi(page)

    // Suggestion buttons are in a grid inside the InvestigationPanel (expanded by default on /chat)
    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()

    // After clicking a suggestion the question is sent immediately;
    // the user-bubble (bg-primary text-white) or the assistant answer should appear
    await page.waitForLoadState("networkidle")
    const hasBubble = await page.locator('[data-testid="investigation-panel"] .bg-primary').count() > 0
    const hasAnswer  = await page.getByText("Mock answer.").count() > 0

    expect(hasBubble || hasAnswer).toBeTruthy()
  })

  test("typing message and sending shows response or error", async ({ page }) => {
    await page.goto("/chat")
    await waitForApi(page)

    const chatInput = page.locator("textarea").last()
    await chatInput.fill("What are the current security findings?")

    const sendBtn = page.locator('button[type="submit"]').or(page.getByRole("button", { name: /send/i })).first()
    await sendBtn.click()

    // Wait for network activity to settle (LLM may take time)
    await page.waitForLoadState("networkidle", { timeout: 15000 })

    const hasResponse = await page.locator('[class*="message"]').or(page.locator('[class*="border"]')).count() > 1
    const hasError = await page.locator('[role="alert"], [class*="error"], [class*="destructive"]').or(page.getByText(/error|failed/i)).count() > 0

    expect(hasResponse || hasError).toBeTruthy()
  })

  test("BYOLLM toggle shows API key input", async ({ page }) => {
    await page.goto("/chat")
    const byollmBtn = page.getByText("BYOLLM")
    await byollmBtn.click()

    const apiKeyInput = page.locator('input[type="password"]')
    await expect(apiKeyInput).toBeVisible()
  })
})

// ─── Remediation ─────────────────────────────────────────────────────

test.describe("Remediation", () => {
  test("page renders with heading", async ({ page }) => {
    await page.goto("/remediation")
    await expect(page.getByRole("heading", { name: /Remediation/i })).toBeVisible()
  })

  test("Proposals and History tabs visible and clickable", async ({ page }) => {
    await page.goto("/remediation")

    const proposalsTab = page.getByText("Proposals").first()
    const historyTab = page.getByText("History").first()

    await expect(proposalsTab).toBeVisible()
    await expect(historyTab).toBeVisible()

    await historyTab.click()
    await waitForApi(page)

    await proposalsTab.click()
    await waitForApi(page)
  })

  test("does not show error AND empty state simultaneously", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/remediation")
    await waitForApi(page)

    // Error banner must be visible when API fails
    const errorLocator = page.locator('[class*="destructive"], [role="alert"]')
      .or(page.getByText(/failed/i))
    await expect(errorLocator.first()).toBeVisible({ timeout: 5000 })

    // "No remediations needed" must NOT appear alongside the error
    await expect(page.getByText(/No remediations/i)).not.toBeVisible()
  })
})

// ─── Runtime Events ──────────────────────────────────────────────────

test.describe("Runtime Events", () => {
  test("page renders with heading and stat cards", async ({ page }) => {
    await page.goto("/hooks")

    await expect(page.getByRole("heading", { name: /Runtime Events/i })).toBeVisible()

    // 4 stat cards (uppercase labels in the UI)
    await expect(page.getByText("TOTAL EVENTS").or(page.getByText("Total Events"))).toBeVisible()
    await expect(page.getByText("ALERTS TRIGGERED").or(page.getByText("Alerts Triggered"))).toBeVisible()
    await expect(page.getByText("TOP TOOL").or(page.getByText("Top Tool"))).toBeVisible()
    await expect(page.getByText("ALERT RATE").or(page.getByText("Alert Rate"))).toBeVisible()
  })

  test("filter bar renders with skill dropdown and alerts checkbox", async ({ page }) => {
    await page.goto("/hooks")

    const skillFilter = page.locator("select").first()
    await expect(skillFilter).toBeVisible()

    const alertsCheckbox = page.locator('input[type="checkbox"]').first()
    await expect(alertsCheckbox).toBeVisible()
  })

  test("events table renders with headers", async ({ page }) => {
    await page.goto("/hooks")

    const headers = ["Timestamp", "Session", "Skill", "Tool", "Outcome", "Alert"]
    for (const h of headers) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("shows error on auth failure (not silent zeros)", async ({ page }) => {
    await mockAllApi401(page)
    await page.goto("/hooks")
    await waitForApi(page)

    // Error indicator must be visible
    const errorLocator = page.locator('[role="alert"], [class*="error"], [class*="destructive"]')
      .or(page.getByText(/error|failed|401/i))
    await expect(errorLocator.first()).toBeVisible({ timeout: 5000 })

    // Empty state must NOT appear alongside the error
    await expect(page.getByText(/No events recorded/i)).not.toBeVisible()
  })
})

// ─── Full Audit — Scan History ───────────────────────────────────────

test.describe("Full Audit — Scan History", () => {
  test("shows scan history table when scans exist", async ({ page }) => {
    await page.route("**/api/v1/scans*", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([
        {
          id: "test-scan-001",
          status: "completed",
          started_at: new Date(Date.now() - 120_000).toISOString(),
          completed_at: new Date(Date.now() - 60_000).toISOString(),
          total_findings: 3,
          critical_count: 0,
          high_count: 1,
          medium_count: 1,
          low_count: 1,
          skills_scanned: 5,
          triggered_by: "manual",
          error_message: null,
        }
      ])
    }))
    await page.goto("/audit")
    await page.waitForLoadState("networkidle")

    await expect(page.getByText("Previous Scans")).toBeVisible()
    await expect(page.getByText("completed")).toBeVisible()
    await expect(page.getByRole("cell", { name: "3", exact: true })).toBeVisible()
    await expect(page.getByRole("link", { name: /view findings/i })).toBeVisible()
  })

  test("shows empty state when no scans exist", async ({ page }) => {
    await page.route("**/api/v1/scans*", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([])
    }))
    await page.goto("/audit")
    await page.waitForLoadState("networkidle")

    await expect(page.getByText(/No scans yet/i)).toBeVisible()
    await expect(page.getByText(/failed to load/i)).not.toBeVisible()
  })

  test("shows error state exclusively when API fails", async ({ page }) => {
    await page.route("**/api/v1/scans*", route => route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" })
    }))
    await page.goto("/audit")

    await expect(page.getByText(/failed to load/i)).toBeVisible({ timeout: 5000 })
    await expect(page.getByText(/No scans yet/i)).not.toBeVisible()
  })

  test("shows 'View Findings' link with correct scan_id", async ({ page }) => {
    await page.route("**/api/v1/scans*", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([{
        id: "abc-123",
        status: "complete",
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        total_findings: 5,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 5,
        skills_scanned: 1,
        triggered_by: "manual",
        error_message: null,
      }])
    }))
    await page.goto("/audit")
    await page.waitForLoadState("networkidle")

    const link = page.getByRole("link", { name: /view findings/i })
    await expect(link).toHaveAttribute("href", "/findings?scan_id=abc-123")
  })
})

// ─── Console Errors (cross-cutting) ─────────────────────────────────

test.describe("Console Errors", () => {
  const pages = [
    { name: "Dashboard", path: "/dashboard" },
    { name: "Full Audit", path: "/audit" },
    { name: "Skill Explorer", path: "/skills" },
    { name: "Findings Explorer", path: "/findings" },
    { name: "Investigation", path: "/chat" },
    { name: "Remediation", path: "/remediation" },
    { name: "Runtime Events", path: "/hooks" },
  ]

  for (const { name, path } of pages) {
    test(`no uncaught exceptions on ${name}`, async ({ page }) => {
      const uncaughtErrors: string[] = []
      page.on("pageerror", (err) => uncaughtErrors.push(err.message))

      await page.goto(path)
      await waitForApi(page)

      // Filter out known/expected errors (like 401 fetch errors)
      const unexpectedErrors = uncaughtErrors.filter(
        (e) => !e.includes("401") && !e.includes("403") && !e.includes("fetch") && !e.includes("API")
      )

      expect(unexpectedErrors).toEqual([])
    })
  }
})

// ─── Exclusive error/empty state tests (Issues #56, #57) ────────────

test.describe("Error and empty state exclusivity", () => {
  test("Runtime Events shows ONLY error state when API fails (not empty state too)", async ({ page }) => {
    await page.route("**/api/v1/hooks/**", route => route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" })
    }))

    await page.goto("/hooks")

    // Hard assert: error banner IS visible
    await expect(page.getByText(/failed to load|error/i).first()).toBeVisible({ timeout: 5000 })

    // Hard assert: empty state is NOT visible
    await expect(page.getByText(/No events recorded yet/i)).not.toBeVisible()
  })

  test("Runtime Events shows ONLY empty state when API succeeds with no data", async ({ page }) => {
    await page.route("**/api/v1/hooks/stats*", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ total_events: 0, total_alerts: 0, events_by_tool: {}, events_by_skill: {} })
    }))
    await page.route("**/api/v1/hooks/events*", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([])
    }))

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // Hard assert: empty state IS visible
    await expect(page.getByText(/No events recorded yet/i)).toBeVisible({ timeout: 5000 })

    // Hard assert: error banner is NOT visible
    await expect(page.getByText(/failed to load/i)).not.toBeVisible()
  })

  test("Findings Explorer shows ONLY error state when API fails (not empty state too)", async ({ page }) => {
    // Use single-star suffix to reliably intercept URLs with query strings
    await page.route("**/api/v1/findings*", route => route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" })
    }))

    await page.goto("/findings")

    // Hard assert: error banner IS visible (allow up to 10s for React Query retries to exhaust)
    // Note: RiskBadge for critical severity also uses text-red-400, so use div selector
    // The deployed build renders String(error) in the error div (no "Failed to load" prefix)
    await page.waitForSelector("div.text-red-400", { timeout: 10000 })
    await expect(page.locator("div.text-red-400").first()).toBeVisible({ timeout: 5000 })

    // Hard assert: empty state is NOT visible
    await expect(page.getByText(/No findings match/i)).not.toBeVisible()
  })

  test("WebSocket URL does not contain token in query string", async ({ page }) => {
    const wsUrls: string[] = []

    page.on("websocket", ws => {
      wsUrls.push(ws.url())
    })

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // Ensure at least one WS connection was attempted
    expect(wsUrls.length).toBeGreaterThan(0)

    // Any WS connection must NOT have token in URL
    for (const url of wsUrls) {
      expect(url).not.toContain("token=")
      expect(url).not.toContain("NEXT_PUBLIC_API_TOKEN")
    }
  })

  test("Findings Explorer shows ONLY empty state when API returns empty results", async ({ page }) => {
    await page.route("**/api/v1/findings**", route => route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([])
    }))

    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    // Hard assert: empty state IS visible
    await expect(page.getByText(/No findings match/i)).toBeVisible({ timeout: 5000 })

    // Hard assert: error banner is NOT visible
    await expect(page.getByText(/failed to load/i)).not.toBeVisible()
  })
})
