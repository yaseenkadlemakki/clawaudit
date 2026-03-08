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

/** Check if any error indicator is visible on the page */
async function hasErrorIndicator(page: Page): Promise<boolean> {
  const errorByClass = await page.locator('[class*="error"]').count()
  const errorByDestructive = await page.locator('[class*="destructive"]').count()
  const errorByRole = await page.locator('[role="alert"]').count()
  const errorByText = await page.getByText(/error/i).count()
  const errorBy401 = await page.getByText("401").count()
  const errorByFailed = await page.getByText(/failed/i).count()
  return (errorByClass + errorByDestructive + errorByRole + errorByText + errorBy401 + errorByFailed) > 0
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
      { label: "Investigation", path: "/chat" },
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
    await expect(page.locator("text=Phase 7b")).toBeVisible()
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
    await page.waitForTimeout(2000)
    await expect(page.getByText("Scan History")).toBeVisible()
    const headers = ["ID", "Status", "Started", "Finished", "Skills", "Findings"]
    for (const h of headers) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("stat cards show data or error (not perpetual loading)", async ({ page }) => {
    await page.goto("/dashboard")
    await page.waitForTimeout(5000) // give extra time for API call to resolve

    const hasError = await hasErrorIndicator(page)
    // Check if stat card values are still showing loading dots
    const statValues = await page.locator(".text-2xl").allTextContents()
    const allLoading = statValues.length > 0 && statValues.every(
      (v) => v.trim() === "..." || v.trim() === "•••" || v.trim() === ""
    )

    if (allLoading && !hasError) {
      // Stat cards stuck in loading state with no error — silent failure
      expect(allLoading && !hasError).toBe(false)
    }
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
    await page.waitForTimeout(3000)
    const hasStatus = await page.getByText(/running|pending|complete/i).count() > 0
    const hasError = await hasErrorIndicator(page)
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
  test("page heading always visible (even on error)", async ({ page }) => {
    await page.goto("/skills")
    await page.waitForTimeout(3000)

    // The heading should ALWAYS be visible, even when API fails
    const hasHeading = await page.getByRole("heading", { name: /Skill Explorer/i }).count() > 0
    const hasError = await hasErrorIndicator(page)

    // If there's an error but no heading, that's a bug — error replaces entire page
    if (hasError && !hasHeading) {
      expect(hasHeading).toBe(true) // fail with clear message
    }
    // If neither heading nor error, something is wrong
    expect(hasHeading || hasError).toBeTruthy()
  })

  test("Install Skill button visible (even on error)", async ({ page }) => {
    await page.goto("/skills")
    await page.waitForTimeout(3000)

    const hasInstallBtn = await page.getByRole("button", { name: /Install Skill/i }).count() > 0
    const hasError = await hasErrorIndicator(page)

    // If auth fails, Install Skill button should still be visible
    if (hasError && !hasInstallBtn) {
      expect(hasInstallBtn).toBe(true) // fail — controls hidden by error
    }
  })

  test("shows skills list or error (not blank page)", async ({ page }) => {
    await page.goto("/skills")
    await page.waitForTimeout(3000)

    const hasSkills = await page.locator('[class*="card"]').count() > 0
    const hasEmpty = await page.getByText(/no skills/i).count() > 0
    const hasError = await hasErrorIndicator(page)
    const hasLoading = await page.locator('[class*="skeleton"]').or(page.locator('[class*="animate-pulse"]')).count() > 0

    expect(hasSkills || hasEmpty || hasError || hasLoading).toBeTruthy()
  })
})

// ─── Skill Detail ────────────────────────────────────────────────────

test.describe("Skill Detail", () => {
  test("navigating to /skills/test-id shows detail or error", async ({ page }) => {
    await page.goto("/skills/test-id")
    await page.waitForTimeout(3000)

    const hasBackLink = await page.getByText("Back").or(page.locator('[href="/skills"]')).count() > 0
    const hasError = await hasErrorIndicator(page)
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
    await page.waitForTimeout(2000)
    const expectedHeaders = ["Severity", "Title", "Check ID", "Domain"]
    for (const h of expectedHeaders) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("shows error banner on auth failure (not silent zero results)", async ({ page }) => {
    await page.goto("/findings")
    await page.waitForTimeout(3000)

    const hasError = await hasErrorIndicator(page)
    const hasFindings = await page.locator("table tbody tr").count() > 0

    // Check for "0 results" text
    const resultCountEl = await page.getByText(/\d+ results/i).textContent().catch(() => "")
    const showsZeroResults = resultCountEl?.includes("0")

    // Check for "No findings match" empty state
    const hasEmptyMsg = await page.getByText("No findings match your filters").count() > 0

    // Silent failure = showing "0 results" / empty msg with no error indicator
    if (!hasFindings && !hasError && (showsZeroResults || hasEmptyMsg)) {
      expect(false).toBe(true) // FAIL: silent auth failure — no error shown to user
    }
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
    await page.waitForTimeout(2000)

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
    await page.goto("/chat")
    await page.waitForTimeout(2000)

    const firstSuggestion = page.locator('[class*="grid"] button').or(page.locator('[class*="grid"] [class*="card"]')).first()
    await firstSuggestion.click()

    await page.waitForTimeout(1000)
    const chatInput = page.locator("textarea").last()
    const inputValue = await chatInput.inputValue().catch(() => "")
    const hasMessages = await page.locator('[class*="message"]').or(page.locator('[class*="chat"]')).count() > 0

    expect(inputValue.length > 0 || hasMessages).toBeTruthy()
  })

  test("typing message and sending shows response or error", async ({ page }) => {
    await page.goto("/chat")
    await page.waitForTimeout(1000)

    const chatInput = page.locator("textarea").last()
    await chatInput.fill("What are the current security findings?")

    const sendBtn = page.locator('button[type="submit"]').or(page.getByRole("button", { name: /send/i })).first()
    await sendBtn.click()

    await page.waitForTimeout(5000)

    const hasResponse = await page.locator('[class*="message"]').or(page.locator('[class*="border"]')).count() > 1
    const hasError = await hasErrorIndicator(page)

    expect(hasResponse || hasError).toBeTruthy()
  })

  test("BYOLLM toggle shows API key input", async ({ page }) => {
    await page.goto("/chat")
    const byollmBtn = page.getByText("BYOLLM")
    await byollmBtn.click()
    await page.waitForTimeout(500)

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
    await page.waitForTimeout(1000)

    await proposalsTab.click()
    await page.waitForTimeout(1000)
  })

  test("does not show error AND empty state simultaneously", async ({ page }) => {
    await page.goto("/remediation")
    await page.waitForTimeout(3000)

    const hasErrorBanner = await page.locator('[class*="destructive"]').count()
    // Only count [role="alert"] elements that have visible text content
    const alertElements = await page.locator('[role="alert"]').all()
    let visibleAlerts = 0
    for (const el of alertElements) {
      const text = await el.textContent()
      if (text && text.trim().length > 0) visibleAlerts++
    }
    const hasFailedText = await page.getByText(/failed/i).count()
    const hasNoRemediations = await page.getByText(/No remediations/i).count()

    const hasError = hasErrorBanner + visibleAlerts + hasFailedText > 0
    const hasEmpty = hasNoRemediations > 0

    // Bug: should NOT show error + empty state at the same time
    if (hasError && hasEmpty) {
      expect(false).toBe(true) // FAIL: dual error+empty state shown
    }
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
    await page.waitForTimeout(2000)

    const skillFilter = page.locator("select").first()
    await expect(skillFilter).toBeVisible()

    const alertsCheckbox = page.locator('input[type="checkbox"]').first()
    await expect(alertsCheckbox).toBeVisible()
  })

  test("events table renders with headers", async ({ page }) => {
    await page.goto("/hooks")
    await page.waitForTimeout(2000)

    const headers = ["Timestamp", "Session", "Skill", "Tool", "Outcome", "Alert"]
    for (const h of headers) {
      await expect(page.locator(`th:has-text("${h}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("shows error on auth failure (not silent zeros)", async ({ page }) => {
    await page.goto("/hooks")
    await page.waitForTimeout(3000)

    const hasError = await hasErrorIndicator(page)
    const hasEvents = await page.locator("table tbody tr").count() > 0
    const hasEmptyState = await page.getByText(/No events recorded/i).count() > 0

    // If showing empty state with zeros and no error, it's a silent auth failure
    if (!hasEvents && !hasError && hasEmptyState) {
      // Check if stat values are all zero
      const statValues = await page.locator(".text-2xl").allTextContents()
      const allZero = statValues.length > 0 && statValues.every(
        (v) => v.trim() === "0" || v.trim() === "0%" || v.trim() === "—" || v.trim() === "-"
      )
      if (allZero) {
        expect(false).toBe(true) // FAIL: silent auth failure — zeros with no error
      }
    }
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
      await page.waitForTimeout(3000)

      // Filter out known/expected errors (like 401 fetch errors)
      const unexpectedErrors = uncaughtErrors.filter(
        (e) => !e.includes("401") && !e.includes("403") && !e.includes("fetch") && !e.includes("API")
      )

      expect(unexpectedErrors).toEqual([])
    })
  }
})

// ─── NEW: Exclusive error/empty state tests (Issues #56, #57) ───────

test.describe("Error and empty state exclusivity", () => {
  test("Runtime Events shows ONLY error state when API fails (not empty state too)", async ({ page }) => {
    // Intercept BEFORE navigating
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
    await page.route("**/api/v1/findings**", route => route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" })
    }))

    await page.goto("/findings")

    // Hard assert: error banner IS visible
    await expect(page.getByText(/failed to load/i).first()).toBeVisible({ timeout: 5000 })

    // Hard assert: empty state is NOT visible
    await expect(page.getByText(/No findings match/i)).not.toBeVisible()
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
