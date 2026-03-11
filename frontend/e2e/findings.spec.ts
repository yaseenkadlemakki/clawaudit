import { test, expect, Page } from "@playwright/test"

// ─── Shared mock data ─────────────────────────────────────────────────────────

const MOCK_FINDINGS = [
  {
    id: "f-001",
    scan_id: "scan-abc-123456789",
    severity: "critical",
    title: "Shell Injection Risk in filesystem skill",
    check_id: "INJ-001",
    domain: "input_validation",
    skill_name: "filesystem",
    description: "The skill executes shell commands with unsanitised user input.",
    evidence: "cmd = f'ls {user_input}'",
    remediation: "Sanitise all inputs before passing to shell.",
    location: "/home/user/.skills/filesystem.skill",
    detected_at: new Date(Date.now() - 3600_000).toISOString(),
  },
  {
    id: "f-002",
    scan_id: "scan-abc-123456789",
    severity: "high",
    title: "Excessive outbound network access",
    check_id: "NET-002",
    domain: "network",
    skill_name: "web-browse",
    description: "Skill makes requests to arbitrary external domains.",
    evidence: "requests.get(url)",
    remediation: "Restrict outbound domains in skill manifest.",
    location: "/home/user/.skills/web-browse.skill",
    detected_at: new Date(Date.now() - 7200_000).toISOString(),
  },
  {
    id: "f-003",
    scan_id: "scan-abc-123456789",
    severity: "medium",
    title: "Weak file permission on skill config",
    check_id: "PERM-003",
    domain: "permissions",
    skill_name: "config-manager",
    description: "Skill config file is world-readable.",
    evidence: "-rw-r--r-- config.yaml",
    remediation: "Set permissions to 600.",
    location: "/home/user/.skills/config-manager.skill",
    detected_at: new Date(Date.now() - 10800_000).toISOString(),
  },
]

/** Mock all findings API calls with sample data */
async function mockFindingsSuccess(page: Page) {
  await page.route("**/api/v1/findings*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_FINDINGS),
    })
  )
}

/** Mock findings API to return an empty list */
async function mockFindingsEmpty(page: Page) {
  await page.route("**/api/v1/findings*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )
}

/** Mock ALL api/v1 calls to return 500 (ensures findings errors show) */
async function mockAllApi500(page: Page) {
  await page.route("**/api/v1/**", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
}

// ─── Page renders ─────────────────────────────────────────────────────────────

test.describe("Findings Explorer — page renders", () => {
  test("heading is always visible", async ({ page }) => {
    await page.goto("/findings")
    await expect(page.getByRole("heading", { name: /Findings Explorer/i })).toBeVisible()
  })

  test("search input is present and focusable", async ({ page }) => {
    await page.goto("/findings")
    const input = page.locator('input[placeholder*="Search"]').first()
    await expect(input).toBeVisible()
    await input.focus()
    await expect(input).toBeFocused()
  })

  test("severity filter dropdown is rendered with correct options", async ({ page }) => {
    await page.goto("/findings")
    // First select is the severity filter
    const severitySelect = page.locator("select").first()
    await expect(severitySelect).toBeVisible()
    // Default option should be "All Severities"
    await expect(severitySelect.locator("option").first()).toHaveText("All Severities")
    // Should contain all severity levels
    for (const sev of ["Critical", "High", "Medium", "Low", "Info"]) {
      await expect(severitySelect.locator(`option[value="${sev.toLowerCase()}"]`)).toHaveCount(1)
    }
  })

  test("table headers are rendered correctly", async ({ page }) => {
    await page.goto("/findings")
    for (const header of ["Severity", "Title", "Check ID", "Domain", "Skill", "Detected"]) {
      await expect(page.locator(`th:has-text("${header}")`).first()).toBeVisible({ timeout: 5000 })
    }
  })
})

// ─── Data loads ───────────────────────────────────────────────────────────────

test.describe("Findings Explorer — data loads", () => {
  test("renders finding rows when API returns data", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    // Wait for at least one finding row to appear
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    const rows = page.locator("tbody tr")
    // Should have at least 3 rows (one per mock finding)
    expect(await rows.count()).toBeGreaterThanOrEqual(3)
  })

  test("displays finding title from API data", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    await expect(page.getByText("Shell Injection Risk in filesystem skill")).toBeVisible()
  })

  test("displays check_id values from API data", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    await expect(page.getByText("INJ-001")).toBeVisible()
    await expect(page.getByText("NET-002")).toBeVisible()
  })

  test("result count updates after data loads", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    // The page shows "X results" span
    const countSpan = page.locator("span").filter({ hasText: /result/ })
    await expect(countSpan).toBeVisible()
  })
})

// ─── Filter: severity ─────────────────────────────────────────────────────────

test.describe("Findings Explorer — filter by severity", () => {
  test("selecting a severity triggers a new API request with severity param", async ({ page }) => {
    await page.route("**/api/v1/findings*", (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_FINDINGS.filter((f) => f.severity === "critical")),
      })
    })

    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    // Listen for next findings response with the severity filter applied
    const responsePromise = page.waitForResponse(
      (resp) => resp.url().includes("/api/v1/findings") && resp.url().includes("severity=critical"),
      { timeout: 8000 }
    )

    const severitySelect = page.locator("select").first()
    await severitySelect.selectOption("critical")

    // Verify a request was made with the severity param
    const resp = await responsePromise
    expect(resp.status()).toBe(200)
    expect(resp.url()).toContain("severity=critical")
  })

  test("severity select can be changed to each level", async ({ page }) => {
    await mockFindingsEmpty(page)
    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    const severitySelect = page.locator("select").first()
    for (const sev of ["critical", "high", "medium", "low", "info", ""]) {
      await severitySelect.selectOption(sev)
      await expect(severitySelect).toHaveValue(sev)
    }
  })

  test("resetting severity to 'All' clears filter", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForLoadState("networkidle")

    const severitySelect = page.locator("select").first()
    await severitySelect.selectOption("high")
    await expect(severitySelect).toHaveValue("high")

    await severitySelect.selectOption("")
    await expect(severitySelect).toHaveValue("")
  })
})

// ─── Filter: search / check_id ────────────────────────────────────────────────

test.describe("Findings Explorer — search input", () => {
  test("typing in search input updates its value", async ({ page }) => {
    await page.goto("/findings")
    const searchInput = page.locator('input[placeholder*="Search"]').first()
    await searchInput.fill("INJ-001")
    await expect(searchInput).toHaveValue("INJ-001")
  })

  test("search by check_id filters the visible rows", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search"]').first()
    await searchInput.fill("INJ-001")

    // After filtering, NET-002 title should no longer be visible
    await expect(page.getByText("Excessive outbound network access")).not.toBeVisible()
    // But INJ-001 finding should still be visible
    await expect(page.getByText("Shell Injection Risk in filesystem skill")).toBeVisible()
  })

  test("search by title filters correctly", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search"]').first()
    await searchInput.fill("outbound")

    await expect(page.getByText("Excessive outbound network access")).toBeVisible()
    await expect(page.getByText("Shell Injection Risk in filesystem skill")).not.toBeVisible()
  })

  test("clearing search input restores all results", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search"]').first()
    await searchInput.fill("INJ-001")
    // Only one result visible
    await expect(page.getByText("Excessive outbound network access")).not.toBeVisible()

    // Clear the search
    await searchInput.fill("")
    // All results should be back
    await expect(page.getByText("Excessive outbound network access")).toBeVisible()
    await expect(page.getByText("Shell Injection Risk in filesystem skill")).toBeVisible()
  })
})

// ─── Row interaction ──────────────────────────────────────────────────────────

test.describe("Findings Explorer — row expansion", () => {
  test("clicking a row expands it to show description", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    // Click the first data row (role=button rows)
    const firstRow = page.locator("tbody tr[role='button']").first()
    await firstRow.click()

    // Description should now be visible
    await expect(page.getByText("The skill executes shell commands with unsanitised user input.")).toBeVisible()
  })

  test("clicking expanded row collapses it", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const firstRow = page.locator("tbody tr[role='button']").first()
    await firstRow.click()

    // Confirm it expanded
    await expect(page.getByText("The skill executes shell commands with unsanitised user input.")).toBeVisible()

    // Click again to collapse
    await firstRow.click()
    await expect(page.getByText("The skill executes shell commands with unsanitised user input.")).not.toBeVisible()
  })
})

// ─── Empty state ──────────────────────────────────────────────────────────────

test.describe("Findings Explorer — empty state", () => {
  test("shows empty state message when API returns no findings", async ({ page }) => {
    await mockFindingsEmpty(page)
    await page.goto("/findings")
    await page.waitForLoadState("networkidle")
    await expect(page.getByText(/No findings match/i)).toBeVisible({ timeout: 8000 })
  })

  test("empty state is not shown when findings exist", async ({ page }) => {
    await mockFindingsSuccess(page)
    await page.goto("/findings")
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    await expect(page.getByText(/No findings match/i)).not.toBeVisible()
  })
})

// ─── Error state ──────────────────────────────────────────────────────────────

test.describe("Findings Explorer — error state", () => {
  test("shows error banner when API returns 500", async ({ page }) => {
    await mockAllApi500(page)
    await page.goto("/findings")
    // Wait for the error div (div.text-red-400) not any text-red-400 element (RiskBadge also uses it)
    await page.waitForSelector("div.text-red-400", { timeout: 8000 })
    await expect(page.locator("div.text-red-400").first()).toBeVisible()
  })

  test("error banner shows API error message in error div", async ({ page }) => {
    await mockAllApi500(page)
    await page.goto("/findings")
    // Wait for the error div specifically (not just any text-red-400 element like RiskBadge)
    await page.waitForSelector("div.text-red-400", { timeout: 8000 })
    // The deployed build renders String(error) in the error div — check for error content
    const errorDiv = page.locator("div.text-red-400").first()
    await expect(errorDiv).toBeVisible()
    const text = await errorDiv.textContent()
    // The error should contain either the label prefix or the API error string
    expect(text?.toLowerCase()).toMatch(/failed to load|api 5|error/)
  })

  test("empty state is NOT shown alongside error", async ({ page }) => {
    await mockAllApi500(page)
    await page.goto("/findings")
    await page.waitForSelector("div.text-red-400", { timeout: 8000 })
    await expect(page.getByText(/No findings match/i)).not.toBeVisible()
  })

  test("heading remains visible even on API error", async ({ page }) => {
    await mockAllApi500(page)
    await page.goto("/findings")
    await expect(page.getByRole("heading", { name: /Findings Explorer/i })).toBeVisible()
  })
})
