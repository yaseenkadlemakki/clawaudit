import { test, expect, Page } from "@playwright/test"

// ─── Shared mock data ─────────────────────────────────────────────────────────

const MOCK_STATS = {
  total_events: 42,
  total_alerts: 5,
  events_by_tool: {
    bash: 20,
    read_file: 15,
    write_file: 7,
  },
  events_by_skill: {
    filesystem: 22,
    "web-browse": 20,
  },
}

const MOCK_EVENTS = [
  {
    id: "evt-001",
    timestamp: new Date(Date.now() - 5000).toISOString(),
    session_id: "sess-aabbccdd-0001",
    skill_name: "filesystem",
    tool_name: "bash",
    outcome: "success",
    alert_triggered: false,
    alert_reasons: [],
    params_summary: '{"cmd": "ls /tmp"}',
  },
  {
    id: "evt-002",
    timestamp: new Date(Date.now() - 15000).toISOString(),
    session_id: "sess-aabbccdd-0002",
    skill_name: "web-browse",
    tool_name: "read_file",
    outcome: "error",
    alert_triggered: true,
    alert_reasons: ["Suspicious file path accessed", "Shell injection detected"],
    params_summary: '{"path": "/etc/passwd"}',
  },
  {
    id: "evt-003",
    timestamp: new Date(Date.now() - 30000).toISOString(),
    session_id: "sess-aabbccdd-0003",
    skill_name: "filesystem",
    tool_name: "write_file",
    outcome: "success",
    alert_triggered: false,
    alert_reasons: [],
    params_summary: '{"path": "/tmp/output.txt"}',
  },
]

/** Mock all hooks API calls with sample data */
async function mockHooksSuccess(page: Page) {
  await page.route("**/api/v1/hooks/stats*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_STATS),
    })
  )
  await page.route("**/api/v1/hooks/events*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_EVENTS),
    })
  )
}

/** Mock hooks API to return empty data */
async function mockHooksEmpty(page: Page) {
  await page.route("**/api/v1/hooks/stats*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        total_events: 0,
        total_alerts: 0,
        events_by_tool: {},
        events_by_skill: {},
      }),
    })
  )
  await page.route("**/api/v1/hooks/events*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )
}

/** Mock hooks API to return a 500 error — use specific endpoints that are known to work */
async function mockHooksError(page: Page) {
  await page.route("**/api/v1/hooks/stats*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
  await page.route("**/api/v1/hooks/events*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
}

// ─── Page renders ─────────────────────────────────────────────────────────────

test.describe("Runtime Events — page renders", () => {
  test("heading is visible", async ({ page }) => {
    await page.goto("/hooks")
    await expect(page.getByRole("heading", { name: /Runtime Events/i })).toBeVisible()
  })

  test("four stat cards are rendered", async ({ page }) => {
    await page.goto("/hooks")
    await expect(
      page.getByText("TOTAL EVENTS").or(page.getByText("Total Events"))
    ).toBeVisible({ timeout: 8000 })
    await expect(
      page.getByText("ALERTS TRIGGERED").or(page.getByText("Alerts Triggered"))
    ).toBeVisible()
    await expect(
      page.getByText("TOP TOOL").or(page.getByText("Top Tool"))
    ).toBeVisible()
    await expect(
      page.getByText("ALERT RATE").or(page.getByText("Alert Rate"))
    ).toBeVisible()
  })

  test("filter bar renders with skill dropdown", async ({ page }) => {
    await page.goto("/hooks")
    const skillSelect = page.locator("select").first()
    await expect(skillSelect).toBeVisible()
    await expect(skillSelect.locator("option").first()).toHaveText("All Skills")
  })

  test("alerts only checkbox is present", async ({ page }) => {
    await page.goto("/hooks")
    const checkbox = page.locator('input[type="checkbox"]').first()
    await expect(checkbox).toBeVisible()
  })

  test("table headers are rendered", async ({ page }) => {
    await page.goto("/hooks")
    for (const header of ["Timestamp", "Session", "Skill", "Tool", "Outcome", "Alert"]) {
      await expect(page.locator(`th:has-text("${header}")`).first()).toBeVisible({ timeout: 8000 })
    }
  })
})

// ─── Data loads ───────────────────────────────────────────────────────────────

test.describe("Runtime Events — data loads", () => {
  test("stat cards show values from API", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // Total events should show 42 - wait for it in the stat card text
    await page.waitForSelector("text=42", { timeout: 8000 })
    await expect(page.getByText("42")).toBeVisible()
  })

  test("events appear in the table when API returns data", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    // Wait for at least one row
    await page.waitForSelector("tbody tr:not(:has(td[colspan]))", { timeout: 8000 })
    const rows = page.locator("tbody tr")
    // Should have exactly 3 rows (one per mock event)
    await expect(rows).toHaveCount(3)
  })

  test("tool names from events are visible in table", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    // Wait for a table cell containing tool names
    await page.waitForSelector("tbody td", { timeout: 8000 })
    await expect(page.locator("td").getByText("bash").first()).toBeVisible()
    await expect(page.locator("td").getByText("read_file").first()).toBeVisible()
  })

  test("skill names from events are visible in table cells", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForSelector("tbody td", { timeout: 8000 })
    // Target table cells specifically to avoid matching hidden select options
    await expect(page.locator("td").getByText("filesystem").first()).toBeVisible()
  })

  test("alert badges appear for flagged events", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForSelector("tbody tr", { timeout: 8000 })
    // evt-002 has alert_triggered=true → ALERT badge
    await expect(page.getByText("ALERT").first()).toBeVisible()
  })
})

// ─── Connection status / WebSocket ────────────────────────────────────────────

test.describe("Runtime Events — connection status", () => {
  test("Live badge appears when WebSocket delivers an event", async ({ page }) => {
    await mockHooksSuccess(page)

    // Intercept the WebSocket connection and push a fake live event.
    // The routeWebSocket handler is invoked when the connection is established,
    // so ws.send() can be called directly (with a small delay to let the client
    // onopen handler fire first).
    await page.routeWebSocket("**/api/v1/hooks/stream", async (ws) => {
      // Allow client's onopen (auth send) to fire first
      await new Promise((r) => setTimeout(r, 100))
      // Push a fake tool event to the client
      ws.send(
        JSON.stringify({
          id: "live-001",
          timestamp: new Date().toISOString(),
          session_id: "sess-live-0001",
          skill_name: "filesystem",
          tool_name: "bash",
          outcome: "success",
          alert_triggered: false,
          alert_reasons: [],
          params_summary: '{"cmd": "echo hello"}',
        })
      )
    })

    await page.goto("/hooks")

    // The "Live" badge with animated green dot should become visible
    await expect(page.getByText(/^Live$/i)).toBeVisible({ timeout: 8000 })
    // The Live badge's green dot indicator should be present
    await expect(page.locator("span.bg-green-400")).toBeVisible()
  })

  test("page attempts a WebSocket connection to /api/v1/hooks/stream", async ({ page }) => {
    const wsUrls: string[] = []
    page.on("websocket", (ws) => {
      wsUrls.push(ws.url())
    })

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // At least one WebSocket connection attempt must have been made
    expect(wsUrls.length).toBeGreaterThan(0)
    // The URL should point to the hooks stream endpoint
    const hookWs = wsUrls.find((u) => u.includes("/hooks/stream"))
    expect(hookWs).toBeDefined()
  })

  test("WebSocket URL does not contain token in query string", async ({ page }) => {
    const wsUrls: string[] = []
    page.on("websocket", (ws) => {
      wsUrls.push(ws.url())
    })

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    for (const url of wsUrls) {
      expect(url).not.toContain("token=")
      expect(url).not.toContain("NEXT_PUBLIC_API_TOKEN")
    }
  })

  test("page structure renders correctly when waiting for live events", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // The "Live" badge only shows if liveEvents.length > 0 (pushed via WebSocket)
    // Verify page renders without crashing
    await expect(page.getByRole("heading", { name: /Runtime Events/i })).toBeVisible()
    await expect(page.locator("table")).toBeVisible()
  })
})

// ─── Filter interactions ──────────────────────────────────────────────────────

test.describe("Runtime Events — filter interactions", () => {
  test("alerts only checkbox can be toggled", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    const checkbox = page.locator('input[type="checkbox"]').first()
    await expect(checkbox).not.toBeChecked()
    await checkbox.click()
    await expect(checkbox).toBeChecked()
    await checkbox.click()
    await expect(checkbox).not.toBeChecked()
  })

  test("checking alerts only triggers API request with alerts_only param", async ({ page }) => {
    const requestUrls: string[] = []
    await page.route("**/api/v1/hooks/events*", (route) => {
      requestUrls.push(route.request().url())
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_EVENTS.filter((e) => e.alert_triggered)),
      })
    })
    await page.route("**/api/v1/hooks/stats*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_STATS) })
    )

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // Wait for the response with alerts_only param
    const responsePromise = page.waitForResponse(
      (resp) => resp.url().includes("/hooks/events") && resp.url().includes("alerts_only=true"),
      { timeout: 8000 }
    )

    const checkbox = page.locator('input[type="checkbox"]').first()
    await checkbox.click()

    const resp = await responsePromise
    expect(resp.url()).toContain("alerts_only=true")
  })

  test("skill filter dropdown renders with All Skills option", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    // Wait for events to load and populate the skill dropdown
    await page.waitForSelector("tbody td", { timeout: 8000 })
    await page.waitForLoadState("networkidle")

    const skillSelect = page.locator("select").first()
    const options = await skillSelect.locator("option").allTextContents()
    // Should have "All Skills" plus at least the skill names from events
    expect(options.length).toBeGreaterThanOrEqual(1)
    expect(options[0]).toBe("All Skills")
  })

  test("selecting a skill filter triggers API request with skill_name param", async ({ page }) => {
    await page.route("**/api/v1/hooks/events*", (route) => {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_EVENTS),
      })
    })
    await page.route("**/api/v1/hooks/stats*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_STATS) })
    )

    await page.goto("/hooks")
    await page.waitForSelector("tbody td", { timeout: 8000 })
    await page.waitForLoadState("networkidle")

    const skillSelect = page.locator("select").first()

    // Wait for the skill options to populate (derived from loaded events data)
    await expect(skillSelect.locator("option").nth(1)).toBeAttached({ timeout: 8000 })

    const options = await skillSelect.locator("option").allTextContents()
    expect(options.length).toBeGreaterThanOrEqual(2)

    // Set up response watcher for the skill filter request
    const responsePromise = page.waitForResponse(
      (resp) => resp.url().includes("/hooks/events") && resp.url().includes("skill_name="),
      { timeout: 8000 }
    )

    await skillSelect.selectOption(options[1])
    const resp = await responsePromise
    expect(resp.url()).toContain("skill_name=")
  })
})

// ─── Row click / alert detail ─────────────────────────────────────────────────

test.describe("Runtime Events — row click", () => {
  test("clicking an alert row shows alert detail panel", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    // Find the row with ALERT badge and click it
    const alertRow = page.locator("tbody tr").filter({ hasText: "ALERT" }).first()
    await alertRow.click()

    // Alert detail panel should appear
    await page.waitForSelector("text=Alert Detail", { timeout: 5000 })
    await expect(page.getByText(/Alert Detail/i)).toBeVisible()
  })

  test("alert detail panel shows alert reasons", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const alertRow = page.locator("tbody tr").filter({ hasText: "ALERT" }).first()
    await alertRow.click()

    await page.waitForSelector("text=Alert Detail", { timeout: 5000 })
    await expect(page.getByText(/Alert reasons/i)).toBeVisible()
  })

  test("clicking alert row again collapses the detail panel", async ({ page }) => {
    await mockHooksSuccess(page)
    await page.goto("/hooks")
    await page.waitForSelector("tbody tr", { timeout: 8000 })

    const alertRow = page.locator("tbody tr").filter({ hasText: "ALERT" }).first()
    await alertRow.click()

    await page.waitForSelector("text=Alert Detail", { timeout: 5000 })
    await expect(page.getByText(/Alert Detail/i)).toBeVisible()

    // Click again to collapse
    await alertRow.click()
    await expect(page.getByText(/Alert Detail/i)).not.toBeVisible()
  })
})

// ─── Empty state ──────────────────────────────────────────────────────────────

test.describe("Runtime Events — empty state", () => {
  test("shows 'No events recorded yet' when API returns empty", async ({ page }) => {
    await mockHooksEmpty(page)
    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")
    await expect(page.getByText(/No events recorded yet/i)).toBeVisible({ timeout: 8000 })
  })

  test("stat cards show zero values in empty state", async ({ page }) => {
    await mockHooksEmpty(page)
    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    // Total events should be 0
    const statValues = await page.locator(".text-2xl").allTextContents()
    const hasZero = statValues.some((v) => v.trim() === "0")
    expect(hasZero).toBe(true)
  })

  test("empty state is not shown alongside error", async ({ page }) => {
    await mockHooksError(page)
    await page.goto("/hooks")
    await page.waitForSelector("div.text-red-400", { timeout: 10000 })
    await expect(page.getByText(/No events recorded yet/i)).not.toBeVisible()
  })
})

// ─── Error state ──────────────────────────────────────────────────────────────

test.describe("Runtime Events — error state", () => {
  test("shows error banner when API returns 500", async ({ page }) => {
    await mockHooksError(page)
    await page.goto("/hooks")
    // Wait specifically for the error DIV (not the stat card icon or alert badge)
    await page.waitForSelector("div.text-red-400", { timeout: 10000 })
    await expect(page.locator("div.text-red-400").first()).toBeVisible()
  })

  test("error banner shows API error content in error div", async ({ page }) => {
    await mockHooksError(page)
    await page.goto("/hooks")
    // Wait specifically for a DIV with text-red-400 (the error banner div),
    // not the stat card icon or alert badge that also uses text-red-400
    await page.waitForSelector("div.text-red-400", { timeout: 10000 })
    const errorDiv = page.locator("div.text-red-400").first()
    await expect(errorDiv).toBeVisible()
    const text = await errorDiv.textContent()
    // The deployed build renders String(error) — check for error content
    expect(text?.toLowerCase()).toMatch(/failed to load|api 5|error/)
  })

  test("heading remains visible on API error", async ({ page }) => {
    await mockHooksError(page)
    await page.goto("/hooks")
    await expect(page.getByRole("heading", { name: /Runtime Events/i })).toBeVisible()
  })

  test("error state is exclusive — no empty state shown", async ({ page }) => {
    await mockHooksError(page)
    await page.goto("/hooks")
    await page.waitForSelector("div.text-red-400", { timeout: 10000 })
    await expect(page.getByText(/No events recorded yet/i)).not.toBeVisible()
  })
})
