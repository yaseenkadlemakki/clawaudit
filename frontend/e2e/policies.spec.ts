import { test, expect, type Page } from "@playwright/test"

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_STARTER_POLICIES = [
  {
    id: "p-001",
    name: "block-pty-exec",
    domain: "tool_call",
    check: "params.pty",
    condition: "equals",
    value: "true",
    severity: "HIGH",
    action: "BLOCK",
    enabled: true,
    builtin: true,
    description: "Block exec tool calls with PTY enabled.",
    priority: 100,
    tags: null,
    violation_count: 3,
    last_triggered_at: new Date(Date.now() - 3600_000).toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "p-002",
    name: "alert-credential-file-read",
    domain: "tool_call",
    check: "params.path",
    condition: "matches",
    value: "\\.env$|credentials|\\.pem$",
    severity: "HIGH",
    action: "ALERT",
    enabled: true,
    builtin: true,
    description: "Alert when a skill reads credential or secret files.",
    priority: 90,
    tags: null,
    violation_count: 1,
    last_triggered_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "p-003",
    name: "alert-elevated-exec",
    domain: "tool_call",
    check: "params.elevated",
    condition: "equals",
    value: "true",
    severity: "HIGH",
    action: "ALERT",
    enabled: true,
    builtin: true,
    description: "Alert when a skill requests elevated execution.",
    priority: 90,
    tags: null,
    violation_count: 0,
    last_triggered_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "p-004",
    name: "alert-browser-external-navigate",
    domain: "tool_call",
    check: "params.url",
    condition: "matches",
    value: "^https?://(?!localhost)",
    severity: "MEDIUM",
    action: "ALERT",
    enabled: true,
    builtin: true,
    description: "Alert when a skill navigates to an external URL.",
    priority: 70,
    tags: null,
    violation_count: 0,
    last_triggered_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
  {
    id: "p-005",
    name: "alert-message-send",
    domain: "tool_call",
    check: "tool",
    condition: "equals",
    value: "message",
    severity: "MEDIUM",
    action: "ALERT",
    enabled: true,
    builtin: true,
    description: "Alert when a skill sends a message.",
    priority: 60,
    tags: null,
    violation_count: 0,
    last_triggered_at: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  },
]

const MOCK_CUSTOM_POLICY = {
  id: "p-custom-1",
  name: "my-custom-policy",
  domain: "tool_call",
  check: "tool",
  condition: "equals",
  value: "browser",
  severity: "MEDIUM",
  action: "ALERT",
  enabled: true,
  builtin: false,
  description: "Custom test policy",
  priority: 50,
  tags: null,
  violation_count: 0,
  last_triggered_at: null,
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
}

const MOCK_STATS = {
  active_count: 5,
  violations_today: 4,
  blocked_today: 1,
  alerted_today: 3,
  quarantined_skills: 0,
}

const MOCK_VIOLATIONS = [
  {
    id: "viol-001",
    scan_id: "policy-engine",
    check_id: "POL-p-001a",
    domain: "policy",
    title: "Policy BLOCK: params.pty",
    description: "Tool exec blocked by pty policy",
    severity: "HIGH",
    result: "FAIL",
    evidence: "tool=exec params={'pty': True}",
    location: "before_tool_call hook — skill: my-skill",
    remediation: "Review policy rule",
    detected_at: new Date(Date.now() - 3600_000).toISOString(),
    skill_name: "my-skill",
  },
]

// ─── Route helpers ────────────────────────────────────────────────────────────

async function mockPoliciesSuccess(page: Page, policies = [...MOCK_STARTER_POLICIES]) {
  await page.route("**/api/v1/policies/stats", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_STATS),
    })
  )
  await page.route("**/api/v1/policies", (route) => {
    if (route.request().method() === "GET") {
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(policies),
      })
    } else {
      route.continue()
    }
  })
  await page.route("**/api/v1/findings*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_VIOLATIONS),
    })
  )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

test.describe("Policies page", () => {
  test("page loads with 5 starter policies visible", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Page title visible
    await expect(page.getByRole("heading", { name: "Policy Engine" })).toBeVisible()

    // All 5 starter policies visible
    for (const p of MOCK_STARTER_POLICIES) {
      await expect(page.getByText(p.name).first()).toBeVisible()
    }
  })

  test("stats bar shows correct counts", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Wait for stats to load
    await expect(page.getByText("Active Policies")).toBeVisible()
    await expect(page.getByText("Violations Today")).toBeVisible()
    await expect(page.getByText("Blocked Today")).toBeVisible()
    await expect(page.getByText("Alerted Today")).toBeVisible()
    await expect(page.getByText("Quarantined Skills")).toBeVisible()

    // Check stat values
    await expect(page.locator("text=Active Policies").locator("..").getByText("5")).toBeVisible()
    await expect(page.locator("text=Violations Today").locator("..").getByText("4")).toBeVisible()
  })

  test("builtin policies show lock icon and delete is disabled", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Find the delete button for first builtin policy row
    // Builtin delete buttons should be disabled
    const deleteBtn = page.locator("button[aria-label='Delete policy']").first()
    await expect(deleteBtn).toBeDisabled()
  })

  test("create policy modal opens on New Policy button click", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    await page.getByRole("button", { name: /new policy/i }).click()
    await expect(page.getByText("New Policy").last()).toBeVisible()
    await expect(page.getByPlaceholder("my-policy-name")).toBeVisible()
  })

  test("form validates required fields", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    await page.getByRole("button", { name: /new policy/i }).click()
    // Click save without filling required fields
    await page.getByRole("button", { name: /save policy/i }).click()
    await expect(page.getByText(/name is required/i)).toBeVisible()
  })

  test("form validates check field required", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    await page.getByRole("button", { name: /new policy/i }).click()
    await page.getByPlaceholder("my-policy-name").fill("test-policy")
    await page.getByRole("button", { name: /save policy/i }).click()
    await expect(page.getByText(/check field is required/i)).toBeVisible()
  })

  test("save creates policy in table", async ({ page }) => {
    const policies = [...MOCK_STARTER_POLICIES]
    await mockPoliciesSuccess(page, policies)

    await page.route("**/api/v1/policies", async (route) => {
      if (route.request().method() === "POST") {
        const newPolicy = { ...MOCK_CUSTOM_POLICY }
        policies.push(newPolicy)
        await route.fulfill({
          status: 201,
          contentType: "application/json",
          body: JSON.stringify(newPolicy),
        })
        // Reregister GET to return updated list
      } else {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(policies),
        })
      }
    })

    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    await page.getByRole("button", { name: /new policy/i }).click()
    await page.getByPlaceholder("my-policy-name").fill("my-custom-policy")
    await page.getByPlaceholder("params.pty").fill("tool")
    await page.getByRole("button", { name: /save policy/i }).click()

    // Modal closes
    await expect(page.getByPlaceholder("my-policy-name")).not.toBeVisible()
  })

  test("toggle enable/disable fires update request", async ({ page }) => {
    await mockPoliciesSuccess(page)

    let toggleCalled = false
    await page.route("**/api/v1/policies/p-custom-1", async (route) => {
      if (route.request().method() === "PUT") {
        toggleCalled = true
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...MOCK_CUSTOM_POLICY, enabled: false }),
        })
      } else {
        await route.continue()
      }
    })

    // Add custom policy to list
    await page.route("**/api/v1/policies", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify([...MOCK_STARTER_POLICIES, MOCK_CUSTOM_POLICY]),
        })
      } else {
        await route.continue()
      }
    })

    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // The custom policy toggle should be clickable (not builtin)
    const toggleBtns = page.locator("button[aria-label='Disable policy']")
    const customToggle = toggleBtns.last()
    await customToggle.click()

    // Verify PUT was called
    expect(toggleCalled).toBe(true)
  })

  test("delete custom policy fires delete request", async ({ page }) => {
    let deleteCalled = false
    await page.route("**/api/v1/policies/stats", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_STATS) })
    )
    await page.route("**/api/v1/policies/p-custom-1", async (route) => {
      if (route.request().method() === "DELETE") {
        deleteCalled = true
        await route.fulfill({ status: 204 })
      } else {
        await route.continue()
      }
    })
    await page.route("**/api/v1/policies", async (route) => {
      if (route.request().method() === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify([...MOCK_STARTER_POLICIES, MOCK_CUSTOM_POLICY]),
        })
      } else {
        await route.continue()
      }
    })
    await page.route("**/api/v1/findings*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) })
    )

    page.on("dialog", (dialog) => dialog.accept())
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Click last delete button (the custom policy's)
    const deleteBtns = page.locator("button[aria-label='Delete policy']:not([disabled])")
    await deleteBtns.last().click()

    expect(deleteCalled).toBe(true)
  })

  test("delete builtin policy shows error or button is disabled", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // All delete buttons for builtin policies should be disabled
    const allDeleteBtns = page.locator("button[aria-label='Delete policy']")
    const count = await allDeleteBtns.count()

    // Find the first one (should be builtin)
    const firstBtn = allDeleteBtns.first()
    await expect(firstBtn).toBeDisabled()
  })

  test("violations feed tab renders", async ({ page }) => {
    await mockPoliciesSuccess(page)
    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Click violations feed tab
    await page.getByRole("button", { name: /violations feed/i }).click()
    await expect(page.getByText("Recent Policy Violations")).toBeVisible()

    // Violation entry visible
    await expect(page.getByText("Policy BLOCK: params.pty")).toBeVisible()
  })

  test("error state when API fails", async ({ page }) => {
    await page.route("**/api/v1/policies/stats", (route) =>
      route.fulfill({ status: 500, contentType: "application/json", body: '{"detail":"Internal error"}' })
    )
    await page.route("**/api/v1/policies", (route) =>
      route.fulfill({ status: 500, contentType: "application/json", body: '{"detail":"Internal error"}' })
    )
    await page.route("**/api/v1/findings*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: "[]" })
    )

    await page.goto("/policies")
    await page.waitForLoadState("domcontentloaded")

    // Should show error state
    await expect(
      page.getByText(/error|failed|500/i).first()
    ).toBeVisible()
  })
})
