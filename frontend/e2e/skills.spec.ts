import { test, expect, Page } from "@playwright/test"

// ─── Shared mock data ─────────────────────────────────────────────────────────

const MOCK_SKILLS = [
  {
    id: "skill-001",
    scan_id: "scan-xyz-001",
    name: "filesystem",
    source: "local",
    path: "/home/user/.skills/filesystem.skill",
    shell_access: true,
    outbound_domains: [],
    injection_risk: "HIGH",
    trust_score: "CAUTION",
    risk_score: 72,
    risk_level: "HIGH",
    detected_at: new Date(Date.now() - 86400_000).toISOString(),
  },
  {
    id: "skill-002",
    scan_id: "scan-xyz-001",
    name: "web-browse",
    source: "community",
    path: "/home/user/.skills/web-browse.skill",
    shell_access: false,
    outbound_domains: ["api.example.com", "cdn.example.com"],
    injection_risk: "LOW",
    trust_score: "TRUSTED",
    risk_score: 30,
    risk_level: "MEDIUM",
    detected_at: new Date(Date.now() - 172800_000).toISOString(),
  },
]

const MOCK_LIFECYCLE_SKILLS = [
  {
    name: "filesystem",
    source: "local",
    path: "/home/user/.skills/filesystem.skill",
    enabled: true,
    version: "1.2.0",
    installed_at: new Date(Date.now() - 86400_000).toISOString(),
    risk_level: "HIGH",
  },
  {
    name: "web-browse",
    source: "community",
    path: "/home/user/.skills/web-browse.skill",
    enabled: false,
    version: "2.0.1",
    installed_at: new Date(Date.now() - 172800_000).toISOString(),
    risk_level: "MEDIUM",
  },
]

const MOCK_SKILL_DETAIL = { ...MOCK_SKILLS[0] }

/**
 * Mock all skills-related API calls.
 * NOTE: getLifecycleSkills calls /lifecycle (not /skills/lifecycle)
 */
async function mockSkillsSuccess(page: Page) {
  // Lifecycle endpoint is /api/v1/lifecycle
  await page.route("**/api/v1/lifecycle*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_LIFECYCLE_SKILLS),
    })
  )
  // Specific skill detail by name
  await page.route("**/api/v1/skills/filesystem*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_SKILL_DETAIL),
    })
  )
  // Skills list
  await page.route("**/api/v1/skills*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_SKILLS),
    })
  )
}

/** Mock all skills/lifecycle endpoints to return empty */
async function mockSkillsEmpty(page: Page) {
  await page.route("**/api/v1/lifecycle*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )
  await page.route("**/api/v1/skills*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )
}

/** Mock skills API to return a 500 error */
async function mockSkillsError(page: Page) {
  await page.route("**/api/v1/lifecycle*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
  await page.route("**/api/v1/skills*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
}

// ─── Page renders ─────────────────────────────────────────────────────────────

test.describe("Skill Explorer — page renders", () => {
  test("heading is always visible", async ({ page }) => {
    await page.goto("/skills")
    await expect(page.getByRole("heading", { name: /Skill Explorer/i })).toBeVisible()
  })

  test("Install Skill button is always visible", async ({ page }) => {
    await page.goto("/skills")
    await expect(page.getByRole("button", { name: /Install Skill/i })).toBeVisible()
  })

  test("search input is present", async ({ page }) => {
    await page.goto("/skills")
    const searchInput = page.locator('input[placeholder*="Search skills"]').first()
    await expect(searchInput).toBeVisible()
  })

  test("heading and Install button visible even on error", async ({ page }) => {
    await mockSkillsError(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")
    await expect(page.getByRole("heading", { name: /Skill Explorer/i })).toBeVisible()
    await expect(page.getByRole("button", { name: /Install Skill/i })).toBeVisible()
  })
})

// ─── Skills list loads ────────────────────────────────────────────────────────

test.describe("Skill Explorer — skills list loads", () => {
  test("renders skill cards when API returns data", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    // Wait for skill name to appear in a card
    await page.waitForSelector("text=filesystem", { timeout: 8000 })
    // Use exact match to avoid strict mode on multiple elements
    await expect(page.locator("span.font-medium").filter({ hasText: "filesystem" }).first()).toBeVisible()
    await expect(page.locator("span.font-medium").filter({ hasText: "web-browse" }).first()).toBeVisible()
  })

  test("shows skill count badge", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")
    // "X skills" span should appear
    await expect(page.locator("span").filter({ hasText: /skill/ }).first()).toBeVisible()
  })

  test("displays risk level badge on skill cards", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })
    await expect(page.getByText("HIGH").first()).toBeVisible()
  })

  test("shows loading skeleton while fetching", async ({ page }) => {
    // Add a delay to catch the skeleton state
    await page.route("**/api/v1/skills*", async (route) => {
      await new Promise((r) => setTimeout(r, 1000))
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILLS),
      })
    })
    await page.route("**/api/v1/lifecycle*", async (route) => {
      await new Promise((r) => setTimeout(r, 1000))
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_LIFECYCLE_SKILLS),
      })
    })
    await page.goto("/skills")
    // Skeleton/pulse should be visible during loading
    await expect(page.locator('[class*="animate-pulse"]').first()).toBeVisible({ timeout: 3000 })
    // After data loads, skeleton should disappear and real content should appear
    await expect(page.locator("span.font-medium").filter({ hasText: "filesystem" }).first()).toBeVisible({ timeout: 8000 })
  })
})

// ─── Search filtering ─────────────────────────────────────────────────────────

test.describe("Skill Explorer — search", () => {
  test("searching by name filters skill cards", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search skills"]').first()
    await searchInput.fill("filesystem")

    // web-browse skill name span should no longer be visible
    await expect(page.locator("span.font-medium").filter({ hasText: "web-browse" })).not.toBeVisible()
    // filesystem should still be visible
    await expect(page.locator("span.font-medium").filter({ hasText: "filesystem" }).first()).toBeVisible()
  })

  test("clearing search restores all skills", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search skills"]').first()
    await searchInput.fill("filesystem")
    await expect(page.locator("span.font-medium").filter({ hasText: "web-browse" })).not.toBeVisible()

    await searchInput.fill("")
    await expect(page.locator("span.font-medium").filter({ hasText: "web-browse" }).first()).toBeVisible()
  })

  test("searching for non-existent skill shows 'No skills match'", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    const searchInput = page.locator('input[placeholder*="Search skills"]').first()
    await searchInput.fill("zzznomatch999")
    await expect(page.getByText(/No skills match/i)).toBeVisible()
  })
})

// ─── Navigate to skill detail ─────────────────────────────────────────────────

test.describe("Skill Explorer — click skill → detail page", () => {
  test("clicking a skill card navigates to detail page", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    // Click the link inside the first skill card (links now use skill name)
    const skillLink = page.locator('a[href*="/skills/"]').first()
    await skillLink.click()

    // Should navigate to a skill detail page
    await page.waitForURL("**/skills/**")
    expect(page.url()).toMatch(/\/skills\//)
  })

  test("skill detail page shows Back to Skills link", async ({ page }) => {
    await page.route("**/api/v1/skills/filesystem*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILL_DETAIL),
      })
    )
    await page.route("**/api/v1/lifecycle*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) })
    )
    await page.route("**/api/v1/skills*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(MOCK_SKILLS) })
    )
    await page.goto("/skills/filesystem")
    // The detail page should render the back link when data loads
    await expect(page.getByText(/Back to Skills/i)).toBeVisible({ timeout: 8000 })
  })

  test("skill detail page shows error for unknown skill id", async ({ page }) => {
    await page.route("**/api/v1/skills/nonexistent-skill*", (route) =>
      route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Skill not found" }),
      })
    )
    await page.route("**/api/v1/lifecycle*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) })
    )
    await page.goto("/skills/nonexistent-skill")
    await page.waitForLoadState("networkidle")
    // Error message should show
    await expect(page.getByText(/not found|failed to load/i).first()).toBeVisible({ timeout: 8000 })
  })

  test("clicking a skill card opens the skill detail page without error", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")

    // Click the first skill card
    const firstCard = page.locator(".grid > div").first()
    await firstCard.waitFor({ timeout: 10000 })
    await firstCard.click()

    // Should navigate to /skills/<name> and show skill detail
    await page.waitForURL(/\/skills\/[^/]+$/, { timeout: 10000 })

    // Should NOT show error state
    await expect(page.getByText(/skill not found/i)).not.toBeVisible({ timeout: 5000 })
    await expect(page.getByText(/failed to load/i)).not.toBeVisible()

    // Should show skill detail content
    await expect(page.getByText(/risk score|trust|shell|injection/i).first()).toBeVisible({ timeout: 10000 })
  })

  test("skill detail URL contains skill name not a UUID", async ({ page }) => {
    await mockSkillsSuccess(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")

    const firstCard = page.locator(".grid > div").first()
    await firstCard.waitFor({ timeout: 10000 })
    await firstCard.click()

    await page.waitForURL(/\/skills\/[^/]+$/, { timeout: 10000 })

    const url = page.url()
    const slug = url.split("/skills/")[1]

    // Should be a human-readable name, not a UUID pattern
    expect(slug).not.toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/)
    expect(slug.length).toBeGreaterThan(0)
  })

  test("skill detail page renders capabilities section when data loads", async ({ page }) => {
    await page.route("**/api/v1/skills/filesystem*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILL_DETAIL),
      })
    )
    await page.route("**/api/v1/lifecycle*", (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) })
    )
    await page.goto("/skills/filesystem")
    // Skill name should appear in the heading
    await expect(page.getByText("filesystem").first()).toBeVisible({ timeout: 8000 })
    // Capabilities section should be rendered
    await expect(page.getByText(/Capabilities/i)).toBeVisible()
  })
})

// ─── Empty state ──────────────────────────────────────────────────────────────

test.describe("Skill Explorer — empty state", () => {
  test("shows 'No skills found' when both APIs return empty", async ({ page }) => {
    await mockSkillsEmpty(page)
    await page.goto("/skills")
    // Wait for loading to complete and empty state to render
    await page.waitForSelector("text=/No skills found/i", { timeout: 10000 })
    await expect(page.getByText(/No skills found/i)).toBeVisible()
  })

  test("Install Skill button visible in empty state", async ({ page }) => {
    await mockSkillsEmpty(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")
    await expect(page.getByRole("button", { name: /Install Skill/i })).toBeVisible()
  })
})

// ─── Protected skills ─────────────────────────────────────────────────────────

const MOCK_SYSTEM_LIFECYCLE_SKILLS = [
  {
    name: "filesystem",
    source: "system",
    path: "/opt/homebrew/lib/node_modules/openclaw/skills/filesystem",
    enabled: true,
    version: "1.2.0",
    installed_at: new Date(Date.now() - 86400_000).toISOString(),
    risk_level: "HIGH",
  },
  {
    name: "web-browse",
    source: "system",
    path: "/opt/homebrew/lib/node_modules/openclaw/skills/web-browse",
    enabled: true,
    version: "2.0.1",
    installed_at: new Date(Date.now() - 172800_000).toISOString(),
    risk_level: "MEDIUM",
  },
]

async function mockSystemSkills(page: Page) {
  await page.route("**/api/v1/lifecycle*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_SYSTEM_LIFECYCLE_SKILLS),
    })
  )
  await page.route("**/api/v1/skills*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_SKILLS),
    })
  )
}

test.describe("Skill Explorer — protected skills", () => {
  test("protected system skills show lock badge and no action buttons", async ({ page }) => {
    await mockSystemSkills(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    // All lifecycle skills have source=system → Protected badge should appear
    const protectedBadges = page.getByText("Protected")
    await expect(protectedBadges.first()).toBeVisible({ timeout: 10000 })

    // No Enable/Disable or Uninstall buttons should be visible
    await expect(page.getByRole("button", { name: /^Disable$/ })).not.toBeVisible()
    await expect(page.getByRole("button", { name: /^Enable$/ })).not.toBeVisible()
    await expect(page.getByRole("button", { name: /^Uninstall$/ })).not.toBeVisible()
  })

  test("skills page loads and displays skill cards", async ({ page }) => {
    await mockSystemSkills(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")
    await expect(page.locator(".grid > div").first()).toBeVisible({ timeout: 10000 })
  })
})

// ─── System skill confirm dialog ─────────────────────────────────────────────

test.describe("Skill Explorer — system skill confirm dialog", () => {
  async function mockSystemSkillsWithToggle(page: Page) {
    await page.route("**/api/v1/lifecycle**", (route) => {
      const method = route.request().method()
      const url = route.request().url()
      if (method === "POST" && (url.includes("/disable") || url.includes("/enable"))) {
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ok: true }),
        })
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SYSTEM_LIFECYCLE_SKILLS),
      })
    })
    await page.route("**/api/v1/skills*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILLS),
      })
    )
  }

  test("clicking Disable on a system skill opens ConfirmDialog, not native dialog", async ({ page }) => {
    await mockSystemSkillsWithToggle(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    // Listen for native dialog — it should NOT fire
    let nativeDialogFired = false
    page.on("dialog", () => { nativeDialogFired = true })

    const disableBtn = page.getByRole("button", { name: /Disable/ }).first()
    await disableBtn.click()

    // ConfirmDialog should appear with system skill warning
    await expect(page.getByText(/This is a system skill/i)).toBeVisible({ timeout: 3000 })
    expect(nativeDialogFired).toBe(false)
  })

  test("clicking Cancel in ConfirmDialog closes it without toggling", async ({ page }) => {
    await mockSystemSkillsWithToggle(page)
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    const disableBtn = page.getByRole("button", { name: /Disable/ }).first()
    await disableBtn.click()

    await expect(page.getByText(/This is a system skill/i)).toBeVisible({ timeout: 3000 })

    // Click Cancel
    await page.getByRole("button", { name: /Cancel/ }).click()

    // Dialog should close
    await expect(page.getByText(/This is a system skill/i)).not.toBeVisible()
  })

  test("clicking confirm button in ConfirmDialog triggers the toggle", async ({ page }) => {
    let toggleCalled = false
    await page.route("**/api/v1/lifecycle**", (route) => {
      const method = route.request().method()
      const url = route.request().url()
      if (method === "POST" && (url.includes("/disable") || url.includes("/enable"))) {
        toggleCalled = true
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ok: true }),
        })
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SYSTEM_LIFECYCLE_SKILLS),
      })
    })
    await page.route("**/api/v1/skills*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILLS),
      })
    )
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    const disableBtn = page.getByRole("button", { name: /Disable/ }).first()
    await disableBtn.click()

    await expect(page.getByText(/This is a system skill/i)).toBeVisible({ timeout: 3000 })

    // Click the confirm Disable button inside the dialog
    const confirmBtn = page.locator("[role=dialog] button").filter({ hasText: /Disable/ })
    await confirmBtn.click()

    // Dialog should close and API should have been called
    await expect(page.getByText(/This is a system skill/i)).not.toBeVisible({ timeout: 5000 })
    expect(toggleCalled).toBe(true)
  })

  test("non-system skills toggle immediately without confirm dialog", async ({ page }) => {
    let toggleCalled = false
    await page.route("**/api/v1/lifecycle**", (route) => {
      const method = route.request().method()
      const url = route.request().url()
      if (method === "POST" && (url.includes("/disable") || url.includes("/enable"))) {
        toggleCalled = true
        return route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ok: true }),
        })
      }
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_LIFECYCLE_SKILLS),
      })
    })
    await page.route("**/api/v1/skills*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILLS),
      })
    )
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    // filesystem is local source (not system), so toggle should fire immediately
    const disableBtn = page.getByRole("button", { name: /Disable/ }).first()
    await disableBtn.click()

    // No confirm dialog should appear
    await expect(page.getByText(/This is a system skill/i)).not.toBeVisible()
    expect(toggleCalled).toBe(true)
  })
})

// ─── Action error feedback ───────────────────────────────────────────────────

test.describe("Skill Explorer — action error feedback", () => {
  test("shows error banner when toggle fails with 403", async ({ page }) => {
    // Intercept ALL lifecycle API calls with method-aware routing
    await page.route("**/api/v1/lifecycle**", (route) => {
      const url = route.request().url()
      const method = route.request().method()

      // POST to disable/enable should return 403
      if (method === "POST" && (url.includes("/disable") || url.includes("/enable"))) {
        return route.fulfill({
          status: 403,
          contentType: "application/json",
          body: JSON.stringify({ detail: "Skill is in a protected path" }),
        })
      }

      // GET lifecycle list
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_LIFECYCLE_SKILLS),
      })
    })
    // Skills list
    await page.route("**/api/v1/skills*", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(MOCK_SKILLS),
      })
    )
    await page.goto("/skills")
    await page.waitForSelector("text=filesystem", { timeout: 8000 })

    // Click the Disable button on the first skill (filesystem is enabled)
    const disableBtn = page.getByRole("button", { name: /^Disable$/ }).first()
    await disableBtn.click()

    // Error banner should appear with the parsed API detail string (not raw JSON)
    await expect(page.getByText(/Skill is in a protected path/i).first()).toBeVisible({ timeout: 5000 })
  })
})

// ─── Install modal ────────────────────────────────────────────────────────────

test.describe("Skill Explorer — Install modal", () => {
  test("clicking Install Skill opens the modal", async ({ page }) => {
    await mockSkillsEmpty(page)
    await page.goto("/skills")
    await page.getByRole("button", { name: /Install Skill/i }).click()
    // Modal should appear — look for "From URL" tab
    await expect(page.getByText(/From URL/i)).toBeVisible({ timeout: 5000 })
  })

  test("modal can be closed with Escape key", async ({ page }) => {
    await mockSkillsEmpty(page)
    await page.goto("/skills")
    await page.getByRole("button", { name: /Install Skill/i }).click()
    await expect(page.getByText(/From URL/i)).toBeVisible({ timeout: 5000 })
    // Press Escape to close
    await page.keyboard.press("Escape")
    // Heading should still be visible after close
    await expect(page.getByRole("heading", { name: /Skill Explorer/i })).toBeVisible()
  })
})

// ─── Error state ──────────────────────────────────────────────────────────────

test.describe("Skill Explorer — error state", () => {
  test("shows error banner when API returns 500", async ({ page }) => {
    await mockSkillsError(page)
    await page.goto("/skills")
    await page.waitForSelector("div.text-red-400", { timeout: 8000 })
    await expect(page.locator("div.text-red-400").first()).toBeVisible()
  })

  test("error banner mentions 'Failed to load skills'", async ({ page }) => {
    await mockSkillsError(page)
    await page.goto("/skills")
    await page.waitForSelector("div.text-red-400", { timeout: 8000 })
    await expect(page.getByText(/Failed to load skills/i)).toBeVisible()
  })

  test("Install Skill button is still visible on error", async ({ page }) => {
    await mockSkillsError(page)
    await page.goto("/skills")
    await page.waitForLoadState("networkidle")
    await expect(page.getByRole("button", { name: /Install Skill/i })).toBeVisible()
  })
})
