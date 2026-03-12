import { test, expect, type Page } from "@playwright/test"

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function waitForApi(page: Page) {
  await page.waitForLoadState("networkidle")
}

// ─── 1. Dashboard loads and InvestigationPanel section is present ─────────────

test.describe("InvestigationPanel — Dashboard integration", () => {
  test("1. Dashboard loads and InvestigationPanel section is present", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const panel = page.locator('[data-testid="investigation-panel"]')
    await expect(panel).toBeVisible({ timeout: 10000 })
  })

  // ─── 2. Panel is collapsed by default (chat input not visible) ────────────

  test("2. Panel is collapsed by default — chat textarea not visible", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    // The textarea inside the panel should not be rendered when collapsed
    const panel = page.locator('[data-testid="investigation-panel"]')
    await expect(panel).toBeVisible()

    const textarea = panel.locator("textarea")
    await expect(textarea).not.toBeVisible()
  })

  // ─── 3. Clicking expand toggle shows the panel content ───────────────────

  test("3. Clicking expand toggle reveals panel content", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // The panel body should now be visible
    const textarea = page.locator('[data-testid="investigation-panel"] textarea')
    await expect(textarea).toBeVisible({ timeout: 5000 })
  })

  // ─── 4. When expanded: suggested questions visible ────────────────────────

  test("4. When expanded: suggested questions are visible", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Suggested questions are rendered as buttons in a grid
    const suggestionBtns = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    })
    await expect(suggestionBtns.first()).toBeVisible({ timeout: 5000 })
    expect(await suggestionBtns.count()).toBeGreaterThanOrEqual(3)
  })

  // ─── 5. When expanded: OpenClaw/BYOLLM toggle buttons visible ────────────

  test("5. When expanded: OpenClaw and BYOLLM toggle buttons are visible", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    await expect(page.locator('[data-testid="investigation-panel"]').getByText("OpenClaw")).toBeVisible()
    await expect(page.locator('[data-testid="investigation-panel"]').getByText("BYOLLM")).toBeVisible()
  })

  // ─── 6. When expanded: chat input (textarea) visible ─────────────────────

  test("6. When expanded: chat input textarea is visible", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    const textarea = page.locator('[data-testid="investigation-panel"] textarea')
    await expect(textarea).toBeVisible({ timeout: 5000 })
    await expect(textarea).toHaveAttribute("placeholder", /Ask about your security scan/)
  })

  // ─── 7. Submit a suggested question → sends request ──────────────────────

  test("7. Clicking a suggested question sends a request and shows response or error", async ({ page }) => {
    // Mock the chat endpoint
    await page.route("**/api/v1/chat", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ answer: "Mock response: no shell-execution skills found." }),
      })
    )

    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Click the first suggested question
    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()

    // Wait for mock response
    await page.waitForLoadState("networkidle")
    await expect(page.getByText("Mock response: no shell-execution skills found.")).toBeVisible({ timeout: 10000 })
  })

  // ─── 8. "Investigation" link is NOT in the sidebar nav ───────────────────

  test('8. "Investigation" nav link is not present in the sidebar', async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    const investigationLink = page.getByRole("link", { name: "Investigation" })
    await expect(investigationLink).not.toBeVisible()
  })

  // ─── 9. /chat route loads successfully (smoke test) ──────────────────────

  test("9. /chat route loads successfully", async ({ page }) => {
    await page.goto("/chat")
    await waitForApi(page)

    // Should not be a 404 — panel should be visible
    const panel = page.locator('[data-testid="investigation-panel"]')
    await expect(panel).toBeVisible({ timeout: 10000 })
  })

  // ─── 10. InvestigationPanel renders on /chat page ────────────────────────

  test("10. InvestigationPanel on /chat renders expanded by default", async ({ page }) => {
    await page.goto("/chat")
    await waitForApi(page)

    // On /chat page defaultExpanded=true so textarea should be immediately visible
    const textarea = page.locator('[data-testid="investigation-panel"] textarea')
    await expect(textarea).toBeVisible({ timeout: 10000 })

    // Security Investigation heading should be visible
    await expect(page.getByRole("heading", { name: /Security Investigation/i })).toBeVisible()
  })
})
