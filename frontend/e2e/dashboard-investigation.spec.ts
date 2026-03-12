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
    expect(await suggestionBtns.count()).toBeGreaterThanOrEqual(6)
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

  // ─── 11. BYOLLM mode toggle shows API key input ───────────────────────────

  test("11. BYOLLM mode toggle reveals API key input field", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    // Expand the panel first
    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Click BYOLLM mode button
    const byollmBtn = page.locator('[data-testid="investigation-panel"]').getByText("BYOLLM")
    await byollmBtn.click()

    // API key password input should now be visible
    const apiKeyInput = page.locator('[data-testid="investigation-panel"] input[type="password"]')
    await expect(apiKeyInput).toBeVisible({ timeout: 5000 })
    await expect(apiKeyInput).toHaveAttribute("placeholder", /Anthropic API key/i)

    // Switching back to OpenClaw should hide the API key input
    const openclawBtn = page.locator('[data-testid="investigation-panel"]').getByText("OpenClaw")
    await openclawBtn.click()
    await expect(apiKeyInput).not.toBeVisible()
  })

  // ─── 12. Empty state message visible when no messages ────────────────────

  test("12. Empty state message is visible when no messages have been sent", async ({ page }) => {
    await page.goto("/dashboard")
    await waitForApi(page)

    // Expand the panel
    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // The empty-state text should be visible before any messages are sent
    await expect(
      page.getByText(/Run a Full Audit first to get meaningful answers/i)
    ).toBeVisible({ timeout: 5000 })
  })

  // ─── 13. Chat request Authorization header behaviour ─────────────────────

  test("13. chat request Authorization header is handled correctly", async ({ page }) => {
    let capturedAuthHeader: string | undefined

    // Intercept the chat API call so the test is self-contained
    await page.route("**/api/v1/chat", async (route) => {
      capturedAuthHeader = route.request().headers()["authorization"]
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ answer: "Test response", mode: "openclaw", context_used: {} }),
      })
    })

    await page.goto("/dashboard")
    await waitForApi(page)

    // Expand the panel
    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Click the first suggested question
    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()

    // Wait for the mocked response to appear in the chat
    await page.waitForSelector("text=Test response", { timeout: 10000 })

    // NEXT_PUBLIC_API_TOKEN is inlined into the JS bundle at build time.
    // - When configured: Authorization header must be "Bearer <token>".
    // - When not configured (empty string → falsy): header must be absent.
    //   This is the CORRECT behaviour — the conditional spread
    //   `...(API_TOKEN ? { Authorization: \`Bearer \${API_TOKEN}\` } : {})`
    //   intentionally omits the header when no token is set.
    const configuredToken = process.env.NEXT_PUBLIC_API_TOKEN ?? ""
    if (configuredToken) {
      expect(capturedAuthHeader).toMatch(/^Bearer .+/)
    } else {
      // No token configured: Authorization header should NOT be sent
      expect(capturedAuthHeader).toBeUndefined()
    }
  })

  // ─── 14. 503 gateway unavailable shows yellow warning banner ─────────────

  test("14. shows gateway unavailable banner when API returns 503", async ({ page }) => {
    await page.route("**/api/v1/chat", route =>
      route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ detail: "OpenClaw gateway unavailable" }),
      })
    )

    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Click a suggested question to trigger the 503
    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()

    // Wait for the gateway unavailable banner text
    await expect(page.getByText(/OpenClaw gateway unavailable\. Switch to BYOLLM mode/)).toBeVisible({ timeout: 10000 })
    // Banner should have the Switch to BYOLLM button
    const switchBtn = page.locator('[data-testid="investigation-panel"] button').filter({ hasText: /Switch to BYOLLM/ })
    await expect(switchBtn).toBeVisible()
  })

  // ─── 15. "Switch to BYOLLM →" button switches mode ────────────────────────

  test("15. Switch to BYOLLM button sets mode to byollm", async ({ page }) => {
    await page.route("**/api/v1/chat", route =>
      route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ detail: "OpenClaw gateway unavailable" }),
      })
    )

    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()

    // Wait for banner
    await expect(page.getByText(/OpenClaw gateway unavailable\. Switch to BYOLLM mode/)).toBeVisible({ timeout: 10000 })

    // Click Switch to BYOLLM
    const switchBtn = page.locator('[data-testid="investigation-panel"] button').filter({ hasText: /Switch to BYOLLM/ })
    await switchBtn.click()

    // API key input should now be visible
    const apiKeyInput = page.locator('[data-testid="investigation-panel"] input[type="password"]')
    await expect(apiKeyInput).toBeVisible({ timeout: 5000 })
    await expect(apiKeyInput).toHaveAttribute("placeholder", /Anthropic API key/i)

    // Banner should be dismissed (switch button gone)
    await expect(switchBtn).not.toBeVisible()
  })

  // ─── 16. Conversation history is sent with subsequent messages ─────────────

  test("16. sends conversation history with subsequent messages", async ({ page }) => {
    const requestBodies: Array<{ question: string; history?: unknown[] }> = []

    await page.route("**/api/v1/chat", async route => {
      const body = route.request().postDataJSON()
      requestBodies.push(body)
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ answer: `Answer to: ${body.question}`, mode: "openclaw", context_used: {} }),
      })
    })

    await page.goto("/dashboard")
    await waitForApi(page)

    const toggleBtn = page.locator('[aria-label="Toggle investigation panel"]').first()
    await toggleBtn.click()

    // Send first question via suggested question button
    const firstSuggestion = page.locator('[data-testid="investigation-panel"] button').filter({
      hasText: /shell execution|critical findings|unknown publishers|policies failed|external domains|supply chain/i,
    }).first()
    await firstSuggestion.click()
    await expect(page.getByText(/Answer to:/)).toBeVisible({ timeout: 10000 })

    // Send second question via textarea
    const textarea = page.locator('[data-testid="investigation-panel"] textarea')
    await textarea.fill("How do I fix them?")
    await textarea.press("Enter")
    await expect(page.getByText(/Answer to: How do I fix them/)).toBeVisible({ timeout: 10000 })

    // Second request should include history from the first exchange
    expect(requestBodies.length).toBeGreaterThanOrEqual(2)
    const secondRequest = requestBodies[1]
    expect(secondRequest.history).toBeDefined()
    expect(Array.isArray(secondRequest.history)).toBe(true)
    expect((secondRequest.history as unknown[]).length).toBeGreaterThan(0)
  })
})
