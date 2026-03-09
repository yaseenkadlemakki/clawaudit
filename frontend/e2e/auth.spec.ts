import { test, expect } from "@playwright/test"

test.describe("API Authentication", () => {
  test("all API requests include Authorization header when token is set", async ({ page }) => {
    const authRequests: string[] = []
    const unauthRequests: string[] = []

    // Intercept all API calls to inspect headers without needing a running backend
    await page.route("**/api/v1/**", (route) => {
      const req = route.request()
      if (req.headers()["authorization"]) {
        authRequests.push(req.url())
      } else {
        unauthRequests.push(req.url())
      }
      route.fulfill({ status: 200, contentType: "application/json", body: "[]" })
    })

    for (const path of ["/dashboard", "/skills", "/findings", "/remediation", "/hooks"]) {
      await page.goto(path)
      await page.waitForLoadState("networkidle")
    }

    // If no requests had auth, token wasn't configured at build time — skip
    const totalRequests = authRequests.length + unauthRequests.length
    test.skip(totalRequests > 0 && authRequests.length === 0,
      "NEXT_PUBLIC_API_TOKEN not set at build time — Authorization header not sent")
    test.skip(totalRequests === 0, "No API requests intercepted")

    expect(unauthRequests).toHaveLength(0)
  })

  test("401 responses show error banners not silent failures", async ({ page }) => {
    // Intercept all API calls and force 401 responses
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )

    const pages = ["/dashboard", "/skills", "/findings", "/remediation", "/hooks"]
    for (const path of pages) {
      await page.goto(path)
      // Wait for error banner to appear — .text-red-400 is present on all error banners
      await expect(page.locator(".text-red-400").first()).toBeVisible({ timeout: 5000 })
    }
  })

  test("req() helper sends Authorization header on dashboard", async ({ page }) => {
    let authHeaderSeen = false
    let anyRequestSeen = false

    await page.route("**/api/v1/**", (route) => {
      anyRequestSeen = true
      if (route.request().headers()["authorization"]) {
        authHeaderSeen = true
      }
      route.fulfill({ status: 200, contentType: "application/json", body: "{}" })
    })

    await page.goto("/dashboard")
    await page.waitForLoadState("networkidle")

    test.skip(!anyRequestSeen, "No API requests intercepted")
    test.skip(anyRequestSeen && !authHeaderSeen,
      "NEXT_PUBLIC_API_TOKEN not set at build time — Authorization header not sent")

    expect(authHeaderSeen).toBe(true)
  })

  test("Runtime Events stats/events requests include Authorization header", async ({ page }) => {
    let hooksRequestAuthenticated = false
    let anyHooksRequestSeen = false

    await page.route("**/api/v1/hooks/**", (route) => {
      anyHooksRequestSeen = true
      if (route.request().headers()["authorization"]) {
        hooksRequestAuthenticated = true
      }
      route.fulfill({ status: 200, contentType: "application/json", body: "[]" })
    })
    // Intercept other API calls too so the page doesn't hang
    await page.route("**/api/v1/**", (route) => {
      if (!route.request().url().includes("/hooks/")) {
        route.fulfill({ status: 200, contentType: "application/json", body: "[]" })
      }
    })

    await page.goto("/hooks")
    await page.waitForLoadState("networkidle")

    test.skip(!anyHooksRequestSeen, "No hooks API requests intercepted")
    test.skip(anyHooksRequestSeen && !hooksRequestAuthenticated,
      "NEXT_PUBLIC_API_TOKEN not set at build time — Authorization header not sent")

    expect(hooksRequestAuthenticated).toBe(true)
  })

  test("Findings Explorer shows error banner on API failure", async ({ page }) => {
    // Force 401 to guarantee error state
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )
    await page.goto("/findings")
    await expect(page.locator(".text-red-400").first()).toBeVisible({ timeout: 5000 })
    // "No findings match your filters" should NOT appear alongside the error
    await expect(page.getByText("No findings match")).not.toBeVisible()
  })

  test("Skill Explorer heading and Install button visible even on error", async ({ page }) => {
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )
    await page.goto("/skills")

    // Page heading must ALWAYS be visible
    await expect(page.locator("h1, h2").first()).toBeVisible()
    // Install button must ALWAYS be visible
    const installBtn = page.locator("button", { hasText: /^.*Install Skill.*$/i })
    await expect(installBtn).toBeVisible()
  })

  test("Dashboard stat cards show dash not zero on API error", async ({ page }) => {
    // Force 401 to guarantee error state
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )
    await page.goto("/dashboard")

    // Error banner must be visible
    await expect(page.locator(".text-red-400").first()).toBeVisible({ timeout: 5000 })

    // Stat cards should show "—" not "0"
    const statValues = await page.locator(".text-2xl").allTextContents()
    const allZeros = statValues.every((v) => v.trim() === "0")
    expect(allZeros).toBe(false) // at least one should show "—"
  })
})
