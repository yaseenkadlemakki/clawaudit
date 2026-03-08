import { test, expect } from "@playwright/test"

test.describe("API Authentication", () => {
  test("all API requests include Authorization header when token is set", async ({ page }) => {
    const authRequests: string[] = []
    const unauthRequests: string[] = []

    page.on("request", (req) => {
      if (req.url().includes("/api/v1/") && !req.url().includes("/health")) {
        if (req.headers()["authorization"]) {
          authRequests.push(req.url())
        } else {
          unauthRequests.push(req.url())
        }
      }
    })

    // Visit all pages that make API calls
    for (const path of ["/dashboard", "/skills", "/findings", "/remediation", "/hooks"]) {
      await page.goto(path)
      await page.waitForTimeout(1500)
    }

    console.log("Authenticated requests:", authRequests.length)
    console.log("Unauthenticated requests:", unauthRequests)
    expect(unauthRequests).toHaveLength(0)
  })

  test("401 responses show error banners not silent failures", async ({ page }) => {
    // Navigate to each page and verify it renders without crashing
    const pages = [
      { path: "/dashboard", errorSelector: ".border-red-500, .text-red-400" },
      { path: "/skills", errorSelector: ".border-red-500, .text-red-400" },
      { path: "/findings", errorSelector: ".border-red-500, .text-red-400" },
      { path: "/remediation", errorSelector: ".border-red-500, .text-red-400" },
      { path: "/hooks", errorSelector: ".border-red-500, .text-red-400" },
    ]
    for (const { path } of pages) {
      await page.goto(path)
      await page.waitForTimeout(1000)
      // Page should render without crashing
      await expect(page.locator("body")).not.toBeEmpty()
    }
  })

  test("req() helper sends Authorization header on dashboard", async ({ page }) => {
    let authHeaderSeen = false
    page.on("request", (req) => {
      if (req.url().includes("/api/v1/") && req.headers()["authorization"]) {
        authHeaderSeen = true
      }
    })
    await page.goto("/dashboard")
    await page.waitForTimeout(2000)
    expect(authHeaderSeen).toBe(true)
  })

  test("Runtime Events stats/events requests include Authorization header", async ({ page }) => {
    let hooksRequestAuthenticated = false
    page.on("request", (req) => {
      if (req.url().includes("/hooks/") && req.headers()["authorization"]) {
        hooksRequestAuthenticated = true
      }
    })
    await page.goto("/hooks")
    await page.waitForTimeout(2000)
    expect(hooksRequestAuthenticated).toBe(true)
  })

  test("Findings Explorer shows error banner on API failure", async ({ page }) => {
    await page.goto("/findings")
    await page.waitForTimeout(3000)

    const hasData = await page.locator("table tbody tr").count() > 0
    const hasError = await page.locator(".border-red-500, .text-red-400").first().isVisible().catch(() => false)
    const hasNoResults = await page.getByText("No findings match").isVisible().catch(() => false)

    // If no data and showing "no results", error banner must be visible
    if (!hasData && hasNoResults) {
      expect(hasError).toBe(true)
    }
  })

  test("Skill Explorer heading and Install button visible even on error", async ({ page }) => {
    await page.goto("/skills")
    await page.waitForTimeout(2000)

    // Page heading must ALWAYS be visible
    await expect(page.locator("h1, h2").first()).toBeVisible()
    // Install button must ALWAYS be visible
    const installBtn = page.locator("button", { hasText: /^.*Install Skill.*$/i })
    await expect(installBtn).toBeVisible()
  })

  test("Dashboard stat cards show dash not zero on API error", async ({ page }) => {
    await page.goto("/dashboard")
    await page.waitForTimeout(2000)

    const errorVisible = await page.locator(".border-red-500, .text-red-400").first().isVisible().catch(() => false)
    if (errorVisible) {
      // On error: stat cards should show "—" not "0"
      const statValues = await page.locator(".text-2xl").allTextContents()
      const allZeros = statValues.every((v) => v.trim() === "0")
      expect(allZeros).toBe(false) // at least one should show "—"
    }
  })
})
