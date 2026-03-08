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
      await page.waitForResponse((resp) => resp.url().includes("/api/v1/"))
    }

    console.log("Authenticated requests:", authRequests.length)
    console.log("Unauthenticated requests:", unauthRequests)
    expect(unauthRequests).toHaveLength(0)
  })

  test("401 responses show error banners not silent failures", async ({ page }) => {
    // Intercept all API calls and force 401 responses
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )

    const pages = [
      { path: "/dashboard", errorSelector: ".border-red-500" },
      { path: "/skills", errorSelector: ".border-red-500, .text-red-400" },
      { path: "/findings", errorSelector: ".border-red-500" },
      { path: "/remediation", errorSelector: ".border-red-500" },
      { path: "/hooks", errorSelector: ".border-red-500" },
    ]
    for (const { path, errorSelector } of pages) {
      await page.goto(path)
      // Wait for error banner to appear
      await expect(page.locator(errorSelector).first()).toBeVisible({ timeout: 5000 })
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
    await page.waitForResponse((resp) => resp.url().includes("/api/v1/"))
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
    await page.waitForResponse((resp) => resp.url().includes("/hooks/"))
    expect(hooksRequestAuthenticated).toBe(true)
  })

  test("Findings Explorer shows error banner on API failure", async ({ page }) => {
    // Force 401 to guarantee error state
    await page.route("**/api/v1/**", (route) =>
      route.fulfill({ status: 401, body: "Unauthorized" })
    )
    await page.goto("/findings")
    await expect(page.locator(".border-red-500").first()).toBeVisible({ timeout: 5000 })
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
    await expect(page.locator(".border-red-500").first()).toBeVisible({ timeout: 5000 })

    // Stat cards should show "—" not "0"
    const statValues = await page.locator(".text-2xl").allTextContents()
    const allZeros = statValues.every((v) => v.trim() === "0")
    expect(allZeros).toBe(false) // at least one should show "—"
  })
})
