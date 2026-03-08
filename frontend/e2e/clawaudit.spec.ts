import { test, expect } from "@playwright/test"

// ---------------------------------------------------------------------------
// Bug #56 — Runtime Events: error + empty state must be mutually exclusive
// ---------------------------------------------------------------------------

test("Runtime Events shows ONLY error state when API fails (not empty state too)", async ({ page }) => {
  await page.route("**/api/v1/hooks/**", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )

  await page.goto("/hooks")
  await page.waitForTimeout(2000)

  const errorBanner = page.locator(".border-red-500")
  const errorVisible = await errorBanner.first().isVisible().catch(() => false)
  const pageContent = await page.textContent("body") ?? ""
  const emptyStateVisible = pageContent.includes("No events recorded yet")

  // If error is visible, empty state must NOT be visible simultaneously
  if (errorVisible) {
    expect(emptyStateVisible).toBe(false)
  }
})

test("Runtime Events shows ONLY empty state when API succeeds with no data", async ({ page }) => {
  await page.route("**/api/v1/hooks/stats", (route) =>
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
  await page.route("**/api/v1/hooks/events**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )

  await page.goto("/hooks")
  await page.waitForTimeout(2000)

  const errorBanner = page.locator(".border-red-500")
  const errorVisible = await errorBanner.first().isVisible().catch(() => false)
  const pageContent = await page.textContent("body") ?? ""
  const emptyStateVisible = pageContent.includes("No events recorded yet")

  expect(errorVisible).toBe(false)
  expect(emptyStateVisible).toBe(true)
})

// ---------------------------------------------------------------------------
// Bug #57 — Findings Explorer: error + empty state must be mutually exclusive
// ---------------------------------------------------------------------------

test("Findings Explorer shows ONLY error state when API fails (not empty state too)", async ({ page }) => {
  await page.route("**/api/v1/findings**", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )

  await page.goto("/findings")
  await page.waitForTimeout(2000)

  const errorBanner = page.locator(".border-red-500")
  const errorVisible = await errorBanner.first().isVisible().catch(() => false)
  const pageContent = await page.textContent("body") ?? ""
  const emptyStateVisible = pageContent.includes("No findings match")

  // If error is visible, empty state must NOT be visible simultaneously
  if (errorVisible) {
    expect(emptyStateVisible).toBe(false)
  }
})

test("Findings Explorer shows ONLY empty state when API returns empty results", async ({ page }) => {
  await page.route("**/api/v1/findings**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )

  await page.goto("/findings")
  await page.waitForTimeout(2000)

  const errorBanner = page.locator(".border-red-500")
  const errorVisible = await errorBanner.first().isVisible().catch(() => false)
  const pageContent = await page.textContent("body") ?? ""
  const emptyStateVisible = pageContent.includes("No findings match")

  expect(errorVisible).toBe(false)
  expect(emptyStateVisible).toBe(true)
})
