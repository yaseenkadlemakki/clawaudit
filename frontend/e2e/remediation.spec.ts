import { test, expect, Page } from "@playwright/test"

// ─── Shared mock data ─────────────────────────────────────────────────────────

const MOCK_PROPOSALS = [
  {
    proposal_id: "prop-001",
    skill_name: "filesystem",
    check_id: "ADV-001",
    description: "Restrict shell execution permissions in the filesystem skill manifest.",
    impact: [
      "Skill will no longer be able to run arbitrary shell commands.",
      "Scoped shell operations will still work via allowed_commands list.",
    ],
    reversible: true,
    diff_preview: `--- a/filesystem.skill\n+++ b/filesystem.skill\n-shell_access: true\n+shell_access: false`,
  },
  {
    proposal_id: "prop-002",
    skill_name: "web-browse",
    check_id: "ADV-005",
    description: "Add domain allowlist to restrict outbound network calls.",
    impact: ["Skill will only be able to contact explicitly whitelisted domains."],
    reversible: true,
    diff_preview: `--- a/web-browse.skill\n+++ b/web-browse.skill\n+outbound_domains:\n+  - api.safe-example.com`,
  },
]

const MOCK_HISTORY = [
  {
    id: "hist-001",
    proposal_id: "prop-old-001",
    skill_name: "config-manager",
    check_id: "PERM-001",
    description: "Set config file permissions to 600.",
    status: "applied",
    applied_at: new Date(Date.now() - 86400_000).toISOString(),
    snapshot_path: "/backups/config-manager-20240101.snap",
    error: null,
  },
  {
    id: "hist-002",
    proposal_id: "prop-old-002",
    skill_name: "legacy-tool",
    check_id: "ADV-001",
    description: "Restricted shell access.",
    status: "rolled_back",
    applied_at: new Date(Date.now() - 172800_000).toISOString(),
    snapshot_path: "/backups/legacy-tool-20231231.snap",
    error: null,
  },
]

/** Mock proposals API with sample data */
async function mockProposalsSuccess(page: Page) {
  await page.route("**/api/v1/remediation/proposals*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_PROPOSALS),
    })
  )
}

/** Mock history API with sample data */
async function mockHistorySuccess(page: Page) {
  await page.route("**/api/v1/remediation/history*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MOCK_HISTORY),
    })
  )
}

/** Mock both APIs to return empty */
async function mockRemediationEmpty(page: Page) {
  await page.route("**/api/v1/remediation/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify([]),
    })
  )
}

/** Mock all remediation APIs to return 500 */
async function mockRemediationError(page: Page) {
  await page.route("**/api/v1/remediation/**", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ detail: "Internal server error" }),
    })
  )
}

// ─── Page renders ─────────────────────────────────────────────────────────────

test.describe("Remediation — page renders", () => {
  test("heading is always visible", async ({ page }) => {
    await page.goto("/remediation")
    await expect(page.getByRole("heading", { name: /Remediation/i })).toBeVisible()
  })

  test("subtitle / description text is visible", async ({ page }) => {
    await page.goto("/remediation")
    await expect(page.getByText(/Review and apply automated fixes/i)).toBeVisible({ timeout: 8000 })
  })

  test("Proposals and History tabs are rendered", async ({ page }) => {
    await page.goto("/remediation")
    await expect(page.getByRole("button", { name: /proposals/i })).toBeVisible({ timeout: 8000 })
    await expect(page.getByRole("button", { name: /history/i })).toBeVisible()
  })

  test("Proposals tab is active by default", async ({ page }) => {
    await page.goto("/remediation")
    // Active tab has border-primary class
    const proposalsTab = page.locator("button").filter({ hasText: /proposals/i })
    await expect(proposalsTab).toHaveClass(/border-primary/, { timeout: 8000 })
  })
})

// ─── Proposals section ────────────────────────────────────────────────────────

test.describe("Remediation — proposals section", () => {
  test("shows proposal cards when API returns data", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    // Proposal descriptions should be visible
    await expect(page.getByText(/Restrict shell execution permissions/i)).toBeVisible({ timeout: 8000 })
    await expect(page.getByText(/Add domain allowlist/i)).toBeVisible()
  })

  test("each proposal shows check_id badge", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForSelector('[class*="font-mono"]', { timeout: 8000 })
    await expect(page.getByText("ADV-001")).toBeVisible()
    await expect(page.getByText("ADV-005")).toBeVisible()
  })

  test("each proposal shows skill name", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    // Use the span.font-medium selector to target skill name spans specifically
    await expect(page.locator("span.font-medium").filter({ hasText: "filesystem" }).first()).toBeVisible({ timeout: 8000 })
    await expect(page.locator("span.font-medium").filter({ hasText: "web-browse" }).first()).toBeVisible()
  })

  test("Apply Fix button is visible for each proposal", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    const applyBtns = page.getByRole("button", { name: /Apply Fix/i })
    expect(await applyBtns.count()).toBeGreaterThanOrEqual(2)
  })

  test("proposals count badge appears on tab when proposals exist", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    // The tab should show a count badge like "2"
    const proposalsTabArea = page.locator("button").filter({ hasText: /proposals/i })
    await expect(proposalsTabArea.getByText("2")).toBeVisible({ timeout: 8000 })
  })

  test("'Show diff' button toggles diff preview for reversible proposals", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    const showDiffBtn = page.getByText(/Show diff/i).first()
    await expect(showDiffBtn).toBeVisible({ timeout: 8000 })
    await showDiffBtn.click()

    // Diff content should now be visible
    await expect(page.getByText("Hide diff")).toBeVisible()
    // The diff preview should contain some content
    const diffPre = page.locator("pre").first()
    await expect(diffPre).toBeVisible()
  })

  test("impact list is shown for proposals with impact", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    await expect(page.getByText(/Impact/i).first()).toBeVisible({ timeout: 8000 })
    await expect(page.getByText(/Skill will no longer be able to run/i)).toBeVisible()
  })

  test("reversible tag shown for reversible proposals", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    await expect(page.getByText(/reversible/i).first()).toBeVisible({ timeout: 8000 })
  })
})

// ─── Apply confirmation dialog ────────────────────────────────────────────────

test.describe("Remediation — apply confirmation dialog", () => {
  test("clicking Apply Fix opens confirmation dialog", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    const firstApplyBtn = page.getByRole("button", { name: /Apply Fix/i }).first()
    await firstApplyBtn.click()

    // Confirmation dialog must appear
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 })
    await expect(page.getByRole("dialog")).toBeVisible()
    await expect(page.getByText(/Confirm Remediation/i)).toBeVisible()
  })

  test("confirmation dialog shows proposal description inside dialog", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    await page.getByRole("button", { name: /Apply Fix/i }).first().click()
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 })

    // Target the description inside the dialog specifically to avoid strict mode violation
    const dialog = page.getByRole("dialog")
    await expect(dialog.getByText(/Restrict shell execution permissions/i)).toBeVisible()
  })

  test("Cancel button closes the confirmation dialog", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    await page.getByRole("button", { name: /Apply Fix/i }).first().click()
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 })

    const cancelBtn = page.getByRole("button", { name: /Cancel/i })
    await cancelBtn.click()
    await expect(page.getByRole("dialog")).not.toBeVisible()
  })

  test("Escape key closes the confirmation dialog", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    await page.getByRole("button", { name: /Apply Fix/i }).first().click()
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 })
    await expect(page.getByRole("dialog")).toBeVisible()

    await page.keyboard.press("Escape")
    await expect(page.getByRole("dialog")).not.toBeVisible()
  })

  test("snapshot note shown for reversible proposals in dialog", async ({ page }) => {
    await mockProposalsSuccess(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")

    await page.getByRole("button", { name: /Apply Fix/i }).first().click()
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 })

    await expect(page.getByText(/snapshot will be taken/i)).toBeVisible()
  })
})

// ─── History section ──────────────────────────────────────────────────────────

test.describe("Remediation — history section (guidance)", () => {
  test("clicking History tab shows history section", async ({ page }) => {
    await mockProposalsSuccess(page)
    await mockHistorySuccess(page)
    await page.goto("/remediation")

    const historyTab = page.getByRole("button", { name: /history/i })
    await historyTab.click()

    // Wait for history to load — looking for a history item description or the "Loading history" text
    // Note: status values "applied"/"rolled_back" are shown as icons not text
    await page.waitForSelector(
      'text="Set config file permissions to 600.", text="Loading history…", text="No remediations applied yet."',
      { timeout: 8000 }
    ).catch(() => {})

    // The history section rendered if we can find the history item description or empty state
    const hasItems = await page.getByText(/Set config file permissions|No remediations applied yet|Loading history/i).count() > 0
    expect(hasItems).toBeTruthy()
  })

  test("history items appear when API returns data", async ({ page }) => {
    await mockProposalsSuccess(page)
    await mockHistorySuccess(page)
    await page.goto("/remediation")

    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForLoadState("networkidle")

    // History items should be visible — target the skill name span specifically
    await expect(
      page.locator("span.font-medium").filter({ hasText: "config-manager" }).first()
    ).toBeVisible({ timeout: 8000 })
    await expect(
      page.locator("span.font-medium").filter({ hasText: "legacy-tool" }).first()
    ).toBeVisible()
  })

  test("history items show their descriptions", async ({ page }) => {
    await mockProposalsSuccess(page)
    await mockHistorySuccess(page)
    await page.goto("/remediation")

    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForLoadState("networkidle")

    await expect(page.getByText(/Set config file permissions/i)).toBeVisible({ timeout: 8000 })
    await expect(page.getByText(/Restricted shell access/i)).toBeVisible()
  })

  test("history items show check_id", async ({ page }) => {
    await mockProposalsSuccess(page)
    await mockHistorySuccess(page)
    await page.goto("/remediation")

    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForLoadState("networkidle")

    await expect(page.getByText("PERM-001")).toBeVisible({ timeout: 8000 })
  })

  test("empty history message shown when no history exists", async ({ page }) => {
    await mockRemediationEmpty(page)
    await page.goto("/remediation")

    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForLoadState("networkidle")

    await expect(page.getByText(/No remediations applied yet/i)).toBeVisible({ timeout: 8000 })
  })

  test("snapshot path displayed for applied remediations", async ({ page }) => {
    await mockProposalsSuccess(page)
    await mockHistorySuccess(page)
    await page.goto("/remediation")

    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForLoadState("networkidle")

    // Snapshot file basename should be shown
    await expect(page.getByText(/config-manager-20240101\.snap/i)).toBeVisible({ timeout: 8000 })
  })
})

// ─── Empty state ──────────────────────────────────────────────────────────────

test.describe("Remediation — empty state", () => {
  test("shows 'No remediations needed' when proposals list is empty", async ({ page }) => {
    await mockRemediationEmpty(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    await expect(page.getByText(/No remediations needed/i)).toBeVisible({ timeout: 8000 })
  })

  test("empty state shows all skills are within bounds message", async ({ page }) => {
    await mockRemediationEmpty(page)
    await page.goto("/remediation")
    await page.waitForLoadState("networkidle")
    await expect(
      page.getByText(/All scanned skills are within acceptable security bounds/i)
    ).toBeVisible({ timeout: 8000 })
  })

  test("empty state is NOT shown alongside error", async ({ page }) => {
    await mockRemediationError(page)
    await page.goto("/remediation")
    await page.waitForSelector(".text-red-400", { timeout: 8000 })
    await expect(page.getByText(/No remediations needed/i)).not.toBeVisible()
  })
})

// ─── Error state ──────────────────────────────────────────────────────────────

test.describe("Remediation — error state", () => {
  test("shows error banner when proposals API returns 500", async ({ page }) => {
    await mockRemediationError(page)
    await page.goto("/remediation")
    await page.waitForSelector(".text-red-400", { timeout: 8000 })
    await expect(page.locator(".text-red-400").first()).toBeVisible()
  })

  test("error banner says 'Failed to load proposals'", async ({ page }) => {
    await mockRemediationError(page)
    await page.goto("/remediation")
    await page.waitForSelector(".text-red-400", { timeout: 8000 })
    await expect(page.getByText(/Failed to load proposals/i)).toBeVisible()
  })

  test("heading remains visible on API error", async ({ page }) => {
    await mockRemediationError(page)
    await page.goto("/remediation")
    await expect(page.getByRole("heading", { name: /Remediation/i })).toBeVisible()
  })

  test("history tab shows error when history API returns 500", async ({ page }) => {
    await mockRemediationEmpty(page)
    await page.route("**/api/v1/remediation/history*", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ detail: "History not available" }),
      })
    )

    await page.goto("/remediation")
    await page.getByRole("button", { name: /history/i }).click()
    await page.waitForSelector(".text-red-400", { timeout: 8000 })
    await expect(page.getByText(/Failed to load history/i)).toBeVisible()
  })
})
