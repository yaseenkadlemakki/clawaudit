import { test, expect } from '@playwright/test';

test.describe('Static asset serving smoke test', () => {
  test('homepage loads without 404 on static chunks', async ({ page }) => {
    const failedRequests: string[] = [];

    page.on('response', response => {
      if (response.url().includes('/_next/static/') && response.status() >= 400) {
        failedRequests.push(`${response.status()} ${response.url()}`);
      }
    });

    await page.goto('/');
    await page.waitForLoadState('domcontentloaded');

    expect(failedRequests,
      `Static chunks returned errors: ${failedRequests.join(', ')}`
    ).toHaveLength(0);
  });

  test('_next/static directory is accessible via page-sourced chunk URL', async ({ page }) => {
    // Load the page and extract a static chunk URL directly from the DOM.
    // This avoids hardcoding a content-hashed filename that changes every build.
    await page.goto('/');
    await page.waitForLoadState('domcontentloaded');

    const chunkUrl = await page.evaluate(() => {
      // Find any loaded <script src="/_next/static/..."> tag
      const scripts = Array.from(document.querySelectorAll<HTMLScriptElement>('script[src*="/_next/static/"]'));
      return scripts.length > 0 ? scripts[0].src : null;
    });

    // If no static chunk scripts are found, the page may be fully static — skip gracefully
    if (!chunkUrl) {
      test.skip(true, 'No /_next/static/ script tags found — page may be fully static');
      return;
    }

    const response = await page.request.get(chunkUrl, { failOnStatusCode: false });
    // Should be 200 (found) not 404 (missing)
    expect(response.status(), `Static chunk at ${chunkUrl} returned ${response.status()}`).not.toBe(404);
  });
});
