// Copyright (c) 2026 Frank Currie (frank@sfle.ca)
import { test, expect } from '@playwright/test';

test('deployment validation - basic elements and assets', async ({ page }, testInfo) => {
  const failedRequests = [];
  const consoleErrors = [];

  // Track failed requests
  page.on('requestfailed', request => {
    failedRequests.push(`${request.url()}: ${request.failure().errorText}`);
  });

  // Track console errors
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  await page.goto('/');

  // 1. Verify basic page title/content
  await expect(page).toHaveTitle(/UTBA Swarm Map/i);

  // 2. Verify key UI elements are present
  const reportBtn = page.locator('#reportSwarmBtn');
  await expect(reportBtn).toBeVisible();
  await expect(reportBtn).toHaveText(/Report a Swarm at Your Location/i);
  await expect(reportBtn).toHaveAttribute('aria-label', /Report a Bee Swarm at your current location/i);
  await expect(reportBtn.locator('i.fa-location-dot')).toBeVisible();

  const map = page.locator('#map');
  await expect(map).toBeVisible();
  // Check if CSS is applied (map should have height set in style.css)
  const mapHeight = await map.evaluate(el => window.getComputedStyle(el).height);
  expect(parseInt(mapHeight), 'Map height should be at least 400px').toBeGreaterThan(400);

  const legend = page.locator('#legendTitle');
  await expect(legend).toBeVisible();
  await expect(legend).toHaveText(/Pin Color Legend:/i);
  await expect(legend.locator('i.fa-circle-info')).toBeVisible();

  // Check legend items
  const legendItems = page.locator('.legend-item');
  await expect(legendItems).toHaveCount(4);
  await expect(legendItems.nth(0)).toContainText(/Reported/i);
  await expect(legendItems.nth(1)).toContainText(/Verified/i);
  await expect(legendItems.nth(2)).toContainText(/Captured/i);
  await expect(legendItems.nth(3)).toContainText(/Archived/i);

  const footer = page.locator('footer');
  await expect(footer).toBeVisible();
  await expect(footer).toContainText(/Made with/i);
  await expect(footer).toContainText(/gemini-cli/i);
  await expect(footer).toContainText(/🐝❤️🐝/);
  
  // Verify footer link
  const footerLink = footer.locator('a');
  await expect(footerLink).toHaveAttribute('href', 'https://github.com/google/gemini-cli');
  await expect(footerLink).toHaveAttribute('target', '_blank');
  await expect(footerLink).toBeVisible();

  // 3. Verify Leaflet map is initialized (check for leaflet classes)
  const leafletContainer = page.locator('.leaflet-container');
  await expect(leafletContainer).toBeVisible();

  // 4. Verify no critical assets failed to load
  // We exclude some common external tracking or optional stuff if necessary
  if (failedRequests.length > 0) {
    console.error('Failed requests:', failedRequests);
  }
  expect(failedRequests, `Found ${failedRequests.length} failed requests`).toHaveLength(0);

  // 5. Verify no console errors
  if (consoleErrors.length > 0) {
    console.error('Console errors:', consoleErrors);
  }
  // We might allow some minor console errors, but generally want none
  expect(consoleErrors, `Found ${consoleErrors.length} console errors`).toHaveLength(0);
  
  // 6. Verify images are rendered (non-zero size)
  // Wait for at least one map tile to be visible
  await expect(page.locator('.leaflet-tile').first()).toBeVisible({ timeout: 10000 });
  
  const images = page.locator('img');
  const imageCount = await images.count();
  expect(imageCount, 'Page should have at least one image').toBeGreaterThan(0);
  for (let i = 0; i < imageCount; i++) {
    const img = images.nth(i);
    const box = await img.boundingBox();
    expect(box, `Image ${i} should be rendered (no bounding box found)`).not.toBeNull();
    if (box) {
      expect(box.width, `Image ${i} has zero width`).toBeGreaterThan(0);
      expect(box.height, `Image ${i} has zero height`).toBeGreaterThan(0);
    }
  }

  // 7. Visual check - attach a screenshot to the test report
  await testInfo.attach('deployment-screenshot', {
    body: await page.screenshot({ fullPage: true }),
    contentType: 'image/png',
  });
});
